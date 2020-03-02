# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime
import json

# pypi
import sqlalchemy
import transaction

# localapp
from .. import lib
from ..lib import formhandling
from ..lib.forms import Form_QueueCertificate_mark
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class ViewList(Handler):

    """
    note-
    if a renewal fails, the record is marked with the following:
        timestamp_process_attempt = time.time()
        process_result = False
    Records with the above are the failed renewal attempts.

    The record stays active and in the queue, as it may renew later on.
    To be removed, it must suucceed or be explicitly removed from the queue.
    """

    @view_config(
        route_name="admin:queue_certificates", renderer="/admin/queue_certificates.mako"
    )
    @view_config(
        route_name="admin:queue_certificates_paginated",
        renderer="/admin/queue_certificates.mako",
    )
    @view_config(
        route_name="admin:queue_certificates:all", renderer="/admin/queue_certificates.mako"
    )
    @view_config(
        route_name="admin:queue_certificates:all_paginated",
        renderer="/admin/queue_certificates.mako",
    )
    @view_config(
        route_name="admin:queue_certificates:active_failures",
        renderer="/admin/queue_certificates.mako",
    )
    @view_config(
        route_name="admin:queue_certificates:active_failures_paginated",
        renderer="/admin/queue_certificates.mako",
    )
    @view_config(route_name="admin:queue_certificates|json", renderer="json")
    @view_config(route_name="admin:queue_certificates_paginated|json", renderer="json")
    @view_config(route_name="admin:queue_certificates:all|json", renderer="json")
    @view_config(route_name="admin:queue_certificates:all_paginated|json", renderer="json")
    @view_config(
        route_name="admin:queue_certificates:active_failures|json", renderer="json"
    )
    @view_config(
        route_name="admin:queue_certificates:active_failures_paginated|json",
        renderer="json",
    )
    def list(self):
        get_kwargs = {}
        url_template = None
        sidenav_option = None
        if self.request.matched_route.name in (
            "admin:queue_certificates",
            "admin:queue_certificates_paginated",
        ):
            get_kwargs["unprocessed_only"] = True
            if self.request.wants_json:
                url_template = (
                    "%s/queue-certificates/{0}.json"
                    % self.request.registry.settings["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/queue-certificates/{0}"
                    % self.request.registry.settings["admin_prefix"]
                )
            sidenav_option = "unprocessed"
        elif self.request.matched_route.name in (
            "admin:queue_certificates:all",
            "admin:queue_certificates:all_paginated",
        ):
            if self.request.wants_json:
                url_template = (
                    "%s/queue-certificates/{0}.json"
                    % self.request.registry.settings["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/queue-certificates/{0}"
                    % self.request.registry.settings["admin_prefix"]
                )
            sidenav_option = "all"
        elif self.request.matched_route.name in (
            "admin:queue_certificates:active_failures",
            "admin:queue_certificates:active_failures_paginated",
        ):
            get_kwargs["unprocessed_failures_only"] = True
            if self.request.wants_json:
                url_template = (
                    "%s/queue-certificates/{0}.json"
                    % self.request.registry.settings["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/queue-certificates/{0}"
                    % self.request.registry.settings["admin_prefix"]
                )
            sidenav_option = "active-failures"

        items_count = lib_db.get.get__QueueCertificate__count(
            self.request.api_context, **get_kwargs
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__QueueCertificate__paginated(
            self.request.api_context, limit=items_per_page, offset=offset, **get_kwargs
        )

        continue_processing = False
        _results = self.request.params.get("results", None)
        if _results:
            try:
                _results = json.loads(_results)
                items_remaining = int(_results.get("count_remaining", 0))
                if items_remaining:
                    continue_processing = True
            except Exception as exc:
                # this could be a json or int() error
                pass
        if self.request.wants_json:
            _domains = {d.id: d.as_json for d in items_paged}
            return {
                "QueueCertificates": _domains,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "QueueCertificates_count": items_count,
            "QueueCertificates": items_paged,
            "sidenav_option": sidenav_option,
            "pager": pager,
            "continue_processing": continue_processing,
        }


class ViewNew(Handler):

    def _parse_renewal_source(self):
        _failure_url = "%s/queue-certificates" % (self.request.admin_url,)
        queue_source = None
        _acme_order_id = self.request.params.get('acme-order')
        _server_certificate_id = self.request.params.get('server-certificate')
        _unique_fqdn_set_id = self.request.params.get('unique-fqdn-set')
        if _acme_order_id:
            dbAcmeOrder = lib_db.get.get__AcmeOrder__by_id(
                self.request.api_context,
                _acme_order_id
            )
            if not dbAcmeOrder:
                return HTTPSeeOther("%s?result=error&operation=new&error=invalid+acme+order" % _failure_url)
            if not dbAcmeOrder.is_renewable_queue:
                return HTTPSeeOther("%s?result=error&operation=new&error=acme+order+ineligible" % _failure_url)
            queue_source = ('AcmeOrder', dbAcmeOrder)
        elif _server_certificate_id:
            dbServerCertificate = lib_db.get.get__ServerCertificate__by_id(
                self.request.api_context,
                _server_certificate_id
            )
            if not dbServerCertificate:
                return HTTPSeeOther("%s?result=error&operation=new&error=invalid+server+certificate" % _failure_url)
            queue_source = ('ServerCertificate', dbServerCertificate)
        elif _unique_fqdn_set_id:
            dbUniqueFQDNSet = lib_db.get.get__UniqueFQDNSet__by_id(
                self.request.api_context,
                _unique_fqdn_set_id
            )
            if not dbUniqueFQDNSet:
                return HTTPSeeOther("%s?result=error&operation=new&error=invalid+uniqe+fqdn+set" % _failure_url)
            queue_source = ('UniqueFQDNSet', dbUniqueFQDNSet)
        else:
            raise ValueError('invalid option for renewal')
        return queue_source

    @view_config(route_name="admin:queue_certificate:new", renderer=None)
    @view_config(route_name="admin:queue_certificate:new|json", renderer="json")
    def new(self):
        """
        This endpoint is for Immediately Renewing the AcmeOrder with some selection
        """
        queue_source = self._parse_renewal_source()
        if self.request.method == "POST":
            return self._new__submit(queue_source)
        return self._new__print(queue_source)

    def _new__print(self, queue_source):
        dbAcmeAccountProviders = lib_db.get.get__AcmeAccountProviders__paginated(
            self.request.api_context, is_enabled=True
        )
        return render_to_response(
            "/admin/queue_certificate-new.mako",
            {'QueueSource': queue_source,
             'AcmeOrder': queue_source[1] if queue_source[0] == 'AcmeOrder' else None,
             'ServerCertificate': queue_source[1] if queue_source[0] == 'ServerCertificate' else None,
             'UniqueFQDNSet': queue_source[1] if queue_source[0] == 'UniqueFQDNSet' else None,
             'AcmeAccountProviders': dbAcmeAccountProviders,
             },
            self.request,
        )

    def _new__submit(self, queue_source):
        (accountKeySelection, privateKeySelection) = form_utils.form_key_selection(self.request, formStash)
        if queue_source[0] == 'AcmeOrder':
            (
                dbAcmeOrderNew,
                exc,
            ) = lib_db.actions_acme.do__AcmeV2_AcmeOrder__renew_custom(
                self.request.api_context,
                dbAcmeOrder=queue_source[1],
                dbAcmeAccountKey=accountKeySelection.AcmeAccountKey,
                dbPrivateKey=privateKeySelection.PrivateKey,
            )

        renew_url = "%s/queue-renewawls" % (
            self.request.admin_url,
        )
        return HTTPSeeOther("%s?result=success&operation=renew+queue" % renew_url)


class ViewFocus(Handler):
    def _focus(self):
        dbQueueCertificate = lib_db.get.get__QueueCertificate__by_id(
            self.request.api_context, self.request.matchdict["id"], load_events=True
        )
        if not dbQueueCertificate:
            raise HTTPNotFound("the item was not found")
        self._focus_item = dbQueueCertificate
        self._focus_url = "%s/queue-certificate/%s" % (
            self.request.admin_url,
            dbQueueCertificate.id,
        )
        return dbQueueCertificate

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:queue_certificate:focus",
        renderer="/admin/queue_certificate-focus.mako",
    )
    @view_config(route_name="admin:queue_certificate:focus|json", renderer="json")
    def focus(self):
        dbRenewalQueueItem = self._focus()
        if self.request.wants_json:
            return {"status": "success", "QueueCertificate": dbRenewalQueueItem.as_json}
        return {"project": "peter_sslers", "RenewalQueueItem": dbRenewalQueueItem}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:queue_certificate:focus:mark")
    @view_config(route_name="admin:queue_certificate:focus:mark|json", renderer="json")
    def focus_mark(self):
        dbRenewalQueueItem = self._focus()
        if self.request.method == "POST":
            return self._focus_mark__submit(dbRenewalQueueItem)
        return self._focus_mark__print(dbRenewalQueueItem)

    def _focus_mark__print(self, dbRenewalQueueItem):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'action=active' %s/mark.json""" % self._focus_url
                ],
                "form_fields": {"action": "the intended action"},
                "valid_options": {"action": ["cancel"]},
            }
        url_huh = "%s?&result=post+required&operation=mark" % (self._focus_url)
        return HTTPSeeOther(url_huh)

    def _focus_mark__submit(self, dbRenewalQueueItem):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_QueueCertificate_mark, validate_get=True
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string(
                "QueueCertificate__mark"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["queue_certificate.id"] = dbRenewalQueueItem.id
            event_payload_dict["action"] = formStash.results["action"]

            event_status = False
            if action == "cancel":
                if not dbRenewalQueueItem.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field="action", message="Already cancelled")

                dbRenewalQueueItem.is_active = False
                dbRenewalQueueItem.timestamp_processed = (
                    self.request.api_context.timestamp
                )
                event_status = "QueueCertificate__mark__cancelled"
                self.request.api_context.dbSession.flush(objects=[dbRenewalQueueItem])
            else:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(field="action", message="invalid action")

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type, event_payload_dict
            )
            lib_db.logger._log_object_event(
                self.request.api_context,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    event_status
                ),
                dbQueueCertificate=dbRenewalQueueItem,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "QueueCertificate": dbRenewalQueueItem.as_json,
                }

            url_post_required = "%s?result=success&operation=mark" % (self._focus_url,)
            return HTTPSeeOther(url_post_required)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                exc.to_querystring(),
                action,
            )
            raise HTTPSeeOther(url_failure)
