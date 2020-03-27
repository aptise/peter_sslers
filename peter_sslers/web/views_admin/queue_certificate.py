# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime
import json
import pdb

# pypi
import sqlalchemy
import transaction

# localapp
from .. import lib
from ..lib import formhandling
from ..lib import form_utils as form_utils
from ..lib.forms import Form_QueueCertificate_mark
from ..lib.forms import Form_QueueCertificate_new_AcmeOrder
from ..lib.forms import Form_QueueCertificate_new_ServerCertificate
from ..lib.forms import Form_QueueCertificate_new_UniqueFQDNSet
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
        route_name="admin:queue_certificates:all",
        renderer="/admin/queue_certificates.mako",
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
    @view_config(
        route_name="admin:queue_certificates:all_paginated|json", renderer="json"
    )
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
    def _parse_queue_source(self):
        _failure_url = "%s/queue-certificates" % (self.request.admin_url,)
        queue_source = self.request.params.get("queue_source")
        acme_order_id = self.request.params.get("acme_order")
        server_certificate_id = self.request.params.get("server_certificate")
        unique_fqdn_set_id = self.request.params.get("unique_fqdn_set")

        queue_data = {
            "queue_source": queue_source,
            "AcmeAccountKey_reuse": None,
            "AcmeOrder": None,
            "PrivateKey_reuse": None,
            "ServerCertificate": None,
            "UniqueFQDNSet": None,
        }
        if (queue_source == "AcmeOrder") and acme_order_id:
            dbAcmeOrder = lib_db.get.get__AcmeOrder__by_id(
                self.request.api_context, acme_order_id
            )
            if not dbAcmeOrder:
                raise HTTPSeeOther(
                    "%s?result=error&operation=new&error=invalid+acme+order"
                    % _failure_url
                )
            if not dbAcmeOrder.is_renewable_queue:
                raise HTTPSeeOther(
                    "%s?result=error&operation=new&error=acme+order+ineligible"
                    % _failure_url
                )
            queue_data["AcmeOrder"] = dbAcmeOrder
            queue_data["AcmeAccountKey_reuse"] = dbAcmeOrder.acme_account_key
            queue_data["PrivateKey_reuse"] = dbAcmeOrder.private_key

        elif (queue_source == "ServerCertificate") and server_certificate_id:
            dbServerCertificate = lib_db.get.get__ServerCertificate__by_id(
                self.request.api_context, server_certificate_id
            )
            if not dbServerCertificate:
                raise HTTPSeeOther(
                    "%s?result=error&operation=new&error=invalid+server+certificate"
                    % _failure_url
                )
            queue_data["ServerCertificate"] = dbServerCertificate
            queue_data["PrivateKey_reuse"] = dbServerCertificate.private_key

        elif (queue_source == "UniqueFQDNSet") and unique_fqdn_set_id:
            dbUniqueFQDNSet = lib_db.get.get__UniqueFQDNSet__by_id(
                self.request.api_context, unique_fqdn_set_id
            )
            if not dbUniqueFQDNSet:
                raise HTTPSeeOther(
                    "%s?result=error&operation=new&error=invalid+uniqe+fqdn+set"
                    % _failure_url
                )
            queue_data["UniqueFQDNSet"] = dbUniqueFQDNSet
        else:
            raise HTTPSeeOther(
                "%s?result=error&operation=new&error=invalid+queue+source"
                % _failure_url
            )
        return queue_data

    @view_config(route_name="admin:queue_certificate:new", renderer=None)
    @view_config(route_name="admin:queue_certificate:new|json", renderer="json")
    def new(self):
        """
        This endpoint is for Immediately Renewing the AcmeOrder with some selection
        """
        self._load_AcmeAccountKey_GlobalDefault()
        self._load_AcmeAccountProviders()
        self._load_PrivateKey_GlobalDefault()
        self.queue_data = self._parse_queue_source()

        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        return render_to_response(
            "/admin/queue_certificate-new.mako",
            {
                "queue_source": self.queue_data["queue_source"],
                "AcmeOrder": self.queue_data["AcmeOrder"],
                "AcmeAccountKey_GlobalDefault": self.dbAcmeAccountKey_GlobalDefault,
                "AcmeAccountProviders": self.dbAcmeAccountProviders,
                "AcmeAccountKey_resuse": self.queue_data["AcmeAccountKey_reuse"],
                "PrivateKey_GlobalDefault": self.dbPrivateKey_GlobalDefault,
                "PrivateKey_reuse": self.queue_data["PrivateKey_reuse"],
                "ServerCertificate": self.queue_data["ServerCertificate"],
                "UniqueFQDNSet": self.queue_data["UniqueFQDNSet"],
            },
            self.request,
        )

    def _new__submit(self):
        try:
            _form = None
            _create_kwargs = {}
            if self.queue_data["queue_source"] == "AcmeOrder":
                _form = Form_QueueCertificate_new
                _create_kwargs["dbAcmeOrder"] = self.queue_data["AcmeOrder"]

            elif self.queue_data["queue_source"] == "ServerCertificate":
                _form = Form_QueueCertificate_new_ServerCertificate
                _create_kwargs["dbServerCertificate"] = self.queue_data[
                    "ServerCertificate"
                ]

            elif self.queue_data["queue_source"] == "UniqueFQDNSet":
                _form = Form_QueueCertificate_new_UniqueFQDNSet
                _create_kwargs["dbUniqueFQDNSet"] = self.queue_data["UniqueFQDNSet"]

            (result, formStash) = formhandling.form_validate(
                self.request, schema=_form, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            event_type = model_utils.OperationsEventType.from_string(
                "QueueCertificate__invert"
            )

            (accountKeySelection, privateKeySelection) = form_utils.form_key_selection(
                self.request, formStash
            )
            _create_kwargs["dbAcmeAccountKey"] = accountKeySelection.AcmeAccountKey
            _create_kwargs["dbPrivateKey"] = privateKeySelection.PrivateKey
            dbQueueCertificate = lib_db.create.create__QueueCertificate(
                self.request.api_context, **_create_kwargs
            )

            return HTTPSeeOther(
                "%s/queue-certificates?result=success&operation=renew+queue&queued-certificate=%s"
                % (self.request.admin_url, dbQueueCertificate.id)
            )
        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(self.request, self._new__print)


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
        dbQueueCertificate = self._focus()
        if self.request.wants_json:
            return {"status": "success", "QueueCertificate": dbQueueCertificate.as_json}
        return {"project": "peter_sslers", "QueueCertificate": dbQueueCertificate}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:queue_certificate:focus:mark")
    @view_config(route_name="admin:queue_certificate:focus:mark|json", renderer="json")
    def focus_mark(self):
        dbQueueCertificate = self._focus()
        if self.request.method == "POST":
            return self._focus_mark__submit(dbQueueCertificate)
        return self._focus_mark__print(dbQueueCertificate)

    def _focus_mark__print(self, dbQueueCertificate):
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

    def _focus_mark__submit(self, dbQueueCertificate):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_QueueCertificate_mark, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string(
                "QueueCertificate__mark"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["queue_certificate.id"] = dbQueueCertificate.id
            event_payload_dict["action"] = formStash.results["action"]

            event_status = False
            if action == "cancel":
                if not dbQueueCertificate.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field="action", message="Already cancelled")

                dbQueueCertificate.is_active = False
                dbQueueCertificate.timestamp_processed = (
                    self.request.api_context.timestamp
                )
                event_status = "QueueCertificate__mark__cancelled"
                self.request.api_context.dbSession.flush(objects=[dbQueueCertificate])
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
                dbQueueCertificate=dbQueueCertificate,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "QueueCertificate": dbQueueCertificate.as_json,
                }

            url_post_required = "%s?result=success&operation=mark" % (self._focus_url,)
            return HTTPSeeOther(url_post_required)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                exc.as_querystring,
                action,
            )
            raise HTTPSeeOther(url_failure)
