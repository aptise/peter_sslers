# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import sqlalchemy
import transaction

# localapp
from .. import lib
from ..lib.handler import Handler, items_per_page
from ...model import utils as model_utils
from ...model import objects as model_objects
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils


# ==============================================================================


class ViewAdmin(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_sets", renderer="/admin/unique_fqdn_sets.mako"
    )
    @view_config(
        route_name="admin:unique_fqdn_sets_paginated",
        renderer="/admin/unique_fqdn_sets.mako",
    )
    @view_config(route_name="admin:unique_fqdn_sets|json", renderer="json")
    @view_config(route_name="admin:unique_fqdn_sets_paginated|json", renderer="json")
    def list(self):
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        items_count = lib_db.get.get__UniqueFQDNSet__count(self.request.api_context)
        if wants_json:
            (pager, offset) = self._paginate(
                items_count,
                url_template="%s/unique-fqdn-sets/{0}.json"
                % self.request.registry.settings["admin_prefix"],
            )
        else:
            (pager, offset) = self._paginate(
                items_count,
                url_template="%s/unique-fqdn-sets/{0}"
                % self.request.registry.settings["admin_prefix"],
            )
        items_paged = lib_db.get.get__UniqueFQDNSet__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
            eagerload_web=True,
        )
        if wants_json:
            _sets = {s.id: s.as_json for s in items_paged}
            return {
                "UniqueFQDNSets": _sets,
                "pagination": {
                    "total_items": items_count,
                    "page": pager.page_num,
                    "page_next": pager.next if pager.has_next else None,
                },
            }
        return {
            "project": "peter_sslers",
            "UniqueFQDNSets_count": items_count,
            "UniqueFQDNSets": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _focus(self):
        dbItem = lib_db.get.get__UniqueFQDNSet__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbItem:
            raise HTTPNotFound("the fqdn set was not found")
        return dbItem

    @view_config(
        route_name="admin:unique_fqdn_set:focus",
        renderer="/admin/unique_fqdn_set-focus.mako",
    )
    @view_config(route_name="admin:unique_fqdn_set:focus|json", renderer="json")
    def focus(self):
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        dbFqdnSet = self._focus()
        if wants_json:
            _prefix = "%s/unique-fqdn-set/%s" % (
                self.request.registry.settings["admin_prefix"],
                dbFqdnSet.id,
            )
            return {"UniqueFQDNSet": dbFqdnSet.as_json}

        return {"project": "peter_sslers", "UniqueFQDNSet": dbFqdnSet}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_set:focus:calendar|json", renderer="json"
    )
    def focus__calendar(self):
        rval = {}
        dbUniqueFQDNSet = self._focus()
        weekly_certs = (
            self.request.api_context.dbSession.query(
                model_utils.year_week(
                    model_objects.ServerCertificate.timestamp_signed
                ).label("week_num"),
                sqlalchemy.func.count(model_objects.ServerCertificate.id),
            )
            .filter(
                model_objects.ServerCertificate.unique_fqdn_set_id == dbUniqueFQDNSet.id
            )
            .group_by("week_num")
            .order_by(sqlalchemy.asc("week_num"))
            .all()
        )
        rval["issues"] = {}
        for wc in weekly_certs:
            rval["issues"][str(wc[0])] = wc[1]
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_set:focus:certificates",
        renderer="/admin/unique_fqdn_set-focus-certificates.mako",
    )
    @view_config(
        route_name="admin:unique_fqdn_set:focus:certificates_paginated",
        renderer="/admin/unique_fqdn_set-focus-certificates.mako",
    )
    def focus__certificates(self):
        dbUniqueFQDNSet = self._focus()
        items_count = lib_db.get.get__ServerCertificate__by_UniqueFQDNSetId__count(
            self.request.api_context, dbUniqueFQDNSet.id
        )
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/unique-fqdn-set/%s/certificates/{0}"
            % (self.request.registry.settings["admin_prefix"], dbUniqueFQDNSet.id),
        )
        items_paged = lib_db.get.get__ServerCertificate__by_UniqueFQDNSetId__paginated(
            self.request.api_context,
            dbUniqueFQDNSet.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "UniqueFQDNSet": dbUniqueFQDNSet,
            "ServerCertificates_count": items_count,
            "ServerCertificates": items_paged,
            "pager": pager,
        }

    @view_config(
        route_name="admin:unique_fqdn_set:focus:certificate_requests",
        renderer="/admin/unique_fqdn_set-focus-certificate_requests.mako",
    )
    @view_config(
        route_name="admin:unique_fqdn_set:focus:certificate_requests_paginated",
        renderer="/admin/unique_fqdn_set-focus-certificate_requests.mako",
    )
    def focus__certificate_requests(self):
        dbUniqueFQDNSet = self._focus()
        items_count = lib_db.get.get__CertificateRequest__by_UniqueFQDNSetId__count(
            self.request.api_context, dbUniqueFQDNSet.id
        )
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/unique-fqdn-set/%s/certificate-requests/{0}"
            % (self.request.registry.settings["admin_prefix"], dbUniqueFQDNSet.id),
        )
        items_paged = lib_db.get.get__CertificateRequest__by_UniqueFQDNSetId__paginated(
            self.request.api_context,
            dbUniqueFQDNSet.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "UniqueFQDNSet": dbUniqueFQDNSet,
            "CertificateRequests_count": items_count,
            "CertificateRequests": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:unique_fqdn_set:focus:renew:queue", renderer=None)
    @view_config(
        route_name="admin:unique_fqdn_set:focus:renew:queue|json", renderer="json"
    )
    def focus_renew_queue(self):
        """this endpoint is for adding the certificate to the renewal queue immediately"""
        dbUniqueFQDNSet = self._focus()
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        try:
            # first check to see if this is already queued
            dbQueued = lib_db.get.get__SslQueueRenewal__by_UniqueFQDNSetId__active(
                self.request.api_context, dbUniqueFQDNSet.id
            )
            if dbQueued:
                raise errors.DisplayableError(
                    "There is an existing entry in the queue for this certificate's FQDN set."
                )

            # okay, we're good to go...'
            event_type = model_utils.SslOperationsEventType.from_string(
                "queue_renewal__update"
            )
            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = lib_db.logger.log__SslOperationsEvent(
                self.request.api_context, event_type, event_payload_dict
            )
            dbQueue = lib_db.create._create__SslQueueRenewal_fqdns(
                self.request.api_context, dbUniqueFQDNSet.id
            )
            event_payload_dict["unique_fqdn_set-queued.ids"] = str(dbUniqueFQDNSet.id)
            event_payload_dict["sql_queue_renewals.ids"] = str(dbQueue.id)
            dbOperationsEvent.set_event_payload(event_payload_dict)
            self.request.api_context.dbSession.flush(objects=[dbOperationsEvent])

            if wants_json:
                return {"status": "success", "queue_item": dbQueue.id}
            url_success = (
                "%s/unique-fqdn-set/%s?operation=renewal&renewal_type=queue&success=%s&result=success"
                % (
                    self.request.registry.settings["admin_prefix"],
                    dbUniqueFQDNSet.id,
                    dbQueue.id,
                )
            )
            return HTTPSeeOther(url_success)

        except errors.DisplayableError as exc:
            if wants_json:
                return {"status": "error", "error": str(exc)}
            url_failure = (
                "%s/unique-fqdn-set/%s?operation=renewal&renewal_type=queue&error=%s&result=error"
                % (
                    self.request.registry.settings["admin_prefix"],
                    dbUniqueFQDNSet.id,
                    str(exc).replace(" ", "+"),
                )
            )
            raise HTTPSeeOther(url_failure)
