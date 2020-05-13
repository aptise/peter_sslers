# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import json

# pypi
import sqlalchemy

# localapp
from .. import lib
from ..lib import formhandling
from ..lib import form_utils as form_utils
from ..lib import text as lib_text
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import acme_v2
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class ViewAdmin_List(Handler):
    @view_config(
        route_name="admin:acme_authorizations",
        renderer="/admin/acme_authorizations.mako",
    )
    @view_config(
        route_name="admin:acme_authorizations_paginated",
        renderer="/admin/acme_authorizations.mako",
    )
    @view_config(
        route_name="admin:acme_authorizations|json", renderer="json",
    )
    @view_config(
        route_name="admin:acme_authorizations_paginated|json", renderer="json",
    )
    def list(self):
        url_status = self.request.params.get("status")
        if url_status not in ("active", "active-expired"):
            url_status = ""
        if url_status == "active":
            sidenav_option = "active"
        elif url_status == "active-expired":
            sidenav_option = "active-expired"
        else:
            sidenav_option = "all"

        active_only = True if url_status == "active" else False
        expired_only = True if url_status == "active-expired" else False

        if self.request.wants_json:
            url_template = (
                "%s/acme-authorizations/{0}.json"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
        else:
            url_template = (
                "%s/acme-authorizations/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
        if url_status:
            url_template = "%s?status=%s" % (url_template, url_status)

        items_count = lib_db.get.get__AcmeAuthorization__count(
            self.request.api_context, active_only=active_only
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template,)
        items_paged = lib_db.get.get__AcmeAuthorization__paginated(
            self.request.api_context,
            active_only=active_only,
            expired_only=expired_only,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _auths = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeAuthorizations": _auths,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeAuthorizations_count": items_count,
            "AcmeAuthorizations": items_paged,
            "pager": pager,
        }


class ViewAdmin_Focus(Handler):
    def _focus(self, eagerload_web=False):
        dbAcmeAuthorization = lib_db.get.get__AcmeAuthorization__by_id(
            self.request.api_context,
            self.request.matchdict["id"],
            eagerload_web=eagerload_web,
        )
        if not dbAcmeAuthorization:
            raise HTTPNotFound("The AcmeAuthorization was not found")
        self._focus_url = "%s/acme-authorization/%s" % (
            self.request.admin_url,
            dbAcmeAuthorization.id,
        )
        return dbAcmeAuthorization

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_authorization:focus",
        renderer="/admin/acme_authorization-focus.mako",
    )
    @view_config(
        route_name="admin:acme_authorization:focus|json", renderer="json",
    )
    def focus(self):
        dbAcmeAuthorization = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "AcmeAuthorization": dbAcmeAuthorization._as_json(
                    admin_url=self.request.admin_url
                )
            }
        return {"project": "peter_sslers", "AcmeAuthorization": dbAcmeAuthorization}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_authorization:focus:acme_orders",
        renderer="/admin/acme_authorization-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:acme_authorization:focus:acme_orders_paginated",
        renderer="/admin/acme_authorization-focus-acme_orders.mako",
    )
    def related__AcmeOrders(self):
        dbAcmeAuthorization = self._focus(eagerload_web=True)
        items_count = lib_db.get.get__AcmeOrder__by_AcmeAuthorizationId__count(
            self.request.api_context, dbAcmeAuthorization.id
        )
        (pager, offset) = self._paginate(
            items_count, url_template="%s/acme-orders" % self._focus_url,
        )
        items_paged = lib_db.get.get__AcmeOrder__by_AcmeAuthorizationId__paginated(
            self.request.api_context,
            dbAcmeAuthorization.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeAuthorization": dbAcmeAuthorization,
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_authorization:focus:acme_challenges",
        renderer="/admin/acme_authorization-focus-acme_challenges.mako",
    )
    @view_config(
        route_name="admin:acme_authorization:focus:acme_challenges_paginated",
        renderer="/admin/acme_authorization-focus-acme_challenges.mako",
    )
    def related__AcmeChallenges(self):
        dbAcmeAuthorization = self._focus(eagerload_web=True)
        items_count = lib_db.get.get__AcmeChallenge__by_AcmeAuthorizationId__count(
            self.request.api_context, dbAcmeAuthorization.id
        )
        (pager, offset) = self._paginate(
            items_count, url_template="%s/acme-challenges" % self._focus_url,
        )
        items_paged = lib_db.get.get__AcmeChallenge__by_AcmeAuthorizationId__paginated(
            self.request.api_context,
            dbAcmeAuthorization.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeAuthorization": dbAcmeAuthorization,
            "AcmeChallenges_count": items_count,
            "AcmeChallenges": items_paged,
            "pager": pager,
        }


class ViewAdmin_Focus_Manipulate(ViewAdmin_Focus):
    @view_config(
        route_name="admin:acme_authorization:focus:acme_server:sync", renderer=None
    )
    @view_config(
        route_name="admin:acme_authorization:focus:acme_server:sync|json",
        renderer="json",
    )
    def acme_server_sync(self):
        """
        Acme Refresh should just update the record against the acme server.
        """
        dbAcmeAuthorization = self._focus(eagerload_web=True)
        try:
            if not dbAcmeAuthorization.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeAuthorization"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeAuthorization__acme_server_sync(
                self.request.api_context, dbAcmeAuthorization=dbAcmeAuthorization,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/sync",
                    "AcmeAuthorization": dbAcmeAuthorization.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+sync" % self._focus_url
            )
        except (
            errors.AcmeCommunicationError,
            errors.DomainVerificationError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/sync",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+sync"
                % (self._focus_url, exc.as_querystring)
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_authorization:focus:acme_server:deactivate",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_authorization:focus:acme_server:deactivate|json",
        renderer="json",
    )
    def acme_server_deactivate(self):
        """
        Acme Deactivate
        """
        dbAcmeAuthorization = self._focus(eagerload_web=True)
        try:
            if not dbAcmeAuthorization.is_can_acme_server_deactivate:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeAuthorization"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeAuthorization__acme_server_deactivate(
                self.request.api_context, dbAcmeAuthorization=dbAcmeAuthorization,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/deactivate",
                    "AcmeAuthorization": dbAcmeAuthorization.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+deactivate" % self._focus_url
            )
        except (
            errors.AcmeCommunicationError,
            errors.AcmeServerError,
            errors.DomainVerificationError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/deactivate",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+deactivate"
                % (self._focus_url, exc.as_querystring)
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_authorization:focus:acme_server:trigger", renderer=None,
    )
    @view_config(
        route_name="admin:acme_authorization:focus:acme_server:trigger|json",
        renderer="json",
    )
    def acme_server_trigger(self):
        """
        Acme Trigger
        """
        dbAcmeAuthorization = self._focus(eagerload_web=True)
        try:
            if not dbAcmeAuthorization.is_can_acme_server_trigger:
                raise errors.InvalidRequest(
                    "ACME Server Trigger is not allowed for this AcmeAuthorization"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeAuthorization__acme_server_trigger(
                self.request.api_context, dbAcmeAuthorization=dbAcmeAuthorization,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/trigger",
                    "AcmeAuthorization": dbAcmeAuthorization.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+trigger" % self._focus_url
            )
        except (
            errors.AcmeCommunicationError,
            errors.AcmeServerError,
            errors.DomainVerificationError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/trigger",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+trigger"
                % (self._focus_url, exc.as_querystring)
            )
