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
from ..lib import text as lib_text
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import cert_utils
from ...lib import errors
from ...lib import db as lib_db
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:acme_challenges", renderer="/admin/acme_challenges.mako",
    )
    @view_config(
        route_name="admin:acme_challenges_paginated",
        renderer="/admin/acme_challenges.mako",
    )
    @view_config(
        route_name="admin:acme_challenges|json", renderer="json",
    )
    @view_config(
        route_name="admin:acme_challenges_paginated|json", renderer="json",
    )
    def list(self):
        wants_active = True if self.request.params.get("status") == "active" else False
        wants_resolved = (
            True if self.request.params.get("status") == "resolved" else False
        )
        wants_processing = (
            True if self.request.params.get("status") == "processing" else False
        )
        active_only = None
        resolved_only = None
        processing_only = None
        if wants_active:
            sidenav_option = "active"
            active_only = True
            if self.request.wants_json:
                url_template = (
                    "%s/acme-challenges/{0}.json?status=active"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/acme-challenges/{0}?status=active"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
        elif wants_resolved:
            sidenav_option = "resolved"
            resolved_only = True
            if self.request.wants_json:
                url_template = (
                    "%s/acme-challenges/{0}.json?status=resolved"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/acme-challenges/{0}?status=resolved"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
        elif wants_processing:
            sidenav_option = "processing"
            processing_only = True
            if self.request.wants_json:
                url_template = (
                    "%s/acme-challenges/{0}.json?status=processing"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/acme-challenges/{0}?status=processing"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
        else:
            sidenav_option = "all"
            active_only = False
            if self.request.wants_json:
                url_template = (
                    "%s/acme-challenges/{0}.json"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/acme-challenges/{0}"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
        items_count = lib_db.get.get__AcmeChallenge__count(
            self.request.api_context,
            active_only=active_only,
            resolved_only=resolved_only,
            processing_only=processing_only,
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template,)
        items_paged = lib_db.get.get__AcmeChallenge__paginated(
            self.request.api_context,
            active_only=active_only,
            resolved_only=resolved_only,
            processing_only=processing_only,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _items = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeChallenges": _items,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeChallenges_count": items_count,
            "AcmeChallenges": items_paged,
            "pager": pager,
            "sidenav_option": sidenav_option,
        }


class View_Focus(Handler):
    def _focus(self, eagerload_web=False):
        dbAcmeChallenge = lib_db.get.get__AcmeChallenge__by_id(
            self.request.api_context, self.request.matchdict["id"],
        )
        if not dbAcmeChallenge:
            raise HTTPNotFound("the order was not found")
        self._focus_url = "%s/acme-challenge/%s" % (
            self.request.admin_url,
            dbAcmeChallenge.id,
        )
        return dbAcmeChallenge

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_challenge:focus",
        renderer="/admin/acme_challenge-focus.mako",
    )
    @view_config(
        route_name="admin:acme_challenge:focus|json", renderer="json",
    )
    def focus(self):
        dbAcmeChallenge = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "AcmeChallenge": dbAcmeChallenge._as_json(
                    admin_url=self.request.admin_url
                )
            }
        return {"project": "peter_sslers", "AcmeChallenge": dbAcmeChallenge}


class View_Focus_Manipulate(View_Focus):
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server:sync", renderer=None
    )
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server:sync|json", renderer="json"
    )
    def acme_server_sync(self):
        """
        Acme Refresh should just update the record against the acme server.
        """
        dbAcmeChallenge = self._focus(eagerload_web=True)
        try:
            if not dbAcmeChallenge.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeChallenge"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeChallenge__acme_server_sync(
                self.request.api_context, dbAcmeChallenge=dbAcmeChallenge,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/sync",
                    "AcmeChallenge": dbAcmeChallenge.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+sync" % self._focus_url
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
                    "operation": "acme-server/sync",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+sync"
                % (self._focus_url, exc.as_querystring)
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_challenge:focus:acme_server:trigger", renderer=None,
    )
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server:trigger|json",
        renderer="json",
    )
    def acme_server_trigger(self):
        """
        Acme Trigger
        """
        dbAcmeChallenge = self._focus(eagerload_web=True)
        try:
            if not dbAcmeChallenge.is_can_acme_server_trigger:
                raise errors.InvalidRequest(
                    "ACME Server Trigger is not allowed for this AcmeChallenge"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeChallenge__acme_server_trigger(
                self.request.api_context, dbAcmeChallenge=dbAcmeChallenge,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/trigger",
                    "AcmeChallenge": dbAcmeChallenge.as_json,
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
