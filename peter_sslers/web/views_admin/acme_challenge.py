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


class ViewAdmin_List(Handler):
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
        if wants_active:
            sidenav_option = "active"
            active_only = True
            if self.request.wants_json:
                url_template = (
                    "%s/acme-challenges/{0}.json?status=active"
                    % self.request.registry.settings["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/acme-challenges/{0}?status=active"
                    % self.request.registry.settings["admin_prefix"]
                )
        else:
            sidenav_option = "all"
            active_only = False
            if self.request.wants_json:
                url_template = (
                    "%s/acme-challenges/{0}.json"
                    % self.request.registry.settings["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/acme-challenges/{0}"
                    % self.request.registry.settings["admin_prefix"]
                )
        items_count = lib_db.get.get__AcmeChallenge__count(
            self.request.api_context, active_only=active_only
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template,)
        items_paged = lib_db.get.get__AcmeChallenge__paginated(
            self.request.api_context,
            active_only=active_only,
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


class ViewAdmin_Focus(Handler):
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


class ViewAdmin_Focus_Manipulate(ViewAdmin_Focus):
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server_sync", renderer=None
    )
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server_sync|json", renderer="json"
    )
    def acme_server_sync(self):
        """
        Acme Refresh should just update the record against the acme server.
        """
        dbAcmeChallenge = self._focus(eagerload_web=True)
        try:
            if not dbAcmeChallenge.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeAuthorization"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeChallenge__acme_server_sync(
                self.request.api_context, dbAcmeChallenge=dbAcmeChallenge,
            )
            if self.request.wants_json:
                return HTTPSeeOther(
                    "%s.json?result=success&operation=acme+server+sync"
                    % self._focus_url
                )
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
                return HTTPSeeOther(
                    "%s.json?result=error&error=acme+server+sync&message=%s"
                    % (self._focus_url, exc.to_querystring())
                )
            return HTTPSeeOther(
                "%s?result=error&error=acme+server+sync&message=%s"
                % (self._focus_url, exc.to_querystring())
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_challenge:focus:acme_server_trigger", renderer=None,
    )
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server_trigger|json",
        renderer="json",
    )
    def acme_server_trigger(self):
        """
        Acme Trigger
        """
        # todo: json response
        dbAcmeChallenge = self._focus(eagerload_web=True)
        try:
            if not dbAcmeChallenge.is_can_acme_server_trigger:
                raise errors.InvalidRequest(
                    "ACME Server Trugger is not allowed for this AcmeChallenge"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeChallenge__acme_server_trigger(
                self.request.api_context, dbAcmeChallenge=dbAcmeChallenge,
            )
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+trigger"
                % self._focus_url
            )
        except (
            errors.AcmeCommunicationError,
            errors.AcmeServerError,
            errors.DomainVerificationError,
            errors.InvalidRequest,
        ) as exc:
            return HTTPSeeOther(
                "%s?result=error&error=acme+server+trigger&message=%s"
                % (self._focus_url, exc.to_querystring())
            )
