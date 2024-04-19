# stdlib
from typing import Optional

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...model.objects import AcmeChallenge

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:acme_challenges",
        renderer="/admin/acme_challenges.mako",
    )
    @view_config(
        route_name="admin:acme_challenges_paginated",
        renderer="/admin/acme_challenges.mako",
    )
    @view_config(
        route_name="admin:acme_challenges|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:acme_challenges_paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-challenges.json",
            "section": "acme-challenges",
            "about": """list AcmeChallenge(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-challenges.json",
            "params": {
                "status": [
                    "active",
                    "resolved",
                    "processing",
                ],
            },
        }
    )
    @docify(
        {
            "endpoint": "/acme-challenges/{PAGE}.json",
            "section": "acme-challenges",
            "example": "curl {ADMIN_PREFIX}/acme-challenges/1.json",
            "variant_of": "/acme-challenges.json",
        }
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
        url_status = None
        if wants_active:
            sidenav_option = "active"
            url_status = "active"
            active_only = True

        elif wants_resolved:
            sidenav_option = "resolved"
            url_status = "resolved"
            resolved_only = True
        elif wants_processing:
            sidenav_option = "processing"
            url_status = "processing"
            processing_only = True
        else:
            sidenav_option = "all"
            url_status = None
            active_only = False

        url_template = (
            "%s/acme-challenges/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        if url_status:
            url_template = "%s?status=%s" % (url_template, url_status)

        items_count = lib_db.get.get__AcmeChallenge__count(
            self.request.api_context,
            active_only=active_only,
            resolved_only=resolved_only,
            processing_only=processing_only,
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
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
    dbAcmeChallenge: Optional[AcmeChallenge] = None

    def _focus(self, eagerload_web=False) -> AcmeChallenge:
        if self.dbAcmeChallenge is None:
            dbAcmeChallenge = lib_db.get.get__AcmeChallenge__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbAcmeChallenge:
                raise HTTPNotFound("the order was not found")
            self.dbAcmeChallenge = dbAcmeChallenge
            self._focus_url = "%s/acme-challenge/%s" % (
                self.request.admin_url,
                self.dbAcmeChallenge.id,
            )
        return self.dbAcmeChallenge

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_challenge:focus",
        renderer="/admin/acme_challenge-focus.mako",
    )
    @view_config(
        route_name="admin:acme_challenge:focus|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-challenge/{ID}.json",
            "section": "acme-challenge",
            "about": """AcmeChallenge Focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-challenge/1.json",
        }
    )
    def focus(self):
        dbAcmeChallenge = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "AcmeChallenge": dbAcmeChallenge.as_json,
            }
        return {"project": "peter_sslers", "AcmeChallenge": dbAcmeChallenge}


class View_Focus_Manipulate(View_Focus):
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server:sync", renderer=None
    )
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server:sync|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-challenge/{ID}/acme-server/sync.json",
            "section": "acme-challenge",
            "about": """AcmeChallenge focus: AcmeServer sync""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/acme-challenge/1/acme-server/sync.json",
        }
    )
    def acme_server_sync(self):
        """
        Acme Refresh should just update the record against the acme server.
        """
        dbAcmeChallenge = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self, "/acme-challenge/{ID}/acme-server/sync.json"
                )
            return HTTPSeeOther(
                "%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            if not dbAcmeChallenge.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeChallenge"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeChallenge__acme_server_sync(  # noqa: F841
                self.request.api_context,
                dbAcmeChallenge=dbAcmeChallenge,
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
        route_name="admin:acme_challenge:focus:acme_server:trigger",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_challenge:focus:acme_server:trigger|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-challenge/{ID}/acme-server/trigger.json",
            "section": "acme-challenge",
            "about": """AcmeChallenge focus: AcmeServer trigger""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/acme-challenge/1/acme-server/trigger.json",
        }
    )
    def acme_server_trigger(self):
        """
        Acme Trigger
        """
        dbAcmeChallenge = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self, "/acme-challenge/{ID}/acme-server/trigger.json"
                )
            return HTTPSeeOther(
                "%s?result=error&operation=acme+server+trigger&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            if not dbAcmeChallenge.is_can_acme_server_trigger:
                raise errors.InvalidRequest(
                    "ACME Server Trigger is not allowed for this AcmeChallenge"
                )
            if not dbAcmeChallenge.is_configured_to_answer:
                _token_submitted = self.request.params.get("token")
                if _token_submitted != dbAcmeChallenge.token:
                    raise errors.InvalidRequest(
                        "This installation is NOT configured to answer this challenge. You must submit the challenge token to trigger."
                    )
            result = lib_db.actions_acme.do__AcmeV2_AcmeChallenge__acme_server_trigger(  # noqa: F841
                self.request.api_context,
                dbAcmeChallenge=dbAcmeChallenge,
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
            errors.AcmeOrphanedObject,
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
