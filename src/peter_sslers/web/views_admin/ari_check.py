# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db


# ==============================================================================


class View_List(Handler):
    @view_config(route_name="admin:ari_checks", renderer="/admin/ari_checks.mako")
    @view_config(
        route_name="admin:ari_checks_paginated",
        renderer="/admin/ari_checks.mako",
    )
    @view_config(route_name="admin:ari_checks|json", renderer="json")
    @view_config(route_name="admin:ari_checks_paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/ari-checks.json",
            "section": "ari-check",
            "about": """list AriCheck(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/ari-checks.json",
        }
    )
    @docify(
        {
            "endpoint": "/ari-checks/{PAGE}.json",
            "section": "ari-check",
            "example": "curl {ADMIN_PREFIX}/ari-checks/1.json",
            "variant_of": "/ari-checks.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__AriChecks__count(self.request.api_context)
        url_template = (
            "%s/ari-checks/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AriChecks___paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _auths = {k.id: k.as_json for k in items_paged}
            return {
                "AriChecks": _auths,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AriChecks": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    def _ari_check_focus(self):
        dbAriCheck = lib_db.get.get__AriCheck__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbAriCheck:
            raise HTTPNotFound("the log was not found")
        return dbAriCheck

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:ari_check:focus",
        renderer="/admin/ari_check-focus.mako",
    )
    @view_config(
        route_name="admin:ari_check:focus|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/ari-check/{ID}.json",
            "section": "ari-check",
            "about": """AriCheck""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/ari-check/1.json",
        }
    )
    def focus(self):
        item = self._ari_check_focus()
        if self.request.wants_json:
            return {
                "AriCheck": item.as_json,
            }
        return {"project": "peter_sslers", "AriCheck": item}
