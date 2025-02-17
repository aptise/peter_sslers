# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:ari_checks",
    )
    @view_config(
        route_name="admin:ari_checks|json",
    )
    def list_redirect(self):
        url_default = (
            "%s/ari-checks/cert-latest-overdue"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_default = "%s.json" % url_default
        return HTTPSeeOther(url_default)

    @view_config(route_name="admin:ari_checks:all", renderer="/admin/ari_checks.mako")
    @view_config(
        route_name="admin:ari_checks:cert_latest", renderer="/admin/ari_checks.mako"
    )
    @view_config(
        route_name="admin:ari_checks:cert_latest_overdue",
        renderer="/admin/ari_checks.mako",
    )
    @view_config(
        route_name="admin:ari_checks:all_paginated", renderer="/admin/ari_checks.mako"
    )
    @view_config(
        route_name="admin:ari_checks:cert_latest_paginated",
        renderer="/admin/ari_checks.mako",
    )
    @view_config(
        route_name="admin:ari_checks:cert_latest_overdue_paginated",
        renderer="/admin/ari_checks.mako",
    )
    @view_config(route_name="admin:ari_checks:all|json", renderer="json")
    @view_config(route_name="admin:ari_checks:cert_latest|json", renderer="json")
    @view_config(
        route_name="admin:ari_checks:cert_latest_overdue|json", renderer="json"
    )
    @view_config(route_name="admin:ari_checks:all_paginated|json", renderer="json")
    @view_config(
        route_name="admin:ari_checks:cert_latest_paginated|json", renderer="json"
    )
    @view_config(
        route_name="admin:ari_checks:cert_latest_overdue_paginated|json",
        renderer="json",
    )
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
    @docify(
        {
            "endpoint": "/ari-checks/all.json",
            "section": "ari-check",
            "about": """list AriCheck(s) ALL""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/ari-checks/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/ari-checks/all/{PAGE}.json",
            "section": "ari-check",
            "example": "curl {ADMIN_PREFIX}/ari-checks/all/1.json",
            "variant_of": "/ari-checks/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/ari-checks/cert-latest.json",
            "section": "ari-check",
            "about": """list AriCheck(s) Cert Latest""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/ari-checks/cert-latest.json",
        }
    )
    @docify(
        {
            "endpoint": "/ari-checks/cert-latest/{PAGE}.json",
            "section": "ari-check",
            "example": "curl {ADMIN_PREFIX}/ari-checks/cert-latest/1.json",
            "variant_of": "/ari-checks/cert-latest.json",
        }
    )
    @docify(
        {
            "endpoint": "/ari-checks/cert-latest-overdue.json",
            "section": "ari-check",
            "about": """list AriCheck(s) Cert Latest Overdue""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/ari-checks/cert-latest-overdue.json",
        }
    )
    @docify(
        {
            "endpoint": "/ari-checks/cert-latest-overdue/{PAGE}.json",
            "section": "ari-check",
            "example": "curl {ADMIN_PREFIX}/ari-checks/cert-latest-overdue/1.json",
            "variant_of": "/ari-checks/cert-latest.json",
        }
    )
    def list(self):
        sidenav_option = ""
        if self.request.matched_route.name in (
            "admin:ari_checks:all",
            "admin:ari_checks:all_paginated",
            "admin:ari_checks:all|json",
            "admin:ari_checks:all_paginated|json",
        ):
            sidenav_option = "all"
        elif self.request.matched_route.name in (
            "admin:ari_checks:cert_latest",
            "admin:ari_checks:cert_latest_paginated",
            "admin:ari_checks:cert_latest|json",
            "admin:ari_checks:cert_latest_paginated|json",
        ):
            sidenav_option = "cert-latest"
        elif self.request.matched_route.name in (
            "admin:ari_checks:cert_latest_overdue",
            "admin:ari_checks:cert_latest_overdue_paginated",
            "admin:ari_checks:cert_latest_overdue|json",
            "admin:ari_checks:cert_latest_overdue_paginated|json",
        ):
            sidenav_option = "cert-latest-overdue"

        url_template = "%s/ari-checks/%s/{0}" % (
            self.request.api_context.application_settings["admin_prefix"],
            "sidenav_option",
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        items_count = lib_db.get.get__AriChecks__count(
            self.request.api_context, strategy=sidenav_option
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AriChecks___paginated(
            self.request.api_context,
            strategy=sidenav_option,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _auths = {k.id: k.as_json for k in items_paged}
            return {
                "AriChecks": _auths,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AriChecks_count": items_count,
            "AriChecks": items_paged,
            "pager": pager,
            "sidenav_option": sidenav_option,
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
