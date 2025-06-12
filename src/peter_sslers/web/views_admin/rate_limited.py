# stdlib
from typing import Optional

# from typing import Dict

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import RateLimited

# ==============================================================================


class View_List(Handler):

    @view_config(route_name="admin:rate_limiteds", renderer="/admin/rate_limiteds.mako")
    @view_config(route_name="admin:rate_limiteds-paginated", renderer="/admin/rate_limiteds.mako")
    @view_config(route_name="admin:rate_limiteds-paginated|json", renderer="json")
    @view_config(route_name="admin:rate_limiteds|json", renderer="json")
    @docify(
        {
            "endpoint": "/rate-limiteds.json",
            "section": "rate-limited",
            "about": """list RenewalConfiguration(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/rate-limiteds.json",
        }
    )
    @docify(
        {
            "endpoint": "/rate-limiteds/{PAGE}.json",
            "section": "rate-limited",
            "example": "curl {ADMIN_PREFIX}/rate-limiteds/1.json",
            "variant_of": "/rate-limiteds.json",
        }
    )
    def list(self):
        url_template = "%s/rate-limiteds/{0}" % (
            self.request.api_context.application_settings["admin_prefix"],
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        items_count = lib_db.get.get__RateLimited__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__RateLimited__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            # admin_url = self.request.admin_url
            return {
                "RateLimiteds": [i.as_json for i in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "RateLimiteds_count": items_count,
            "RateLimiteds": items_paged,
            "pager": pager,
        }


# ------------------------------------------------------------------------------


class View_Focus(Handler):
    dbRateLimited: Optional[RateLimited] = None

    def _focus(self) -> RateLimited:
        if self.dbRateLimited is None:
            dbRateLimited = lib_db.get.get__RateLimited__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbRateLimited:
                raise HTTPNotFound("the RateLimited was not found")
            self.dbRateLimited = dbRateLimited
            self._focus_url = "%s/rate-limited/%s" % (
                self.request.admin_url,
                self.dbRateLimited.id,
            )
        return self.dbRateLimited

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:rate_limited:focus",
        renderer="/admin/rate_limited-focus.mako",
    )
    @view_config(route_name="admin:rate_limited:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/rate-limited/{ID}.json",
            "section": "rate-limited",
            "about": """RateLimited focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/rate-limited/1.json",
        }
    )
    def focus(self):
        dbRateLimited = self._focus()
        if self.request.wants_json:
            return {
                "RateLimited": dbRateLimited.as_json,
            }
        return {
            "project": "peter_sslers",
            "RateLimited": dbRateLimited,
        }
