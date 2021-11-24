# pypi
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db


# ==============================================================================


class View_List(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain_autocerts",
        renderer="/admin/domain_autocerts.mako",
    )
    @view_config(
        route_name="admin:domain_autocerts_paginated",
        renderer="/admin/domain_autocerts.mako",
    )
    @view_config(route_name="admin:domain_autocerts|json", renderer="json")
    @view_config(route_name="admin:domain_autocerts_paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/domain-autocerts.json",
            "section": "domain-autocert",
            "about": """list DomainAutocert(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain-autocerts.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain-autocerts/{PAGE}.json",
            "section": "domain-autocert",
            "example": "curl {ADMIN_PREFIX}/domain-autocerts/1.json",
            "variant_of": "/domain-autocerts.json",
        }
    )
    def list(self):
        url_template = (
            "%s/domain-autocerts/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        items_count = lib_db.get.get__DomainAutocert__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__DomainAutocert__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )

        if self.request.wants_json:
            return {
                "DomainAutocerts": [d.as_json for d in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "DomainAutocerts_count": items_count,
            "DomainAutocerts": items_paged,
            "pager": pager,
        }
