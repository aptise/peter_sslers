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
        route_name="admin:domains_blocklisted",
        renderer="/admin/domains_blocklisted.mako",
    )
    @view_config(
        route_name="admin:domains_blocklisted-paginated",
        renderer="/admin/domains_blocklisted.mako",
    )
    @view_config(route_name="admin:domains_blocklisted|json", renderer="json")
    @view_config(route_name="admin:domains_blocklisted-paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/domain-blocklisteds.json",
            "section": "domain-blocklisted",
            "about": """list DomainBlocklisted(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain-blocklisteds.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain-blocklisteds/{PAGE}.json",
            "section": "domain-blocklisted",
            "example": "curl {ADMIN_PREFIX}/domain-blocklisteds/1.json",
            "variant_of": "/domain-blocklisteds.json",
        }
    )
    def list(self):
        url_template = (
            "%s/domains-blocklisted/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        items_count = lib_db.get.get__DomainBlocklisted__count(
            self.request.api_context,
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__DomainBlocklisted__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )

        if self.request.wants_json:
            return {
                "DomainsBlocklisted": [d.as_json for d in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "DomainsBlocklisted_count": items_count,
            "DomainsBlocklisted": items_paged,
            "pager": pager,
        }
