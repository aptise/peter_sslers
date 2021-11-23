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
    @view_config(route_name="admin:root_stores", renderer="/admin/root_stores.mako")
    @view_config(
        route_name="admin:root_stores_paginated", renderer="/admin/root_stores.mako"
    )
    @view_config(route_name="admin:root_stores|json", renderer="json")
    @view_config(route_name="admin:root_stores_paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/root-stores.json",
            "section": "root-store",
            "about": """list RootStore(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/root-stores.json",
        }
    )
    @docify(
        {
            "endpoint": "/root-stores/{PAGE}.json",
            "section": "root-store",
            "example": "curl {ADMIN_PREFIX}/root-stores/1.json",
            "variant_of": "/root-stores.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__RootStore__count(self.request.api_context)
        url_template = (
            "%s/root-store/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__RootStore__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _sets = {s.id: s.as_json for s in items_paged}
            return {
                "RootStores": _sets,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "RootStores_count": items_count,
            "RootStores": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbRootStore = None

    def _focus(self):
        if self.dbRootStore is None:
            dbRootStore = lib_db.get.get__RootStore__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbRootStore:
                raise HTTPNotFound("the Root Store was not found")
            self.dbRootStore = dbRootStore
            self._focus_item = dbRootStore
            self._focus_url = "%s/root-store/%s" % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                self.dbRootStore.id,
            )
        return self.dbRootStore

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:root_store:focus",
        renderer="/admin/root_store-focus.mako",
    )
    @view_config(route_name="admin:root_store:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/root-store/{ID}.json",
            "section": "root-store",
            "about": """root-store focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/root-store/1.json",
        }
    )
    def focus(self):
        dbRootStore = self._focus()
        if self.request.wants_json:
            return {"RootStore": dbRootStore.as_json}

        return {"project": "peter_sslers", "RootStore": dbRootStore}
