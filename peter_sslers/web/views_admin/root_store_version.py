# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import sqlalchemy
import transaction

# localapp
from .. import lib
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ..lib import formhandling
from ...model import utils as model_utils
from ...model import objects as model_objects
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils


# ==============================================================================


class View_Focus(Handler):
    dbRootStoreVersion = None

    def _focus(self):
        if self.dbRootStoreVersion is None:
            dbRootStoreVersion = lib_db.get.get__RootStoreVersion__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbRootStoreVersion:
                raise HTTPNotFound("the Root Store Version was not found")
            self.dbRootStoreVersion = dbRootStoreVersion
            self._focus_item = dbRootStoreVersion
            self._focus_url = "%s/root-store-version/%s" % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                self.dbRootStoreVersion.id,
            )
        return self.dbRootStoreVersion

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:root_store_version:focus",
        renderer="/admin/root_store_version-focus.mako",
    )
    @view_config(route_name="admin:root_store_version:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/root-store-version/{ID}.json",
            "section": "root-store-version",
            "about": """root-store-version focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/root-store-version/1.json",
        }
    )
    def focus(self):
        dbRootStoreVersion = self._focus()
        if self.request.wants_json:
            return {"RootStoreVersion": dbRootStoreVersion.as_json}

        return {"project": "peter_sslers", "RootStoreVersion": dbRootStoreVersion}
