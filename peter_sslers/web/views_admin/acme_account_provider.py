# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response

# stdlib
import datetime

# pypi
import sqlalchemy

# localapp
from ..lib.handler import Handler
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model import utils as model_utils


# ==============================================================================


class ViewAdmin(Handler):
    @view_config(
        route_name="admin:acme_account_providers", renderer="/admin/acme_account_providers.mako"
    )
    @view_config(route_name="admin:acme_account_providers|json", renderer="json")
    def list(self):
        items_paged = lib_db.get.get__AcmeAccountProviders__paginated(self.request.api_context)
        if self.request.wants_json:
            _keys = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeAccountProviders": _keys,
            }
        return {
            "project": "peter_sslers",
            "AcmeAccountProviders": items_paged,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
