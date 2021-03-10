# pyramid
from pyramid.view import view_config

# stdlib

# pypi

# localapp
from ..lib.handler import Handler
from ...lib import db as lib_db


# ==============================================================================


class ViewAdmin(Handler):
    @view_config(
        route_name="admin:acme_account_providers",
        renderer="/admin/acme_account_providers.mako",
    )
    @view_config(route_name="admin:acme_account_providers|json", renderer="json")
    def list(self):
        items_paged = lib_db.get.get__AcmeAccountProviders__paginated(
            self.request.api_context
        )
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
