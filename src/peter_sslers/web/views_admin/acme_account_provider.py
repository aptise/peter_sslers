# pypi
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ...lib import db as lib_db

# from ..lib.docs import formatted_get_docs


# ==============================================================================


class ViewAdmin(Handler):
    @view_config(
        route_name="admin:acme_account_providers",
        renderer="/admin/acme_account_providers.mako",
    )
    @view_config(route_name="admin:acme_account_providers|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-account-providers.json",
            "section": "acme-account-provider",
            "about": """list AcmeAccountProvider(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account-providers.json",
        }
    )
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
