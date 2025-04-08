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
    @view_config(
        route_name="admin:acme_polling_errors",
        renderer="/admin/acme_polling_error.mako",
    )
    @view_config(
        route_name="admin:acme_polling_errors-paginated",
        renderer="/admin/acme_polling_error.mako",
    )
    @view_config(route_name="admin:acme_polling_errors|json", renderer="json")
    @view_config(route_name="admin:acme_polling_errors-paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-polling-errors.json",
            "section": "acme-polling-errors",
            "about": """list AcmePollingError(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-polling-errors.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-polling-errors/{PAGE}.json",
            "section": "acme-polling-errors",
            "example": "curl {ADMIN_PREFIX}/acme-polling-errors/1.json",
            "variant_of": "/acme-polling-errors.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__AcmePollingError__count(self.request.api_context)
        url_template = (
            "%s/acme-polling-errors/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmePollingError__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _auths = {k.id: k.as_json for k in items_paged}
            return {
                "AcmePollingErrors": _auths,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmePollingErrors": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    def _acme_polling_error_focus(self):
        dbAcmePollingError = lib_db.get.get__AcmePollingError__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbAcmePollingError:
            raise HTTPNotFound("the error was not found")
        return dbAcmePollingError

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_polling_error:focus",
        renderer="/admin/acme_polling_error-focus.mako",
    )
    @view_config(
        route_name="admin:acme_polling_error:focus|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-polling-error/{ID}.json",
            "section": "acme-polling-error",
            "about": """AcmePollingError""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-polling-error/1.json",
        }
    )
    def focus(self):
        item = self._acme_polling_error_focus()
        if self.request.wants_json:
            return {
                "AcmePollingError": item.as_json,
            }
        return {"project": "peter_sslers", "AcmePollingError": item}
