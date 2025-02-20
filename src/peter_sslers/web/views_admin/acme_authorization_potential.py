# stdlib
from typing import Optional

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import AcmeAuthorizationPotential

# from ...lib import errors
# from ...model import objects as model_objects


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:acme_authorization_potentials",
        renderer="/admin/acme_authorization_potentials.mako",
    )
    @view_config(
        route_name="admin:acme_authorization_potentials-paginated",
        renderer="/admin/acme_authorization_potentials.mako",
    )
    @view_config(
        route_name="admin:acme_authorization_potentials|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:acme_authorization_potentials-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-authz-potentials.json",
            "section": "acme-authz-potential",
            "about": """list AcmeAuthorizationPotential(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-authz-potentials.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-authz-potentials/{PAGE}.json",
            "section": "acme-authz-potential",
            "example": "curl {ADMIN_PREFIX}/acme-authz-potentials/1.json",
            "variant_of": "/acme-authz-potentials.json",
        }
    )
    def list(self):
        url_template = (
            "%s/acme-authz-potentials/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        items_count = lib_db.get.get__AcmeAuthorizationPotentials__count(
            self.request.api_context
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeAuthorizationPotentials__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _auths = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeAuthorizationPotentials": _auths,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeAuthorizationPotentials_count": items_count,
            "AcmeAuthorizationPotentials": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbAcmeAuthorizationPotential: Optional[AcmeAuthorizationPotential] = None

    def _focus(self) -> AcmeAuthorizationPotential:
        if self.dbAcmeAuthorizationPotential is None:
            dbAcmeAuthorizationPotential = (
                lib_db.get.get__AcmeAuthorizationPotential__by_id(
                    self.request.api_context,
                    self.request.matchdict["id"],
                )
            )
            if not dbAcmeAuthorizationPotential:
                raise HTTPNotFound("The AcmeAuthorizationPotential was not found")
            self.dbAcmeAuthorizationPotential = dbAcmeAuthorizationPotential
            self._focus_url = "%s/acme-authz-potential/%s" % (
                self.request.admin_url,
                self.dbAcmeAuthorizationPotential.id,
            )
        return self.dbAcmeAuthorizationPotential

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_authorization_potential:focus",
        renderer="/admin/acme_authorization_potential-focus.mako",
    )
    @view_config(
        route_name="admin:acme_authorization_potential:focus|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-authz-potential/{ID}.json",
            "section": "acme-authz-potential",
            "about": """AcmeAuthorizationPotential focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-authz-potential/1.json",
        }
    )
    def focus(self):
        dbAcmeAuthorizationPotential = self._focus()
        if self.request.wants_json:
            return {
                "AcmeAuthorizationPotential": dbAcmeAuthorizationPotential.as_json,
            }
        return {
            "project": "peter_sslers",
            "AcmeAuthorizationPotential": dbAcmeAuthorizationPotential,
        }


class View_Focus_Manipulate(View_Focus):
    @view_config(
        route_name="admin:acme_authorization_potential:focus:delete", renderer=None
    )
    @view_config(
        route_name="admin:acme_authorization_potential:focus:delete|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-authz-potential/{ID}/delete.json",
            "section": "acme-authz-potential",
            "about": """AcmeAuthorizationPotential focus: delete""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/acme-authz-potential/1/delete.json",
        }
    )
    def delete(self):
        """
        Acme Refresh should just update the record against the acme server.
        """
        dbAcmeAuthorizationPotential = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self, "/acme-authz-potential/{ID}/delete.json"
                )
            return HTTPSeeOther(
                "%s?result=error&operation=delete&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            self.request.dbSession.delete(dbAcmeAuthorizationPotential)
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "delete",
                    "AcmeAuthorizationPotential": dbAcmeAuthorizationPotential.as_json,
                }
            return HTTPSeeOther(
                "%s/acme-authz-potentials?id=%s&result=success&operation=delete"
                % (self.request.admin_url, dbAcmeAuthorizationPotential.id)
            )
        except Exception:
            raise
