# stdlib
from typing import Optional
from typing import TYPE_CHECKING

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_AcmeServer_mark
from ..lib.handler import Handler
from ...lib import acme_v2
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils
from ...model.objects import AcmeServer

# from ..lib.docs import formatted_get_docs


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:acme_servers",
        renderer="/admin/acme_servers.mako",
    )
    @view_config(route_name="admin:acme_servers|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-servers.json",
            "section": "acme-server",
            "about": """list AcmeServer(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-servers.json",
        }
    )
    def list(self):
        items_paged = lib_db.get.get__AcmeServers__paginated(self.request.api_context)
        if self.request.wants_json:
            _keys = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeServers": _keys,
            }
        return {
            "project": "peter_sslers",
            "AcmeServers": items_paged,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_Focus(Handler):
    dbAcmeServer: Optional[AcmeServer] = None

    def _focus(self) -> AcmeServer:
        if self.dbAcmeServer is None:
            dbAcmeServer = lib_db.get.get__AcmeServer__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbAcmeServer:
                raise HTTPNotFound("the acme server was not found")
            self.dbAcmeServer = dbAcmeServer
            self._focus_url = "%s/acme-server/%s" % (
                self.request.admin_url,
                self.dbAcmeServer.id,
            )
        return self.dbAcmeServer

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_server:focus",
        renderer="/admin/acme_server-focus.mako",
    )
    @view_config(route_name="admin:acme_server:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-server/{ID}.json",
            "section": "acme-server",
            "about": """AcmeServer""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-server/1.json",
        }
    )
    def focus(self):
        dbAcmeServer = self._focus()
        if self.request.wants_json:
            return {
                "AcmeServer": dbAcmeServer.as_json,
            }
        return {"project": "peter_sslers", "AcmeServer": dbAcmeServer}

    @view_config(route_name="admin:acme_server:focus:check_ari", renderer=None)
    @view_config(route_name="admin:acme_server:focus:check_ari|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-server/{ID}/check-ari.json",
            "section": "acme-server",
            "about": """AcmeServer check ARI""",
            "POST": True,
            "GET": None,
            "example": """curl --form 'action=active' {ADMIN_PREFIX}/acme-server/{ID}/check-ari.json""",
        }
    )
    def check_ari(self):
        dbAcmeServer = self._focus()
        if self.request.method == "POST":
            return self._check_ari__submit(dbAcmeServer)
        return self._check_ari__print(dbAcmeServer)

    def _check_ari__print(self, dbAcmeServer):
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-server/{ID}/check-ari.json")
        url_post_required = (
            "%s?result=error&error=post+required&operation=check-ari" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _check_ari__submit(self, dbAcmeServer):
        has_ari = acme_v2.check_endpoint_for_renewalInfo(
            dbAcmeServer.url, allow_insecure=dbAcmeServer.allow_insecure
        )
        if self.request.wants_json:
            return {"result": "success", "operation": "check-ari", "check-ari": has_ari}
        url_result = "%s?result=success&operation=check-ari&check-ari=%s" % (
            self._focus_url,
            has_ari,
        )
        return HTTPSeeOther(url_result)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_server:focus:mark", renderer=None)
    @view_config(route_name="admin:acme_server:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-server/{ID}/mark.json",
            "section": "acme-server",
            "about": """AcmeServer: Focus. Mark""",
            "POST": True,
            "GET": None,
            "example": "curl --form 'action=is_unlimited_pending_authz-true' {ADMIN_PREFIX}/acme-server/1/mark.json",
            "form_fields": {"action": "the intended action"},
            "valid_options": {
                "action": Form_AcmeServer_mark.fields["action"].list,
            },
        }
    )
    def focus_mark(self):
        dbAcmeServer = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._focus_mark__submit()
        return self._focus_mark__print()

    def _focus_mark__print(self):
        dbAcmeServer = self._focus()  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-server/{ID}/mark.json")
        url_post_required = "%s?result=error&error=post+required&operation=mark" % (
            self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self):
        dbAcmeServer = self._focus()  # noqa: F841
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeServer_mark,
                validate_get=False,
                # validate_post=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string("AcmeServer__mark")
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_server_id"] = dbAcmeServer.id
            event_payload_dict["action"] = formStash.results["action"]

            event_status: Optional[str] = None

            try:
                if action == "is_unlimited_pending_authz-true":
                    event_status = (
                        lib_db.update.update_AcmeServer__is_unlimited_pending_authz(
                            self.request.api_context,
                            dbAcmeServer,
                            is_unlimited_pending_authz=True,
                        )
                    )

                elif action == "is_unlimited_pending_authz-false":
                    event_status = (
                        lib_db.update.update_AcmeServer__is_unlimited_pending_authz(
                            self.request.api_context,
                            dbAcmeServer,
                            is_unlimited_pending_authz=False,
                        )
                    )

                else:
                    raise errors.InvalidTransition("Invalid option")

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

            if TYPE_CHECKING:
                assert event_status is not None

            self.request.api_context.dbSession.flush(objects=[dbAcmeServer])

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type, event_payload_dict
            )
            lib_db.logger._log_object_event(
                self.request.api_context,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    event_status
                ),
                dbAcmeServer=dbAcmeServer,
            )
            if self.request.wants_json:
                return {"result": "success", "AcmeServer": dbAcmeServer.as_json}
            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                errors.formstash_to_querystring(formStash),
                action,
            )
            raise HTTPSeeOther(url_failure)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
