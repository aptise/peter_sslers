# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime

# pypi
import requests
import sqlalchemy

# localapp
from ...lib import db as lib_db
from ...model import utils as model_utils
from ..lib import formhandling
from ..lib.forms import Form_AcmeDnsServer_new
from ..lib.forms import Form_AcmeDnsServer_mark
from ..lib.forms import Form_AcmeDnsServer_edit
from ..lib.handler import Handler
from ..lib.handler import json_pagination
from ...lib import utils
from ...lib import errors

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:acme_dns_servers", renderer="/admin/acme_dns_servers.mako",
    )
    @view_config(route_name="admin:acme_dns_servers|json", renderer="json")
    @view_config(
        route_name="admin:acme_dns_servers_paginated",
        renderer="/admin/acme_dns_servers.mako",
    )
    @view_config(route_name="admin:acme_dns_servers_paginated|json", renderer="json")
    def list(self):
        items_count = lib_db.get.get__AcmeDnsServer__count(self.request.api_context)
        items_paged = lib_db.get.get__AcmeDnsServer__paginated(self.request.api_context)
        if self.request.wants_json:
            return {
                "AcmeDnsServers": [s.as_json for s in items_paged],
                "AcmeDnsServers_count": items_count,
            }
        return {
            "project": "peter_sslers",
            "AcmeDnsServers": items_paged,
            "AcmeDnsServers_count": items_count,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_New(Handler):
    @view_config(route_name="admin:acme_dns_server:new")
    @view_config(route_name="admin:acme_dns_server:new|json", renderer="json")
    def new(self):
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return {
                "instructions": [],
                "form_fields": {},
                "notes": [],
                "valid_options": {},
            }
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response("/admin/acme_dns_server-new.mako", {}, self.request,)

    def _new__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeDnsServer_new, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            (dbAcmeDnsServer, _is_created,) = lib_db.getcreate.getcreate__AcmeDnsServer(
                self.request.api_context, root_url=formStash.results["root_url"]
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeDnsServer": dbAcmeDnsServer.as_json,
                    "is_created": True if _is_created else False,
                }
            return HTTPSeeOther(
                "%s/acme-dns-server/%s?result=success&operation=new%s"
                % (
                    self.request.admin_url,
                    dbAcmeDnsServer.id,
                    ("&is_created=1" if _is_created else "&is_existing=1"),
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)


class View_Focus(Handler):
    def _focus(self, eagerload_web=False):
        dbAcmeDnsServer = lib_db.get.get__AcmeDnsServer__by_id(
            self.request.api_context, self.request.matchdict["id"],
        )
        if not dbAcmeDnsServer:
            raise HTTPNotFound("the acme-dns server was not found")
        self._focus_url = "%s/acme-dns-server/%s" % (
            self.request.admin_url,
            dbAcmeDnsServer.id,
        )
        return dbAcmeDnsServer

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_dns_server:focus",
        renderer="/admin/acme_dns_server-focus.mako",
    )
    @view_config(route_name="admin:acme_dns_server:focus|json", renderer="json")
    def focus(self):
        dbAcmeDnsServer = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "AcmeDnsServer": dbAcmeDnsServer.as_json,
            }
        return {"project": "peter_sslers", "AcmeDnsServer": dbAcmeDnsServer}

    @view_config(route_name="admin:acme_dns_server:focus:check", renderer=None)
    @view_config(route_name="admin:acme_dns_server:focus:check|json", renderer="json")
    def focus_check(self):
        dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._focus_check__submit(dbAcmeDnsServer)
        return self._focus_check__print(dbAcmeDnsServer)

    def _focus_check__print(self, dbAcmeDnsServer):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'action=active' %s/check.json""" % self._focus_url,
                    """POST required.""",
                ],
            }
        url_post_required = (
            "%s?result=error&error=post+required&operation=mark" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_check__submit(self, dbAcmeDnsServer):
        try:
            resp = requests.get("%s/health" % dbAcmeDnsServer.root_url)
            if resp.status_code != 200:
                raise ValueError("invalid status_code: %s" % resp.status_code)
            if self.request.wants_json:
                return {"result": "success", "health": True}
            url_success = "%s?result=success&operation=check" % (
                self._focus_url,
            )
            return HTTPSeeOther(url_success)
        except Exception as exc:
            if self.request.wants_json:
                return {"result": "success", "health": False}
            url_failure = "%s?result=error&operation=check" % (
                self._focus_url,
            )
            return HTTPSeeOther(url_failure)


    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts", renderer="/admin/acme_dns_server-focus-acme_dns_server_accounts.mako",
    )
    @view_config(route_name="admin:acme_dns_server:focus:acme_dns_server_accounts|json", renderer="json")
    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts_paginated",
        renderer="/admin/acme_dns_server-focus-acme_dns_server_accounts.mako",
    )
    @view_config(route_name="admin:acme_dns_server:focus:acme_dns_server_accounts_paginated|json", renderer="json")
    def list_accounts(self):
        dbAcmeDnsServer = self._focus(eagerload_web=True)
        items_count = lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__count(self.request.api_context, dbAcmeDnsServer.id)
        items_paged = lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__paginated(self.request.api_context, dbAcmeDnsServer.id)
        if self.request.wants_json:
            return {
                "AcmeDnsServer": dbAcmeDnsServer.as_json,
                "AcmeDnsServerAccounts": [s.as_json for s in items_paged],
                "AcmeDnsServerAccounts_count": items_count,
            }
        return {
            "project": "peter_sslers",
                "AcmeDnsServer": dbAcmeDnsServer,
                "AcmeDnsServerAccounts": [s.as_json for s in items_paged],
                "AcmeDnsServerAccounts_count": items_count,
        }
        


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:acme_dns_server:focus:mark", renderer=None)
    @view_config(route_name="admin:acme_dns_server:focus:mark|json", renderer="json")
    def focus_mark(self):
        dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._focus_mark__submit(dbAcmeDnsServer)
        return self._focus_mark__print(dbAcmeDnsServer)

    def _focus_mark__print(self, dbAcmeDnsServer):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'action=active' %s/mark.json""" % self._focus_url
                ],
                "form_fields": {"action": "the intended action"},
                "valid_options": {"action": ["active", "inactive", "global_default"]},
            }
        url_post_required = (
            "%s?result=error&error=post+required&operation=mark" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self, dbAcmeDnsServer):
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeDnsServer_mark, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string(
                "AcmeDnsServer__mark"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_dns_server.id"] = dbAcmeDnsServer.id
            event_payload_dict["action"] = formStash.results["action"]

            event_status = None
            event_alt = None
            try:
                if action == "active":
                    event_status = lib_db.update.update_AcmeDnsServer__set_active(
                        self.request.api_context, dbAcmeDnsServer
                    )

                elif action == "inactive":
                    event_status = lib_db.update.update_AcmeDnsServer__unset_active(
                        self.request.api_context, dbAcmeDnsServer
                    )

                elif action == "global_default":
                    (
                        event_status,
                        alt_info,
                    ) = lib_db.update.update_AcmeDnsServer__set_global_default(
                        self.request.api_context, dbAcmeDnsServer
                    )
                    if alt_info:
                        for (k, v) in alt_info["event_payload_dict"].items():
                            event_payload_dict[k] = v
                        event_alt = alt_info["event_alt"]

                else:
                    raise errors.InvalidTransition("invalid option")

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

            self.request.api_context.dbSession.flush(objects=[dbAcmeDnsServer])

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
                dbAcmeDnsServer=dbAcmeDnsServer,
            )
            if event_alt:
                lib_db.logger._log_object_event(
                    self.request.api_context,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                        event_alt[0]
                    ),
                    dbAcmeDnsServer=event_alt[1],
                )
            if self.request.wants_json:
                return {"result": "success", "AcmeDnsServer": dbAcmeDnsServer.as_json}
            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                errors.formstash_to_querystring(formStash),
                action,
            )
            raise HTTPSeeOther(url_failure)

    @view_config(route_name="admin:acme_dns_server:focus:edit", renderer=None)
    @view_config(route_name="admin:acme_dns_server:focus:edit|json", renderer="json")
    def focus_edit(self):
        dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._focus_edit__submit(dbAcmeDnsServer)
        return self._focus_edit__print(dbAcmeDnsServer)

    def _focus_edit__print(self, dbAcmeDnsServer):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'action=active' %s/edit.json""" % self._focus_url
                ],
                "form_fields": {"root_url": "the url"},
            }
        return render_to_response(
            "/admin/acme_dns_server-focus-edit.mako",
            {"project": "peter_sslers", "AcmeDnsServer": dbAcmeDnsServer,},
            self.request,
        )

    def _focus_edit__submit(self, dbAcmeDnsServer):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeDnsServer_edit, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            event_type_id = model_utils.OperationsEventType.from_string(
                "AcmeDnsServer__edit"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_dns_server.id"] = dbAcmeDnsServer.id
            event_payload_dict["old.root_url"] = dbAcmeDnsServer.root_url
            event_payload_dict["new.root_url"] = formStash.results["root_url"]

            result = lib_db.update.update_AcmeDnsServer__root_url(
                self.request.api_context, dbAcmeDnsServer, formStash.results["root_url"]
            )

            self.request.api_context.dbSession.flush(objects=[dbAcmeDnsServer])

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type_id, event_payload_dict
            )
            lib_db.logger._log_object_event(
                self.request.api_context,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    "AcmeDnsServer__edit"
                ),
                dbAcmeDnsServer=dbAcmeDnsServer,
            )
            if self.request.wants_json:
                return {"result": "success", "AcmeDnsServer": dbAcmeDnsServer.as_json}
            url_success = "%s?result=success&operation=edit" % (self._focus_url,)
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._edit__print)
