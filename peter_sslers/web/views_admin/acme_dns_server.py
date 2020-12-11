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
from ...lib import acmedns as lib_acmedns
from ...lib import db as lib_db
from ...model import utils as model_utils
from ..lib import formhandling
from ..lib.forms import Form_AcmeDnsServer_new
from ..lib.forms import Form_AcmeDnsServer_mark
from ..lib.forms import Form_AcmeDnsServer_edit
from ..lib.forms import Form_AcmeDnsServer_ensure_domains
from ..lib.forms import Form_AcmeDnsServer_import_domain
from ..lib.handler import Handler
from ..lib.handler import json_pagination
from ...lib import utils
from ...lib import errors

# ==============================================================================


def encode_AcmeDnsServerAccounts(dbAcmeDnsServerAccounts):
    domain_matrix = {}
    for _dbAcmeDnsServerAccount in dbAcmeDnsServerAccounts:
        _dbDomain = _dbAcmeDnsServerAccount.domain
        domain_matrix[_dbDomain.domain_name] = {
            "Domain": {
                "id": _dbDomain.id,
                "domain_name": _dbDomain.domain_name,
            },
            "AcmeDnsServerAccount": {
                "id": _dbAcmeDnsServerAccount.id,
                "subdomain": _dbAcmeDnsServerAccount.subdomain,
                "fulldomain": _dbAcmeDnsServerAccount.fulldomain,
            },
        }
    return domain_matrix


class View_List(Handler):
    @view_config(
        route_name="admin:acme_dns_servers",
        renderer="/admin/acme_dns_servers.mako",
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
                "instructions": [
                    "HTTP POST required",
                ],
                "form_fields": {"root_url": "The root url of the api"},
                "notes": [],
                "valid_options": {},
            }
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_dns_server-new.mako",
            {},
            self.request,
        )

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
            self.request.api_context,
            self.request.matchdict["id"],
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
    def check(self):
        dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._check__submit(dbAcmeDnsServer)
        return self._check__print(dbAcmeDnsServer)

    def _check__print(self, dbAcmeDnsServer):
        if self.request.wants_json:
            return {
                "instructions": [
                    "HTTP POST required",
                    """curl --form 'action=active' %s/check.json""" % self._focus_url,
                ],
            }
        url_post_required = (
            "%s?result=error&error=post+required&operation=mark" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _check__submit(self, dbAcmeDnsServer):
        try:
            resp = requests.get("%s/health" % dbAcmeDnsServer.root_url)
            if resp.status_code != 200:
                raise ValueError("invalid status_code: %s" % resp.status_code)
            if self.request.wants_json:
                return {"result": "success", "health": True}
            url_success = "%s?result=success&operation=check" % (self._focus_url,)
            return HTTPSeeOther(url_success)
        except Exception as exc:
            if self.request.wants_json:
                return {"result": "error", "health": None}
            url_failure = "%s?result=error&operation=check" % (self._focus_url,)
            return HTTPSeeOther(url_failure)

    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts",
        renderer="/admin/acme_dns_server-focus-acme_dns_server_accounts.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts_paginated",
        renderer="/admin/acme_dns_server-focus-acme_dns_server_accounts.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts_paginated|json",
        renderer="json",
    )
    def list_accounts(self):
        dbAcmeDnsServer = self._focus(eagerload_web=True)
        items_count = lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__count(
            self.request.api_context, dbAcmeDnsServer.id
        )
        items_paged = (
            lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__paginated(
                self.request.api_context, dbAcmeDnsServer.id
            )
        )
        if self.request.wants_json:
            return {
                "AcmeDnsServer": dbAcmeDnsServer.as_json,
                "AcmeDnsServerAccounts": [s.as_json for s in items_paged],
                "AcmeDnsServerAccounts_count": items_count,
            }
        return {
            "project": "peter_sslers",
            "AcmeDnsServer": dbAcmeDnsServer,
            "AcmeDnsServerAccounts": items_paged,
            "AcmeDnsServerAccounts_count": items_count,
        }

    @view_config(route_name="admin:acme_dns_server:focus:ensure_domains", renderer=None)
    @view_config(
        route_name="admin:acme_dns_server:focus:ensure_domains|json", renderer="json"
    )
    def ensure_domains(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._ensure_domains__submit()
        return self._ensure_domains__print()

    def _ensure_domains__print(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if self.request.wants_json:
            return {
                "instructions": [
                    "HTTP POST required",
                ],
                "form_fields": {
                    "domain_names": "A comma separated list of domain names"
                },
                "notes": [],
                "valid_options": {},
            }
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_dns_server-focus-ensure_domains.mako",
            {"AcmeDnsServer": dbAcmeDnsServer},
            self.request,
        )

    def _ensure_domains__submit(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        try:
            if lib_acmedns.pyacmedns is None:
                raise formhandling.FormInvalid("`pyacmedns` is not installed")
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeDnsServer_ensure_domains,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                # this function checks the domain names match a simple regex
                domain_names = utils.domains_from_string(
                    formStash.results["domain_names"]
                )
            except ValueError as exc:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="invalid domain names detected"
                )
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names",
                    message="invalid or no valid domain names detected",
                )
            if len(domain_names) > 100:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names",
                    message="More than 100 domain names. There is a max of 100 domains per certificate.",
                )

            # initialize a client
            client = lib_acmedns.new_client(dbAcmeDnsServer.root_url)

            dbAcmeDnsServerAccounts = []
            for _domain_name in domain_names:
                _dbAcmeDnsServerAccount = None
                _is_created__account = None
                (
                    _dbDomain,
                    _is_created__domain,
                ) = lib_db.getcreate.getcreate__Domain__by_domainName(
                    self.request.api_context, _domain_name, is_from_queue_domain=False
                )
                if not _is_created__domain:
                    _dbAcmeDnsServerAccount = lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId_DomainId(
                        self.request.api_context,
                        acme_dns_server_id=dbAcmeDnsServer.id,
                        domain_id=_dbDomain.id,
                    )
                if not _dbAcmeDnsServerAccount:
                    try:
                        account = client.register_account(None)  # arg = allowlist ips
                    except Exception as exc:
                        raise ValueError("error registering an account with AcmeDns")
                    _dbAcmeDnsServerAccount = (
                        lib_db.create.create__AcmeDnsServerAccount(
                            self.request.api_context,
                            dbAcmeDnsServer=dbAcmeDnsServer,
                            dbDomain=_dbDomain,
                            username=account["username"],
                            password=account["password"],
                            fulldomain=account["fulldomain"],
                            subdomain=account["subdomain"],
                            allowfrom=account["allowfrom"],
                        )
                    )
                    _is_created__account = True

                dbAcmeDnsServerAccounts.append(_dbAcmeDnsServerAccount)

            if self.request.wants_json:
                result_matrix = encode_AcmeDnsServerAccounts(dbAcmeDnsServerAccounts)
                return {"result": "success", "result_matrix": result_matrix}

            acme_dns_server_accounts = ",".join(
                [
                    str(_dbAcmeDnsServerAccount.id)
                    for _dbAcmeDnsServerAccount in dbAcmeDnsServerAccounts
                ]
            )
            url_success = "%s/ensure-domains-results?acme-dns-server-accounts=%s" % (
                self._focus_url,
                acme_dns_server_accounts,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._ensure_domains__print)

    @view_config(
        route_name="admin:acme_dns_server:focus:ensure_domains_results",
        renderer="/admin/acme_dns_server-focus-ensure_domains-results.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server:focus:ensure_domains_results|json",
        renderer="json",
    )
    def ensure_domains_results(self):
        try:
            dbAcmeDnsServer = self.dbAcmeDnsServer = self._focus()
            _AcmeDnsServerAccountIds = self.request.params.get(
                "acme-dns-server-accounts", ""
            )
            _AcmeDnsServerAccountIds = [
                int(i) for i in _AcmeDnsServerAccountIds.split(",")
            ]
            if not _AcmeDnsServerAccountIds:
                raise ValueError("missing `acme-dns-server-accounts`")
            if len(_AcmeDnsServerAccountIds) > 100:
                raise ValueError(
                    "More than 100 AcmeDnsServerAccounts specified; this is not allowed."
                )
            dbAcmeDnsServerAccounts = lib_db.get.get__AcmeDnsServerAccounts__by_ids(
                self.request.api_context, _AcmeDnsServerAccountIds
            )
            if not dbAcmeDnsServerAccounts:
                raise ValueError("invalid `acme-dns-server-accounts`")

            if self.request.wants_json:
                result_matrix = encode_AcmeDnsServerAccounts(dbAcmeDnsServerAccounts)
                return {"result": "success", "result_matrix": result_matrix}

            return {
                "project": "peter_sslers",
                "AcmeDnsServer": dbAcmeDnsServer,
                "AcmeDnsServerAccounts": dbAcmeDnsServerAccounts,
            }

        except:
            raise

    @view_config(route_name="admin:acme_dns_server:focus:import_domain", renderer=None)
    @view_config(
        route_name="admin:acme_dns_server:focus:import_domain|json", renderer="json"
    )
    def import_domain(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._import_domain__submit()
        return self._import_domain__print()

    def _import_domain__print(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if self.request.wants_json:
            return {
                "instructions": [
                    "HTTP POST required",
                ],
                "form_fields": {
                    "domain_name": "The domain name",
                    "username": "The acme-dns username",
                    "password": "The acme-dns password",
                    "fulldomain": "The acme-dns fulldomain",
                    "subdomain": "The acme-dns subdomain",
                    "allowfrom": "The acme-dns allowfrom",
                },
                "notes": [],
                "valid_options": {},
            }
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_dns_server-focus-import_domain.mako",
            {"AcmeDnsServer": dbAcmeDnsServer},
            self.request,
        )

    def _import_domain__submit(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        try:
            if lib_acmedns.pyacmedns is None:
                raise formhandling.FormInvalid("`pyacmedns` is not installed")
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeDnsServer_import_domain,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            for test_domain in ("domain_name", "fulldomain"):
                try:
                    # this function checks the domain names match a simple regex
                    domain_name = utils.domains_from_string(
                        formStash.results[test_domain]
                    )
                except ValueError as exc:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field=test_domain, message="invalid domain names detected"
                    )
                if not domain_name:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field=test_domain,
                        message="invalid or no valid domain names detected",
                    )
                if len(domain_name) != 1:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field=test_domain,
                        message="Only 1 domain accepted here.",
                    )

            # ensure we have a domain!
            domain_name = formStash.results["domain_name"]
            (
                _dbDomain,
                _is_created__domain,
            ) = lib_db.getcreate.getcreate__Domain__by_domainName(
                self.request.api_context, domain_name, is_from_queue_domain=False
            )
            _dbAcmeDnsServerAccount = None
            _is_created__account = None
            if not _is_created__domain:
                _dbAcmeDnsServerAccount = (
                    lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId_DomainId(
                        self.request.api_context,
                        acme_dns_server_id=dbAcmeDnsServer.id,
                        domain_id=_dbDomain.id,
                    )
                )
            if not _dbAcmeDnsServerAccount:
                _dbAcmeDnsServerAccount = lib_db.create.create__AcmeDnsServerAccount(
                    self.request.api_context,
                    dbAcmeDnsServer=dbAcmeDnsServer,
                    dbDomain=_dbDomain,
                    username=formStash.results["username"],
                    password=formStash.results["password"],
                    fulldomain=formStash.results["fulldomain"],
                    subdomain=formStash.results["subdomain"],
                    allowfrom=formStash.results["allowfrom"] or "[]",
                )
                _is_created__account = True

            if self.request.wants_json:
                result_matrix = encode_AcmeDnsServerAccounts(
                    [
                        _dbAcmeDnsServerAccount,
                    ]
                )
                result_matrix[_dbDomain.domain_name]["result"] = (
                    "success" if _is_created__account else "existing"
                )
                return {"result": "success", "result_matrix": result_matrix}

            url_success = "%s/acme-dns-server-account/%s?result=%s&operation=import" % (
                self.request.admin_url,
                _dbAcmeDnsServerAccount.id,
                "success" if _is_created__account else "existing",
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._import_domain__print)


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:acme_dns_server:focus:mark", renderer=None)
    @view_config(route_name="admin:acme_dns_server:focus:mark|json", renderer="json")
    def mark(self):
        dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._mark__submit(dbAcmeDnsServer)
        return self._mark__print(dbAcmeDnsServer)

    def _mark__print(self, dbAcmeDnsServer):
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

    def _mark__submit(self, dbAcmeDnsServer):
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
                    raise errors.InvalidTransition("Invalid option")

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

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
    def edit(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._edit__submit()
        return self._edit__print()

    def _edit__print(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'action=active' %s/edit.json""" % self._focus_url
                ],
                "form_fields": {"root_url": "the url"},
            }
        return render_to_response(
            "/admin/acme_dns_server-focus-edit.mako",
            {
                "project": "peter_sslers",
                "AcmeDnsServer": dbAcmeDnsServer,
            },
            self.request,
        )

    def _edit__submit(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
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

            try:
                result = lib_db.update.update_AcmeDnsServer__root_url(
                    self.request.api_context,
                    dbAcmeDnsServer,
                    formStash.results["root_url"],
                )
            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(exc.args[0])

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
