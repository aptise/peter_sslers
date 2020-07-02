# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import json

# pypi
import sqlalchemy

# localapp
from .. import lib
from ..lib import formhandling
from ..lib.forms import Form_AcmeAccount_new__auth
from ..lib.forms import Form_AcmeAccount_new__file
from ..lib.forms import Form_AcmeAccount_mark
from ..lib.forms import Form_AcmeAccount_edit
from ..lib.forms import Form_AcmeAccount_deactivate_authorizations
from ..lib.form_utils import AcmeAccountUploadParser
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class View_List(Handler):
    @view_config(route_name="admin:acme_accounts", renderer="/admin/acme_accounts.mako")
    @view_config(
        route_name="admin:acme_accounts_paginated",
        renderer="/admin/acme_accounts.mako",
    )
    @view_config(route_name="admin:acme_accounts|json", renderer="json")
    @view_config(route_name="admin:acme_accounts_paginated|json", renderer="json")
    def list(self):
        items_count = lib_db.get.get__AcmeAccount__count(self.request.api_context)
        url_template = (
            "%s/acme-accounts/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeAccount__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _accounts = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeAccounts": _accounts,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeAccounts_count": items_count,
            "AcmeAccounts": items_paged,
            "pager": pager,
        }


class View_New(Handler):
    @view_config(route_name="admin:acme_account:upload")
    @view_config(route_name="admin:acme_account:upload|json", renderer="json")
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        self._load_AcmeAccountProviders()
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'account_key_file_pem=@key.pem' --form 'acme_account_provider_id=1' %s/acme-account/upload.json"""
                    % self.request.admin_url,
                    """curl --form 'account_key_file_le_meta=@meta.json' 'account_key_file_le_pkey=@private_key.json' 'account_key_file_le_reg=@regr.json' %s/acme-account/upload.json"""
                    % self.request.admin_url,
                ],
                "form_fields": {
                    "account_key_file_pem": "Group A",
                    "acme_account_provider_id": "Group A",
                    "account_key_file_le_meta": "Group B",
                    "account_key_file_le_pkey": "Group B",
                    "account_key_file_le_reg": "Group B",
                    "account__contact": "the contact's email address for the ACME Server",
                    "account__private_key_cycle": "how should the PrivateKey be cycled for this account?",
                },
                "notes": ["You must submit ALL items from Group A or Group B"],
                "valid_options": {
                    "acme_account_provider_id": {
                        i.id: "%s (%s)" % (i.name, i.url)
                        for i in self.dbAcmeAccountProviders
                    },
                    "account__private_key_cycle": model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle,
                },
            }
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_account-upload.mako",
            {"AcmeAccountProviders": self.dbAcmeAccountProviders},
            self.request,
        )

    def _upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeAccount_new__file, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            parser = AcmeAccountUploadParser(formStash)
            parser.require_upload(require_contact=None)
            # this will have `contact` and `private_key_cycle`
            key_create_args = parser.getcreate_args
            acme_account_provider_id = key_create_args.get("acme_account_provider_id")
            if acme_account_provider_id:
                self._load_AcmeAccountProviders()
                _acme_account_provider_ids__all = [
                    i.id for i in self.dbAcmeAccountProviders
                ]
                if acme_account_provider_id not in _acme_account_provider_ids__all:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="acme_account_provider_id",
                        message="Invalid provider submitted.",
                    )

            key_create_args["event_type"] = "AcmeAccount__insert"
            key_create_args[
                "acme_account_key_source_id"
            ] = model_utils.AcmeAccountKeySource.from_string("imported")
            (dbAcmeAccount, _is_created,) = lib_db.getcreate.getcreate__AcmeAccount(
                self.request.api_context, **key_create_args
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeAccount": dbAcmeAccount.as_json,
                    "is_created": True if _is_created else False,
                    "is_existing": False if _is_created else True,
                }
            return HTTPSeeOther(
                "%s/acme-account/%s?result=success&operation=upload%s"
                % (
                    self.request.admin_url,
                    dbAcmeAccount.id,
                    ("&is_created=1" if _is_created else "&is_existing=1"),
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_account:new")
    @view_config(route_name="admin:acme_account:new|json", renderer="json")
    def new(self):
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        self._load_AcmeAccountProviders()
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'account_key_file_pem=@key.pem' --form 'acme_account_provider_id=1' %s/acme-account/new.json"""
                    % self.request.admin_url,
                ],
                "form_fields": {
                    "acme_account_provider_id": "which provider",
                    "account__contact": "the contact's email address for the ACME Server",
                    "account__private_key_cycle": "how should the PrivateKey be cycled for this account?",
                },
                "notes": [""],
                "valid_options": {
                    "acme_account_provider_id": {
                        i.id: "%s (%s)" % (i.name, i.url)
                        for i in self.dbAcmeAccountProviders
                    },
                    "account__private_key_cycle": model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle,
                },
            }
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_account-new.mako",
            {"AcmeAccountProviders": self.dbAcmeAccountProviders},
            self.request,
        )

    def _new__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeAccount_new__auth, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            self._load_AcmeAccountProviders()
            _acme_account_provider_ids__all = [
                i.id for i in self.dbAcmeAccountProviders
            ]
            _acme_account_provider_ids__enabled = [
                i.id for i in self.dbAcmeAccountProviders if i.is_enabled
            ]

            acme_account_provider_id = formStash.results["acme_account_provider_id"]
            if acme_account_provider_id not in _acme_account_provider_ids__all:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="acme_account_provider_id",
                    message="Invalid provider submitted.",
                )

            if acme_account_provider_id not in _acme_account_provider_ids__enabled:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="acme_account_provider_id",
                    message="This provider is no longer enabled.",
                )

            parser = AcmeAccountUploadParser(formStash)
            parser.require_new(require_contact=True)
            # this will have `contact` and `private_key_cycle`
            key_create_args = parser.getcreate_args
            key_pem = cert_utils.new_account_key()  # bits=2048)
            key_create_args["key_pem"] = key_pem
            key_create_args["event_type"] = "AcmeAccount__create"
            key_create_args[
                "acme_account_key_source_id"
            ] = model_utils.AcmeAccountKeySource.from_string("generated")
            (dbAcmeAccount, _is_created,) = lib_db.getcreate.getcreate__AcmeAccount(
                self.request.api_context, **key_create_args
            )

            # result is either: `new-account` or `existing-account`
            # failing will raise an exception
            authenticatedUser = lib_db.actions_acme.do__AcmeAccount_AcmeV2_register(
                self.request.api_context, dbAcmeAccount
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeAccount": dbAcmeAccount.as_json,
                    "is_created": True if _is_created else False,
                    "is_existing": False if _is_created else True,
                }
            return HTTPSeeOther(
                "%s/acme-account/%s?result=success&operation=new%s"
                % (
                    self.request.admin_url,
                    dbAcmeAccount.id,
                    ("&is_created=1" if _is_created else "&is_existing=1"),
                )
            )

        except errors.AcmeServerError as exc:
            if self.request.wants_json:
                return {"result": "error", "error": exc.as_querystring}
            return HTTPSeeOther(
                "%s/acme-account/new?result=error&error=%s"
                % (self.request.admin_url, exc.as_querystring,)
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)


class View_Focus(Handler):
    def _focus(self):
        dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(
            self.request.api_context, self.request.matchdict["id"],
        )
        if not dbAcmeAccount:
            raise HTTPNotFound("the key was not found")
        self._focus_url = "%s/acme-account/%s" % (
            self.request.admin_url,
            dbAcmeAccount.id,
        )
        self.dbAcmeAccount = dbAcmeAccount
        return dbAcmeAccount

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus",
        renderer="/admin/acme_account-focus.mako",
    )
    @view_config(route_name="admin:acme_account:focus|json", renderer="json")
    def focus(self):
        dbAcmeAccount = self._focus()
        if self.request.wants_json:
            _prefix = "%s" % self._focus_url
            return {
                "AcmeAccount": dbAcmeAccount.as_json,
                "raw": {
                    "pem.txt": "%s/key.pem.txt" % _prefix,
                    "pem": "%s/key.pem" % _prefix,
                    "der": "%s/key.key" % _prefix,
                },
            }
        return {"project": "peter_sslers", "AcmeAccount": dbAcmeAccount}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_account:focus:raw", renderer="string")
    def focus_raw(self):
        dbAcmeAccount = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbAcmeAccount.acme_account_key.key_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbAcmeAccount.acme_account_key.key_pem
        elif self.request.matchdict["format"] == "key":
            self.request.response.content_type = "application/pkcs8"
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbAcmeAccount.acme_account_key.key_pem
            )
            return as_der

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_account:focus:parse|json", renderer="json")
    def focus_parse_json(self):
        dbAcmeAccount = self._focus()
        return {
            "AcmeAccount": {
                "id": dbAcmeAccount.id,
                "AcmeAccountKey": {
                    "id": dbAcmeAccount.acme_account_key.id
                    if dbAcmeAccount.acme_account_key
                    else None,
                    "parsed": cert_utils.parse_key(
                        key_pem=dbAcmeAccount.acme_account_key.key_pem
                    )
                    if dbAcmeAccount.acme_account_key
                    else None,
                },
            }
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_account:focus:config|json", renderer="json")
    def focus_config_json(self):
        dbAcmeAccount = self._focus()
        return {
            "AcmeAccount": {
                "id": dbAcmeAccount.id,
                "is_active": dbAcmeAccount.is_active,
                "is_global_default": dbAcmeAccount.is_global_default,
                "private_key_cycle": dbAcmeAccount.private_key_cycle,
            },
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_authorizations",
        renderer="/admin/acme_account-focus-acme_authorizations.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_authorizations_paginated",
        renderer="/admin/acme_account-focus-acme_authorizations.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_authorizations|json", renderer="json",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_authorizations_paginated|json",
        renderer="json",
    )
    def related__AcmeAuthorizations(self):
        dbAcmeAccount = self._focus()

        url_status = self.request.params.get("status")
        if url_status not in ("active", "active-expired"):
            url_status = ""
        if url_status == "active":
            sidenav_option = "active"
        elif url_status == "active-expired":
            sidenav_option = "active-expired"
        else:
            sidenav_option = "all"

        active_only = True if url_status == "active" else False
        expired_only = True if url_status == "active-expired" else False

        items_count = lib_db.get.get__AcmeAuthorization__by_AcmeAccountId__count(
            self.request.api_context,
            dbAcmeAccount.id,
            active_only=active_only,
            expired_only=expired_only,
        )
        url_template = "%s/acme-authorizations/{0}" % self._focus_url
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        if url_status:
            url_template = "%s?status=%s" % (url_template, url_status)

        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeAuthorization__by_AcmeAccountId__paginated(
            self.request.api_context,
            dbAcmeAccount.id,
            active_only=active_only,
            expired_only=expired_only,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _authorizations = [k.as_json for k in items_paged]
            return {
                "AcmeAuthorizations": _authorizations,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "AcmeAuthorizations_count": items_count,
            "AcmeAuthorizations": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @view_config(
        route_name="admin:acme_account:focus:acme_orders",
        renderer="/admin/acme_account-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_orders_paginated",
        renderer="/admin/acme_account-focus-acme_orders.mako",
    )
    def related__AcmeOrders(self):
        dbAcmeAccount = self._focus()
        items_count = lib_db.get.get__AcmeOrder__by_AcmeAccountId__count(
            self.request.api_context, dbAcmeAccount.id
        )
        url_template = "%s/acme-orders/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeOrder__by_AcmeAccountId__paginated(
            self.request.api_context,
            dbAcmeAccount.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:private_keys",
        renderer="/admin/acme_account-focus-private_keys.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:private_keys_paginated",
        renderer="/admin/acme_account-focus-private_keys.mako",
    )
    def related__PrivateKeys(self):
        dbAcmeAccount = self._focus()
        items_count = lib_db.get.get__PrivateKey__by_AcmeAccountIdOwner__count(
            self.request.api_context, dbAcmeAccount.id
        )
        url_template = "%s/private-keys/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__PrivateKey__by_AcmeAccountIdOwner__paginated(
            self.request.api_context,
            dbAcmeAccount.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "PrivateKeys_count": items_count,
            "PrivateKeys": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:server_certificates",
        renderer="/admin/acme_account-focus-server_certificates.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:server_certificates_paginated",
        renderer="/admin/acme_account-focus-server_certificates.mako",
    )
    def related__ServerCertificates(self):
        dbAcmeAccount = self._focus()
        items_count = lib_db.get.get__ServerCertificate__by_AcmeAccountId__count(
            self.request.api_context, dbAcmeAccount.id
        )
        url_template = "%s/server-certificates/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__ServerCertificate__by_AcmeAccountId__paginated(
            self.request.api_context,
            dbAcmeAccount.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "ServerCertificates_count": items_count,
            "ServerCertificates": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:queue_certificates",
        renderer="/admin/acme_account-focus-queue_certificates.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:queue_certificates_paginated",
        renderer="/admin/acme_account-focus-queue_certificates.mako",
    )
    def related__QueueCertificates(self):
        dbAcmeAccount = self._focus()
        items_count = lib_db.get.get__QueueCertificate__by_AcmeAccountId__count(
            self.request.api_context, dbAcmeAccount.id
        )
        url_template = "%s/queue-certificates/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__QueueCertificate__by_AcmeAccountId__paginated(
            self.request.api_context,
            dbAcmeAccount.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "QueueCertificates_count": items_count,
            "QueueCertificates": items_paged,
            "pager": pager,
        }


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:acme_account:focus:edit")
    @view_config(route_name="admin:acme_account:focus:edit|json", renderer="json")
    def focus_edit(self):
        dbAcmeAccount = self._focus()
        if self.request.method == "POST":
            return self._focus_edit__submit()
        return self._focus_edit__print()

    def _focus_edit__print(self):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'account__private_key_cycle=certificate' %s/acme-account/{ID}/edit.json"""
                    % self.request.admin_url,
                ],
                "form_fields": {
                    "account__private_key_cycle": "option for cycling the PrivateKey on renewals",
                },
                "notes": [""],
                "valid_options": {
                    "account__private_key_cycle": model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle,
                },
            }
        return render_to_response(
            "/admin/acme_account-focus-edit.mako",
            {"AcmeAccount": self.dbAcmeAccount},
            self.request,
        )

    def _focus_edit__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeAccount_edit, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            event_type = model_utils.OperationsEventType.from_string(
                "AcmeAccount__edit"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_account_id"] = self.dbAcmeAccount.id
            event_payload_dict["action"] = "edit"
            event_payload_dict["edit"] = {
                "old": {"private_key_cycle": self.dbAcmeAccount.private_key_cycle},
                "new": {"private_key_cycle": self.dbAcmeAccount.private_key_cycle},
            }

            try:
                event_status = lib_db.update.update_AcmeAccount__private_key_cycle(
                    self.request.api_context,
                    self.dbAcmeAccount,
                    formStash.results["account__private_key_cycle"],
                )
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
                dbAcmeAccount=self.dbAcmeAccount,
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeAccount": self.dbAcmeAccount.as_json,
                }
            url_success = "%s?result=success&operation=edit" % (self._focus_url,)
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus_edit__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_server:authenticate", renderer=None,
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_server:authenticate|json",
        renderer="json",
    )
    def focus__acme_server_authenticate(self):
        """
        this just hits the api, hoping we authenticate correctly.
        """
        dbAcmeAccount = self._focus()
        if not dbAcmeAccount.is_can_authenticate:
            error_message = "This AcmeAccount can not Authenticate"
            if self.request.wants_json:
                return {
                    "error": error_message,
                }
            url_error = (
                "%s?result=error&error=%s&operation=acme-server--authenticate"
                % (self._focus_url, error_message.replace(" ", "+"),)
            )
            return HTTPSeeOther(url_error)
        if self.request.method == "POST":
            return self._focus__authenticate__submit(dbAcmeAccount)
        return self._focus__authenticate__print(dbAcmeAccount)

    def _focus__authenticate__print(self, dbAcmeAccount):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl -X POST %s/acme-server/authenticate.json"""
                    % self._focus_url
                ]
            }
        url_post_required = (
            "%s?result=error&error=post+required&operation=acme-server--authenticate"
            % (self._focus_url,)
        )
        return HTTPSeeOther(url_post_required)

    def _focus__authenticate__submit(self, dbAcmeAccount):
        # result is either: `new-account` or `existing-account`
        # failing will raise an exception
        authenticatedUser = lib_db.actions_acme.do__AcmeAccount_AcmeV2_authenticate(
            self.request.api_context, dbAcmeAccount
        )
        if self.request.wants_json:
            return {"AcmeAccount": dbAcmeAccount.as_json}
        return HTTPSeeOther(
            "%s?result=success&operation=acme-server--authenticate&is_authenticated=%s"
            % (self._focus_url, True)
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_account:focus:mark", renderer=None)
    @view_config(route_name="admin:acme_account:focus:mark|json", renderer="json")
    def focus_mark(self):
        dbAcmeAccount = self._focus()
        if self.request.method == "POST":
            return self._focus_mark__submit(dbAcmeAccount)
        return self._focus_mark__print(dbAcmeAccount)

    def _focus_mark__print(self, dbAcmeAccount):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'action=active' %s/mark.json""" % self._focus_url
                ],
                "form_fields": {"action": "the intended action"},
                "valid_options": {"action": ["global_default", "active", "inactive"]},
            }
        url_post_required = "%s?result=error&error=post+required&operation=mark" % (
            self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self, dbAcmeAccount):
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeAccount_mark,
                validate_get=False,
                # validate_post=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string(
                "AcmeAccount__mark"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_account_id"] = dbAcmeAccount.id
            event_payload_dict["action"] = formStash.results["action"]

            event_status = False
            event_alt = None

            try:
                if action == "active":
                    event_status = lib_db.update.update_AcmeAccount__set_active(
                        self.request.api_context, dbAcmeAccount
                    )

                elif action == "inactive":
                    event_status = lib_db.update.update_AcmeAccount__unset_active(
                        self.request.api_context, dbAcmeAccount
                    )

                elif action == "global_default":
                    (
                        event_status,
                        alt_info,
                    ) = lib_db.update.update_AcmeAccount__set_global_default(
                        self.request.api_context, dbAcmeAccount
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

            self.request.api_context.dbSession.flush(objects=[dbAcmeAccount])

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
                dbAcmeAccount=dbAcmeAccount,
            )
            if event_alt:
                lib_db.logger._log_object_event(
                    self.request.api_context,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                        event_alt[0]
                    ),
                    dbAcmeAccount=event_alt[1],
                )
            if self.request.wants_json:
                return {"result": "success", "AcmeAccount": dbAcmeAccount.as_json}
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

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_server:deactivate_pending_authorizations",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_server:deactivate_pending_authorizations|json",
        renderer="json",
    )
    def focus__acme_server_deactivate_pending_authorizations(self):
        """
        this just hits the api, hoping we authenticate correctly.
        """
        dbAcmeAccount = self._focus()
        if not dbAcmeAccount.is_can_authenticate:
            error_message = "This AcmeAccount can not Authenticate"
            if self.request.wants_json:
                return {
                    "error": error_message,
                }
            url_error = (
                "%s?result=error&error=%s&operation=acme-server--deactivate-pending-authorizations"
                % (self._focus_url, error_message.replace(" ", "+"),)
            )
            return HTTPSeeOther(url_error)
        if self.request.method == "POST":
            return self._focus__acme_server_deactivate_pending_authorizations__submit(
                dbAcmeAccount
            )
        return self._focus__acme_server_deactivate_pending_authorizations__print(
            dbAcmeAccount
        )

    def _focus__acme_server_deactivate_pending_authorizations__print(
        self, dbAcmeAccount
    ):
        if self.request.wants_json:
            return {
                "form_fields": {
                    "authorization_id": "the pending authorization id to delete ",
                },
                "instructions": [
                    """curl -X POST %s/acme-server/deactivate-pending-authorizations.json"""
                    % self._focus_url
                ],
            }
        url_post_required = (
            "%s/acme-authorizations?status=active&result=error&error=post+required&operation=acme-server--deactivate-pending-authorizations"
            % (self._focus_url,)
        )
        return HTTPSeeOther(url_post_required)

    def _focus__acme_server_deactivate_pending_authorizations__submit(
        self, dbAcmeAccount
    ):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeAccount_deactivate_authorizations,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            if not formStash.results["acme_authorization_id"]:
                # `formStash.fatal_form()` will raise `FormInvalid()`
                formStash.fatal_form(
                    "You must supply at least one `acme_authorization_id` to deactivate."
                )

            dbAcmeAccount = self._focus()
            results = lib_db.actions_acme.do__AcmeV2_AcmeAccount__acme_server_deactivate_authorizations(
                self.request.api_context,
                dbAcmeAccount=dbAcmeAccount,
                acme_authorization_ids=formStash.results["acme_authorization_id"],
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "results": results,
                    "AcmeAccount": dbAcmeAccount.as_json,
                }

            return HTTPSeeOther(
                "%s/acme-authorizations?status=active&result=success&operation=acme-server--deactivate-pending-authorizations"
                % (self._focus_url,)
            )
        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return HTTPSeeOther(
                "%s/acme-authorizations?status=active&result=error&error=%s&operation=acme-server--deactivate-pending-authorizations"
                % (self._focus_url, errors.formstash_to_querystring(formStash),)
            )
