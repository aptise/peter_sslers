# stlib
import logging
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from urllib.parse import quote_plus

# pypi
import cert_utils
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config
from typing_extensions import Literal

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.form_utils import AcmeAccountUploadParser
from ..lib.forms import Form_AcmeAccount_deactivate
from ..lib.forms import Form_AcmeAccount_deactivate_authorizations
from ..lib.forms import Form_AcmeAccount_edit
from ..lib.forms import Form_AcmeAccount_key_change
from ..lib.forms import Form_AcmeAccount_mark
from ..lib.forms import Form_AcmeAccount_new__auth
from ..lib.forms import Form_AcmeAccount_new__upload
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils
from ...model.objects import AcmeAccount

if TYPE_CHECKING:
    from pyramid.request import Request

# ==============================================================================


log = logging.getLogger("peter_sslers.web")


def submit__new_auth(
    request: "Request",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeAccount, bool]:
    """
    note: this function will commit the transaction on success
    """
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    (result, formStash) = formhandling.form_validate(
        request,
        schema=Form_AcmeAccount_new__auth,
        validate_get=False,
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    parser = AcmeAccountUploadParser(formStash)
    parser.require_new(require_contact=None)
    acme_server_id = parser.validate_acme_server(request.api_context)  # noqa; F841
    key_create_args = parser.generate_create_args()

    dbAcmeAccount = None
    _dbAcmeAccount = None
    try:
        (
            _dbAcmeAccount,
            _is_created,
        ) = lib_db.getcreate.getcreate__AcmeAccount(
            request.api_context, **key_create_args
        )

        # result is either: `new-account` or `existing-account`
        # failing will raise an exception
        authenticatedUser = (  # noqa: F841
            lib_db.actions_acme.do__AcmeV2_AcmeAccount_register(
                request.api_context, _dbAcmeAccount, transaction_commit=True
            )
        )
        # copy this over to signify a total success
        dbAcmeAccount = _dbAcmeAccount

    except errors.ConflictingObject as exc:
        # ConflictingObject: args[0] = tuple(conflicting_object, error_message_string)
        #
        # this happens via `getcreate__AcmeAccount`
        # * args[0] = tuple(conflicting_object, error_message_string)
        # _dbAcmeAccountDuplicate = exc.args[0][0]
        formStash.fatal_field(
            field="account__contact",
            error_field=exc.args[0][1],
        )

    except errors.AcmeDuplicateAccount as exc:  # noqa: F841
        formStash.fatal_form(
            error_main="AcmeDuplicateAccount condition was detected.",
        )
        ## this happens via `do__AcmeV2_AcmeAccount_register`
        ## args[0] MUST be the duplicate AcmeAccount
        # _dbAcmeAccountDuplicate = exc.args[0]
        ## the 'Duplicate' account was the earlier account and therefore
        ## it is our merge Target
        # if TYPE_CHECKING:
        #    assert _dbAcmeAccount is not None
        # lib_db.update.update_AcmeAccount_from_new_duplicate(
        #    request.api_context, _dbAcmeAccountDuplicate, _dbAcmeAccount
        # )
        # dbAcmeAccount = _dbAcmeAccountDuplicate

    except errors.AcmeServerError as exc:
        # (status_code, url, resp_data, headers) = exc.args
        request.tm.abort()
        if _dbAcmeAccount and not dbAcmeAccount:
            # we've created an AcmeAccount locally but not on the server
            # right now, this will persist to the DB ( which causes issues)
            # unless we raise an exception or set an error
            message = "Can not validate on upstream ACME Server."
            if exc.args[0] == 400:
                if isinstance(exc.args[2], dict):
                    if (
                        exc.args[2].get("type")
                        == "urn:ietf:params:acme:error:unsupportedContact"
                    ):
                        message += " Server says `urn:ietf:params:acme:error:unsupportedContact`"
                        _detail = exc.args[2].get("detail")
                        if _detail:
                            message += " " + _detail
                        if message[-1] != ".":
                            message += "."
            formStash.set_error(
                field=formStash.error_main_key,
                message=message,
            )
        else:
            formStash.set_error(
                field=formStash.error_main_key,
                message=str(exc.args[2]),
            )
        raise formhandling.FormInvalid(formStash)

    if TYPE_CHECKING:
        assert dbAcmeAccount is not None

    return (dbAcmeAccount, _is_created)


def submit__authenticate(
    request: "Request",
    dbAcmeAccount: "AcmeAccount",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    `Authenticate` will invoke `newAccount` with `onlyReturnExisting=False`

    `onlyReturnExisting=False` will register a NEW user if applicable

    returns (success:bool, error_message:Optional[str])
    """
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    try:
        if not dbAcmeAccount.is_can_authenticate:
            return False, "This AcmeAccount can not Authenticate"
        # result is either: `new-account` or `existing-account`
        # failing will raise an exception
        authenticatedUser = (  # noqa: F841
            lib_db.actions_acme.do__AcmeV2_AcmeAccount__authenticate(
                request.api_context,
                dbAcmeAccount,
                onlyReturnExisting=False,
                transaction_commit=True,
            )
        )
        return True, None
    except errors.AcmeDuplicateAccount as exc:  # noqa: F841
        return False, "AcmeDuplicateAccount detected"
    except errors.AcmeServerError as exc:
        # (status_code, url, resp_data, headers) = exc.args
        log.critical(exc)
        return False, "AcmeServerError"
    except Exception as exc:
        log.critical(exc)
        return False, "General Error"


def submit__check(
    request: "Request",
    dbAcmeAccount: "AcmeAccount",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    `Authenticate` will invoke `newAccount` with `onlyReturnExisting=True`

    `onlyReturnExisting=True` requires an EXISTING user

    returns (success:bool, error_message:Optional[str])
    """
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    try:
        if not dbAcmeAccount.is_can_authenticate:
            return False, "This AcmeAccount can not Check"
        # result is either: `existing-account` or ERROR
        # failing will raise an exception
        # passing in `onlyReturnExisting` will log the "check"
        checkedUser = (  # noqa: F841
            lib_db.actions_acme.do__AcmeV2_AcmeAccount__authenticate(
                request.api_context,
                dbAcmeAccount,
                onlyReturnExisting=True,
                transaction_commit=True,
            )
        )
        return True, None
    except errors.AcmeDuplicateAccount as exc:  # noqa: F841
        return False, "AcmeDuplicateAccount detected"
    except errors.AcmeServerError as exc:
        # (status_code, url, resp_data, headers) = exc.args
        log.critical(exc)
        # only catch this if `onlyReturnExisting` and there is an DNE error
        if (exc.args[0] == 400) and (
            exc.args[2]["type"] == "urn:ietf:params:acme:error:accountDoesNotExist"
        ):
            if "detail" in exc.args[2]:
                return False, exc.args[2]["detail"]
        return False, "AcmeServerError"
    except Exception as exc:
        log.critical(exc)
        return False, "General Error"


class View_List(Handler):
    @view_config(route_name="admin:acme_accounts", renderer="/admin/acme_accounts.mako")
    @view_config(
        route_name="admin:acme_accounts-paginated",
        renderer="/admin/acme_accounts.mako",
    )
    @view_config(route_name="admin:acme_accounts|json", renderer="json")
    @view_config(route_name="admin:acme_accounts-paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-accounts.json",
            "section": "acme-account",
            "about": """list AcmeAccount(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-accounts.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-accounts/{PAGE}.json",
            "section": "acme-account",
            "example": "curl {ADMIN_PREFIX}/acme-accounts/1.json",
            "variant_of": "/acme-accounts.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__AcmeAccount__count(self.request.api_context)
        url_template = (
            "%s/acme-accounts/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeAccount__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _accounts = {k.id: k.as_json for k in items_paged}
            rval = {
                "AcmeAccounts": _accounts,
                "pagination": json_pagination(items_count, pager),
            }
            if pager._current == 1:
                rval["SystemConfiguration_global"] = (
                    self.request.api_context.dbSystemConfiguration_global.as_json
                )
            return rval
        return {
            "project": "peter_sslers",
            "AcmeAccounts_count": items_count,
            "AcmeAccounts": items_paged,
            "pager": pager,
            "SystemConfiguration_global": self.request.api_context.dbSystemConfiguration_global,
        }


class View_New(Handler):
    @view_config(route_name="admin:acme_account:upload")
    @view_config(route_name="admin:acme_account:upload|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-account/upload.json",
            "section": "acme-account",
            "about": """upload an AcmeAccount and AcmeAccountKey""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-account/upload.json",
            "examples": [
                "curl "
                "--form 'account__order_default_private_key_cycle=single_use' "
                "--form 'account__order_default_private_key_technology=EC_P256' "
                "--form 'account__order_default_acme_profile=tlsserver' "
                "--form 'acme_server_id=1' "
                "--form 'account_key_file_pem=@key.pem' "
                "--form 'account__contact=a@example.com' "
                "{ADMIN_PREFIX}/acme-account/upload.json",
                "curl "
                "--form 'account__order_default_private_key_cycle=single_use' "
                "--form 'account__order_default_private_key_technology=EC_P256' "
                "--form 'account_key_file_le_meta=@meta.json' "
                "--form 'account_key_file_le_pkey=@private_key.json' "
                "--form 'account_key_file_le_reg=@regr.json' "
                "{ADMIN_PREFIX}/acme-account/upload.json",
            ],
            "form_fields": {
                "account_key_file_pem": "Group A",
                "acme_server_id": "Group A",
                "account_key_file_le_meta": "Group B",
                "account_key_file_le_pkey": "Group B",
                "account_key_file_le_reg": "Group B",
                "account__contact": "the contact's email address for the ACME Server",
                "account__order_default_private_key_cycle": "what should orders default to?",
                "account__order_default_private_key_technology": "what should orders default to?",
                "account__order_default_acme_profile": "what acme profile to use?",
            },
            "notes": [
                "You must submit ALL items from Group A or Group B",
            ],
            "valid_options": {
                "acme_server_id": "{RENDER_ON_REQUEST}",
                "account__order_default_private_key_cycle": Form_AcmeAccount_new__upload.fields[
                    "account__order_default_private_key_cycle"
                ].list,
                "account__order_default_private_key_technology": Form_AcmeAccount_new__upload.fields[
                    "account__order_default_private_key_technology"
                ].list,
            },
        }
    )
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-account/upload.json")
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_account-upload.mako",
            {"AcmeServers": self.request.api_context.dbAcmeServers},
            self.request,
        )

    def _upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeAccount_new__upload, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            parser = AcmeAccountUploadParser(formStash)
            parser.require_upload(require_contact=None, require_technology=False)

            key_create_args = parser.getcreate_args
            for _field in (
                "contact",
                "order_default_private_key_cycle_id",
                "order_default_private_key_technology_id",
                "order_default_acme_profile",
            ):
                assert _field in key_create_args

            # not required if uploading LE json fields
            acme_server_id = key_create_args.get("acme_server_id")
            if acme_server_id:
                _acme_server_ids__all = [
                    i.id for i in self.request.api_context.dbAcmeServers
                ]
                if acme_server_id not in _acme_server_ids__all:
                    formStash.fatal_field(
                        field="acme_server_id",
                        error_field="Invalid provider submitted.",
                    )

            key_create_args["event_type"] = "AcmeAccount__insert"
            key_create_args["acme_account_key_source_id"] = (
                model_utils.AcmeAccountKeySource.IMPORTED
            )
            dbAcmeAccount = None
            _dbAcmeAccount = None
            try:
                (
                    _dbAcmeAccount,
                    _is_created,
                ) = lib_db.getcreate.getcreate__AcmeAccount(
                    self.request.api_context, **key_create_args
                )

                # result is either: `new-account` or `existing-account`
                # failing will raise an exception
                authenticatedUser = (  # noqa: F841
                    lib_db.actions_acme.do__AcmeV2_AcmeAccount_register(
                        self.request.api_context,
                        _dbAcmeAccount,
                        transaction_commit=True,
                    )
                )

                # copy this over to signify a total success
                dbAcmeAccount = _dbAcmeAccount

            except errors.ConflictingObject as exc:
                # ConflictingObject: args[0] = tuple(conflicting_object, error_message_string)
                #
                # this happens via `getcreate__AcmeAccount`
                # * args[0] = tuple(conflicting_object, error_message_string)
                # _dbAcmeAccountDuplicate = exc.args[0][0]
                formStash.fatal_form(
                    error_main=exc.args[0][1],
                )
            except errors.AcmeDuplicateAccount as exc:  # noqa: F841
                formStash.fatal_form(
                    error_main="AcmeDuplicateAccount condition was detected.",
                )

            if TYPE_CHECKING:
                assert dbAcmeAccount

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

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_account:new")
    @view_config(route_name="admin:acme_account:new|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-account/new.json",
            "section": "acme-account",
            "about": """Create a new AcmeAccount""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-account/new.json",
            "examples": [
                """curl """
                """--form 'acme_server_id=1' """
                """--form 'account__contact=a@example.com' """
                """--form 'account__private_key_technology=ECP256' """
                """--form 'account__order_default_private_key_cycle=single_use' """
                """--form 'account__order_default_private_key_technology=EC_P256' """
                """--form 'account__order_default_acme_profile=tlsserver' """
                """{ADMIN_PREFIX}/acme-account/new.json""",
            ],
            "form_fields": {
                "acme_server_id": "which provider",
                "account__contact": "the contact's email address for the ACME Server",
                "account__private_key_technology": "what is the key technology preference for this account?",
                "account__order_default_private_key_cycle": "what should orders default to?",
                "account__order_default_private_key_technology": "what should orders default to?",
                "account__order_default_acme_server": "default profile?",
            },
            "valid_options": {
                "acme_server_id": "{RENDER_ON_REQUEST}",
                "account__private_key_technology": Form_AcmeAccount_new__auth.fields[
                    "account__private_key_technology"
                ].list,
                "account__order_default_private_key_cycle": Form_AcmeAccount_new__auth.fields[
                    "account__order_default_private_key_cycle"
                ].list,
                "account__order_default_private_key_technology": Form_AcmeAccount_new__auth.fields[
                    "account__order_default_private_key_technology"
                ].list,
            },
        }
    )
    def new(self):
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-account/new.json")
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_account-new.mako",
            {"AcmeServers": self.request.api_context.dbAcmeServers},
            self.request,
        )

    def _new__submit(self):
        try:
            (dbAcmeAccount, _is_created) = submit__new_auth(
                self.request,
                acknowledge_transaction_commits=True,
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

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": exc.formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)


class View_Focus(Handler):
    dbAcmeAccount: Optional[AcmeAccount] = None

    def _focus(self) -> AcmeAccount:
        if self.dbAcmeAccount is None:
            dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbAcmeAccount:
                raise HTTPNotFound("the key was not found")
            self.dbAcmeAccount = dbAcmeAccount
            self._focus_url = "%s/acme-account/%s" % (
                self.request.admin_url,
                self.dbAcmeAccount.id,
            )
        return self.dbAcmeAccount

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus",
        renderer="/admin/acme_account-focus.mako",
    )
    @view_config(route_name="admin:acme_account:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-account/{ID}.json",
            "section": "acme-account",
            "about": """AcmeAccount record""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1.json",
        }
    )
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
    @docify(
        {
            "endpoint": "/acme-account/{ID}/key.pem",
            "section": "acme-account",
            "about": """AcmeAccount focus. Active key as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1/key.pem",
        }
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/key.pem.txt",
            "section": "acme-account",
            "about": """AcmeAccount focus. Active key as PEM.txt""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1/key.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/key.key",
            "section": "acme-account",
            "about": """AcmeAccount focus. Active key as pkcs8 (DER)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1/key.key",
        }
    )
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
    @docify(
        {
            "endpoint": "/acme-account/{ID}/parse.json",
            "section": "acme-account",
            "about": """AcmeAccount focus. Active key, parsed""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1/parse.json",
        }
    )
    def focus_parse_json(self):
        dbAcmeAccount = self._focus()
        return {
            "AcmeAccount": dbAcmeAccount.as_json,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_authorizations",
        renderer="/admin/acme_account-focus-acme_authorizations.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_authorizations-paginated",
        renderer="/admin/acme_account-focus-acme_authorizations.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_authorizations|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_authorizations-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-authorizations.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. list AcmeAuthorizations(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1/acme-authorizations.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-authorizations/{PAGE}.json",
            "section": "acme-account",
            "example": "curl {ADMIN_PREFIX}/acme-account/1/acme-authorizations/1.json",
            "variant_of": "/acme-account/{ID}/acme-authorizations.json",
        }
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
            "sidenav_option": sidenav_option,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_account_keys",
        renderer="/admin/acme_account-focus-acme_account_keys.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_account_keys-paginated",
        renderer="/admin/acme_account-focus-acme_account_keys.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_account_keys|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_account_keys-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-account-keys.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. list AcmeAccountKeys(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1/acme-account-keys.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-account-keys/{PAGE}.json",
            "section": "acme-account",
            "example": "curl {ADMIN_PREFIX}/acme-account/1/acme-account-keys/1.json",
            "variant_of": "/acme-account/{ID}/acme-account-keys.json",
        }
    )
    def related__AcmeAccountKeys(self):
        dbAcmeAccount = self._focus()
        items_count = lib_db.get.get__AcmeAccountKey__by_AcmeAccountId__count(
            self.request.api_context,
            dbAcmeAccount.id,
        )
        url_template = "%s/acme-account-keys/{0}" % self._focus_url
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeAccountKey__by_AcmeAccountId__paginated(
            self.request.api_context,
            dbAcmeAccount.id,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _acme_account_keys = [k.as_json for k in items_paged]
            return {
                "AcmeAccountKeys": _acme_account_keys,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "AcmeAccountKeys_count": items_count,
            "AcmeAccountKeys": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_orders",
        renderer="/admin/acme_account-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_orders-paginated",
        renderer="/admin/acme_account-focus-acme_orders.mako",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-orders.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. list AcmeOrder(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1/acme-orders.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-orders/{PAGE}.json",
            "section": "acme-account",
            "example": "curl {ADMIN_PREFIX}/acme-account/1/acme-orders/1.json",
            "variant_of": "/acme-account/{ID}/acme-orders.json",
        }
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
        route_name="admin:acme_account:focus:private_keys-paginated",
        renderer="/admin/acme_account-focus-private_keys.mako",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/private-keys.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. list PrivateKeys(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-account/1/private-keys.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/private-keys/{PAGE}.json",
            "section": "acme-account",
            "example": "curl {ADMIN_PREFIX}/acme-account/1/private-keys/1.json",
            "variant_of": "/acme-account/{ID}/private-keys.json",
        }
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
        route_name="admin:acme_account:focus:certificate_signeds",
        renderer="/admin/acme_account-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:certificate_signeds-paginated",
        renderer="/admin/acme_account-focus-certificate_signeds.mako",
    )
    def related__CertificateSigneds(self):
        dbAcmeAccount = self._focus()
        items_count = lib_db.get.get__CertificateSigned__by_AcmeAccountId__count(
            self.request.api_context, dbAcmeAccount.id
        )
        url_template = "%s/certificate-signeds/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateSigned__by_AcmeAccountId__paginated(
            self.request.api_context,
            dbAcmeAccount.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:renewal_configurations",
        renderer="/admin/acme_account-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:renewal_configurations-paginated",
        renderer="/admin/acme_account-focus-renewal_configurations.mako",
    )
    def related__RenewalConfigurations(self):
        dbAcmeAccount = self._focus()
        items_count = lib_db.get.get__RenewalConfigurations__by_AcmeAccountId__count(
            self.request.api_context, dbAcmeAccount.id
        )
        url_template = "%s/renewal-configurations/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__RenewalConfigurations__by_AcmeAccountId__paginated(
                self.request.api_context,
                dbAcmeAccount.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "RenewalConfigurations_count": items_count,
            "RenewalConfigurations": items_paged,
            "RENEWAL_CONTEXT": "Primary",
            "pager": pager,
        }

    @view_config(
        route_name="admin:acme_account:focus:renewal_configurations_backup",
        renderer="/admin/acme_account-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:renewal_configurations_backup-paginated",
        renderer="/admin/acme_account-focus-renewal_configurations.mako",
    )
    def related__RenewalConfigurations_backup(self):
        dbAcmeAccount = self._focus()
        items_count = (
            lib_db.get.get__RenewalConfigurations__by_AcmeAccountIdBackup__count(
                self.request.api_context, dbAcmeAccount.id
            )
        )
        url_template = "%s/renewal-configurations-backup/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__RenewalConfigurations__by_AcmeAccountIdBackup__paginated(
                self.request.api_context,
                dbAcmeAccount.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "RenewalConfigurations_count": items_count,
            "RenewalConfigurations": items_paged,
            "RENEWAL_CONTEXT": "Backup",
            "pager": pager,
        }

    @view_config(
        route_name="admin:acme_account:focus:terms_of_service",
        renderer="/admin/acme_account-focus-terms_of_service.mako",
    )
    @view_config(
        route_name="admin:acme_account:focus:terms_of_service-paginated",
        renderer="/admin/acme_account-focus-terms_of_service.mako",
    )
    def related__TermsOfService(self):
        dbAcmeAccount = self._focus()
        items_count = lib_db.get.get__TermsOfService__by_AcmeAccountId__count(
            self.request.api_context, dbAcmeAccount.id
        )
        url_template = "%s/terms-of-service/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__TermsOfService__by_AcmeAccountId__paginated(
            self.request.api_context,
            dbAcmeAccount.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeAccount": dbAcmeAccount,
            "TermsOfService_count": items_count,
            "TermsOfService": items_paged,
            "pager": pager,
        }


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:acme_account:focus:edit")
    @view_config(route_name="admin:acme_account:focus:edit|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-account/{ID}/edit.json",
            "section": "acme-account",
            "about": """AcmeAccount: Edit""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-account/1/edit.json",
            "examples": [
                """curl"""
                """ --form 'account__private_key_technology=rsa'"""
                """ {ADMIN_PREFIX}/acme-account/{ID}/edit.json""",
            ],
            "form_fields": {
                "account__private_key_technology": "what is the key technology preference for this account?",
                "name": "A label for the account",
                "account__order_default_private_key_cycle": "Default private key cycle for orders",
                "account__order_default_private_key_technology": "Default private key technology for orders",
                "account__order_default_acme_profile": "Default acme profile for orders",
            },
            "valid_options": {
                "account__private_key_technology": Form_AcmeAccount_edit.fields[
                    "account__private_key_technology"
                ].list,
                "account__order_default_private_key_cycle": Form_AcmeAccount_edit.fields[
                    "account__order_default_private_key_cycle"
                ].list,
                "account__order_default_private_key_technology": Form_AcmeAccount_edit.fields[
                    "account__order_default_private_key_technology"
                ].list,
            },
        }
    )
    def focus_edit(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._focus_edit__submit()
        return self._focus_edit__print()

    def _focus_edit__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-account/{ID}/edit.json")
        return render_to_response(
            "/admin/acme_account-focus-edit.mako",
            {"AcmeAccount": self.dbAcmeAccount},
            self.request,
        )

    def _focus_edit__submit(self):
        try:
            if TYPE_CHECKING:
                assert self.dbAcmeAccount is not None
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeAccount_edit, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            event_type = model_utils.OperationsEventType.from_string(
                "AcmeAccount__edit"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_account_id"] = self.dbAcmeAccount.id
            event_payload_dict["action"] = "edit"
            event_payload_dict["edit"] = {
                "old": {},
                "new": {},
            }

            # raise an exception if there are no changes
            _edits: List[str] = []

            # !!!: edit: private_key_technology
            name = formStash.results["name"] or None
            name = utils.normalize_unique_text(name) if name else None
            if name != self.dbAcmeAccount.name:
                try:
                    event_payload_dict["edit"]["old"]["name"] = self.dbAcmeAccount.name
                    event_payload_dict["edit"]["new"]["name"] = name
                    event_status = lib_db.update.update_AcmeAccount__name(
                        self.request.api_context,
                        self.dbAcmeAccount,
                        name,
                    )
                    _edits.append(event_status)
                except errors.InvalidTransition as exc:
                    formStash.fatal_form(error_main=exc.args[0])

            # !!!: edit: private_key_technology
            private_key_technology = formStash.results[
                "account__private_key_technology"
            ]
            if private_key_technology != self.dbAcmeAccount.private_key_technology:
                try:
                    event_payload_dict["edit"]["old"][
                        "private_key_technology"
                    ] = self.dbAcmeAccount.private_key_technology
                    event_payload_dict["edit"]["new"][
                        "private_key_technology"
                    ] = private_key_technology
                    event_status = (
                        lib_db.update.update_AcmeAccount__private_key_technology(
                            self.request.api_context,
                            self.dbAcmeAccount,
                            private_key_technology,
                        )
                    )
                    _edits.append(event_status)
                except errors.InvalidTransition as exc:
                    formStash.fatal_form(error_main=exc.args[0])

            # !!!: edit: order_default_private_key_cycle
            # !!!: edit: order_default_private_key_technology
            order_default_private_key_cycle = formStash.results[
                "account__order_default_private_key_cycle"
            ]
            order_default_private_key_technology = formStash.results[
                "account__order_default_private_key_technology"
            ]
            order_default_acme_profile = formStash.results[
                "account__order_default_acme_profile"
            ]
            if order_default_acme_profile == "":
                order_default_acme_profile = None
            if (
                (
                    order_default_private_key_cycle
                    != self.dbAcmeAccount.order_default_private_key_cycle
                )
                or (
                    order_default_private_key_technology
                    != self.dbAcmeAccount.order_default_private_key_technology
                )
                or (
                    order_default_acme_profile
                    != self.dbAcmeAccount.order_default_acme_profile
                )
            ):
                if (
                    order_default_private_key_cycle
                    != self.dbAcmeAccount.order_default_private_key_cycle
                ):
                    event_payload_dict["edit"]["old"][
                        "order_default_private_key_cycle"
                    ] = self.dbAcmeAccount.order_default_private_key_cycle
                    event_payload_dict["edit"]["new"][
                        "order_default_private_key_cycle"
                    ] = order_default_private_key_cycle
                if (
                    order_default_private_key_technology
                    != self.dbAcmeAccount.order_default_private_key_technology
                ):
                    event_payload_dict["edit"]["old"][
                        "order_default_private_key_technology"
                    ] = self.dbAcmeAccount.order_default_private_key_technology
                    event_payload_dict["edit"]["new"][
                        "order_default_private_key_technology"
                    ] = order_default_private_key_technology
                if (
                    order_default_acme_profile
                    != self.dbAcmeAccount.order_default_acme_profile
                ):
                    event_payload_dict["edit"]["old"][
                        "order_default_acme_profile"
                    ] = self.dbAcmeAccount.order_default_acme_profile
                    event_payload_dict["edit"]["new"][
                        "order_default_acme_profile"
                    ] = order_default_acme_profile
                try:
                    event_status = lib_db.update.update_AcmeAccount__order_defaults(
                        self.request.api_context,
                        self.dbAcmeAccount,
                        order_default_private_key_cycle,
                        order_default_private_key_technology,
                        order_default_acme_profile,
                    )
                    _edits.append(event_status)
                except errors.InvalidTransition as exc:
                    formStash.fatal_form(error_main=exc.args[0])

            if not len(_edits):
                formStash.fatal_form(error_main="No edits submitted.")

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

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus_edit__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _handle_potentially_deactivated(self, exc:errors.AcmeServerError):
        # exc:errors.AcmeServerError
        # (status_code, url, resp_data, headers) = exc.args
        if TYPE_CHECKING:
            assert self.dbAcmeAccount is not None
        if exc.args[0] == 403:
            if isinstance(exc.args[2], dict):
                info = exc.args[2]
                # pebble and bounder use the same strings
                if info.get("type") == "urn:ietf:params:acme:error:unauthorized":
                    if (
                        info.get("detail")
                        == "An account with the provided public key exists but is deactivated"
                    ):
                        if not self.dbAcmeAccount.timestamp_deactivated:
                            lib_db.update.update_AcmeAccount__set_deactivated(
                                self.request.api_context, self.dbAcmeAccount
                            )
                            self.request.api_context.dbSession.flush(
                                objects=[self.dbAcmeAccount]
                            )
                        return True
        return False

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_server:authenticate",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_server:authenticate|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-server/authenticate.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. ACME Server - Authenticate""",
            "summary": """Authenticate the key against the provider's new-reg endpoint""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-account/{ID}/acme-server/authenticate.json",
            "example": """curl -X POST """
            """{ADMIN_PREFIX}/acme-account/{ID}/acme-server/authenticate.json""",
        }
    )
    def focus__acme_server_authenticate(self):
        """
        Hits the ACME Server newAccount API with `onlyReturnExisting=False`
        This will register if the account does not exist.
        """
        dbAcmeAccount = self._focus()
        _message: Optional[str] = None
        if not dbAcmeAccount.is_can_authenticate:
            _message = "This AcmeAccount can not Authenticate"
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": _message,
                }
            url_error = (
                "%s?result=error&error=%s&operation=acme-server--authenticate"
                % (
                    self._focus_url,
                    _message.replace(" ", "+"),
                )
            )
            return HTTPSeeOther(url_error)
        if self.request.method == "POST":
            return self._focus__authenticate__submit()
        return self._focus__authenticate__print()

    def _focus__authenticate__print(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(
                self, "/acme-account/{ID}/acme-server/authenticate.json"
            )
        url_post_required = (
            "%s?result=error&error=post+required&operation=acme-server--authenticate"
            % (self._focus_url,)
        )
        return HTTPSeeOther(url_post_required)

    def _focus__authenticate__submit(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        _result, _err = submit__authenticate(
            self.request,
            dbAcmeAccount=dbAcmeAccount,
            acknowledge_transaction_commits=True,
        )
        if _result:
            if self.request.wants_json:
                return {
                    "AcmeAccount": dbAcmeAccount.as_json,
                    "is_authenticated": True,
                    "result": "success",
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme-server--authenticate&is_authenticated=True"
                % (self._focus_url,)
            )
        if self.request.wants_json:
            return {
                "AcmeAccount": dbAcmeAccount.as_json,
                "is_authenticated": False,
                "result": "success",
                "error": _err,
            }
        # the only url-unsafe text in the errors are ascii-space chars
        if TYPE_CHECKING:
            assert _err
        return HTTPSeeOther(
            "%s?result=error&operation=acme-server--authenticate&error=%s"
            % (self._focus_url, quote_plus(_err))
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_server:check",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_server:check|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-server/check.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. ACME Server - Check""",
            "summary": """Check the key against the provider's new-reg endpoint""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-account/{ID}/acme-server/check.json",
            "example": """curl -X POST """
            """{ADMIN_PREFIX}/acme-account/{ID}/acme-server/check.json""",
        }
    )
    def focus__acme_server_check(self):
        """
        Hits the ACME Server newAccount API with `onlyReturnExisting=True`
        This will NOT register if the account does not exist.
        """
        dbAcmeAccount = self._focus()  # noqa: F841
        if not dbAcmeAccount.is_can_authenticate:
            error_message = "This AcmeAccount can not Check"
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": error_message,
                }
            url_error = "%s?result=error&error=%s&operation=acme-server--check" % (
                self._focus_url,
                error_message.replace(" ", "+"),
            )
            return HTTPSeeOther(url_error)
        if self.request.method == "POST":
            return self._focus__check__submit()
        return self._focus__check__print()

    def _focus__check__print(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-account/{ID}/acme-server/check.json")
        url_post_required = (
            "%s?result=error&error=post+required&operation=acme-server--check"
            % (self._focus_url,)
        )
        return HTTPSeeOther(url_post_required)

    def _focus__check__submit(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        _result, _err = submit__check(
            self.request,
            dbAcmeAccount=dbAcmeAccount,
            acknowledge_transaction_commits=True,
        )
        if _result:
            if self.request.wants_json:
                return {
                    "AcmeAccount": dbAcmeAccount.as_json,
                    "is_checked": True,
                    "result": "success",
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme-server--check&is_checked=True"
                % (self._focus_url,)
            )
        if self.request.wants_json:
            return {
                "AcmeAccount": dbAcmeAccount.as_json,
                "is_checked": False,
                "result": "success",
                "error": _err,
            }
        if TYPE_CHECKING:
            assert _err
        return HTTPSeeOther(
            "%s?result=error&operation=acme-server--check&error=%s"
            % (self._focus_url, quote_plus(_err))
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_account:focus:mark", renderer=None)
    @view_config(route_name="admin:acme_account:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-account/{ID}/mark.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. Mark""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-account/1/mark.json",
            "examples": [
                "curl "
                "--form 'action=active' "
                "{ADMIN_PREFIX}/acme-account/1/mark.json",
            ],
            "form_fields": {"action": "the intended action"},
            "valid_options": {
                "action": Form_AcmeAccount_mark.fields["action"].list,
            },
        }
    )
    def focus_mark(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._focus_mark__submit()
        return self._focus_mark__print()

    def _focus_mark__print(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-account/{ID}/mark.json")
        url_post_required = "%s?result=error&error=post+required&operation=mark" % (
            self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeAccount_mark,
                validate_get=False,
                # validate_post=False
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string(
                "AcmeAccount__mark"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_account_id"] = dbAcmeAccount.id
            event_payload_dict["action"] = formStash.results["action"]

            event_status: Optional[str] = None
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

                elif action == "is_render_in_selects":
                    event_status = (
                        lib_db.update.update_AcmeAccount__is_render_in_selects(
                            self.request.api_context, dbAcmeAccount, "enable"
                        )
                    )

                elif action == "no_render_in_selects":
                    event_status = (
                        lib_db.update.update_AcmeAccount__is_render_in_selects(
                            self.request.api_context, dbAcmeAccount, "disable"
                        )
                    )

                else:
                    raise errors.InvalidTransition("Invalid option")

            except errors.InvalidTransition as exc:
                formStash.fatal_form(error_main=exc.args[0])

            if TYPE_CHECKING:
                assert event_status is not None

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

    @view_config(
        route_name="admin:acme_account:focus:acme_server:deactivate_pending_authorizations",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_server:deactivate_pending_authorizations|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-server/deactivate-pending-authorizations.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. ACME Server - Deactivate Pending Authorizations""",
            "summary": """deactivate pending authorizations on the acme server, must supply the authorization_ids""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-account/1/acme-server/deactivate-pending-authorizations.json",
            "examples": [
                "curl "
                "--form 'acme_authorization_id=1' "
                "--form 'acme_authorization_id=2' "
                "{ADMIN_PREFIX}/acme-account/1/acme-server/deactivate-pending-authorizations.json",
            ],
            "form_fields": {
                "authorization_id": "the pending authorization id to delete ",
            },
        }
    )
    def focus__acme_server_deactivate_pending_authorizations(self):
        """
        this just hits the api, hoping we authenticate correctly.
        this form is available on the URL that lists all the authz for the account
        """
        dbAcmeAccount = self._focus()  # noqa: F841
        if not dbAcmeAccount.is_can_authenticate:
            error_message = "This AcmeAccount can not Authenticate"
            if self.request.wants_json:
                return {
                    "error": error_message,
                }
            url_error = (
                "%s?result=error&error=%s&operation=acme-server--deactivate-pending-authorizations"
                % (
                    self._focus_url,
                    error_message.replace(" ", "+"),
                )
            )
            return HTTPSeeOther(url_error)
        if self.request.method == "POST":
            return self._focus__acme_server_deactivate_pending_authorizations__submit()
        return self._focus__acme_server_deactivate_pending_authorizations__print()

    def _focus__acme_server_deactivate_pending_authorizations__print(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(
                self,
                "/acme-account/{ID}/acme-server/deactivate-pending-authorizations.json",
            )
        url_post_required = (
            "%s/acme-authorizations?status=active&result=error&error=post+required&operation=acme-server--deactivate-pending-authorizations"
            % (self._focus_url,)
        )
        return HTTPSeeOther(url_post_required)

    def _focus__acme_server_deactivate_pending_authorizations__submit(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        try:
            try:
                (result, formStash) = formhandling.form_validate(
                    self.request,
                    schema=Form_AcmeAccount_deactivate_authorizations,
                    validate_get=False,
                )
                if not result:
                    raise formhandling.FormInvalid(formStash)

                if not formStash.results["acme_authorization_id"]:
                    formStash.fatal_form(
                        "You must supply at least one `acme_authorization_id` to deactivate."
                    )

                results = lib_db.actions_acme.do__AcmeV2_AcmeAccount__acme_server_deactivate_authorizations(
                    self.request.api_context,
                    dbAcmeAccount=dbAcmeAccount,
                    acme_authorization_ids=formStash.results["acme_authorization_id"],
                    transaction_commit=True,
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
            except Exception as exc:
                formStash.fatal_form(error_main=str(exc))
        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return HTTPSeeOther(
                "%s/acme-authorizations?status=active&result=error&error=%s&operation=acme-server--deactivate-pending-authorizations"
                % (
                    self._focus_url,
                    errors.formstash_to_querystring(formStash),
                )
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_server:deactivate",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_server:deactivate|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-server/deactivate.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. ACME Server - Deactivate""",
            "POST": True,
            "GET": None,
            "form_fields": {
                "key_pem": "the active key as md5(PEM) or PEM",
            },
            "example": """curl -X POST """
            """{ADMIN_PREFIX}/acme-account/{ID}/acme-server/deactivate.json""",
        }
    )
    def focus__acme_server_deactivate(self):
        """
        this just hits the api, hoping we authenticate correctly.
        """
        dbAcmeAccount = self._focus()  # noqa: F841
        if not dbAcmeAccount.is_can_deactivate:
            error_message = "This AcmeAccount can not be deactivated"
            if self.request.wants_json:
                return {
                    "error": error_message,
                }
            url_error = "%s?result=error&error=%s&operation=acme-server--deactivate" % (
                self._focus_url,
                error_message.replace(" ", "+"),
            )
            return HTTPSeeOther(url_error)
        if self.request.method == "POST":
            return self._focus__acme_server_deactivate__submit()
        return self._focus__acme_server_deactivate__print()

    def _focus__acme_server_deactivate__print(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(
                self, "/acme-account/{ID}/acme-server/deactivate.json"
            )
        return render_to_response(
            "/admin/acme_account-focus-deactivate.mako",
            {"AcmeAccount": dbAcmeAccount},
            self.request,
        )

    def _focus__acme_server_deactivate__submit(self):
        dbAcmeAccount = self._focus()  # noqa: F841
        try:
            try:
                (result, formStash) = formhandling.form_validate(
                    self.request,
                    schema=Form_AcmeAccount_deactivate,
                    validate_get=False,
                )
                if not result:
                    raise formhandling.FormInvalid(formStash)

                # `key_pem` can match the full or md5
                _key_pem = formStash.results["key_pem"]
                if _key_pem != dbAcmeAccount.acme_account_key.key_pem_md5:
                    _key_pem = cert_utils.cleanup_pem_text(_key_pem)
                    if _key_pem != dbAcmeAccount.acme_account_key.key_pem:
                        formStash.fatal_field(
                            field="key_pem",
                            error_field="This does not match the active account key",
                        )
                try:
                    results = lib_db.actions_acme.do__AcmeV2_AcmeAccount__deactivate(  # noqa: F841
                        self.request.api_context,
                        dbAcmeAccount=dbAcmeAccount,
                        transaction_commit=True,
                    )
                except errors.AcmeServerError as exc:
                    # (status_code, url, resp_data, headers) = exc.args
                    if self._handle_potentially_deactivated(exc):
                        formStash.fatal_form(error_main=str(exc.args[2]))
                    raise
                if self.request.wants_json:
                    return {
                        "result": "success",
                        "AcmeAccount": dbAcmeAccount.as_json,
                    }

                return HTTPSeeOther(
                    "%s?result=success&operation=acme-server--deactivate"
                    % (self._focus_url,)
                )
            except formhandling.FormInvalid:
                raise
            except Exception as exc:
                formStash.fatal_form(error_main=str(exc))
        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(
                self.request, self._focus__acme_server_deactivate__print
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_account:focus:acme_server:key_change",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_account:focus:acme_server:key_change|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-account/{ID}/acme-server/key-change.json",
            "section": "acme-account",
            "about": """AcmeAccount: Focus. ACME Server - KeyChange""",
            "POST": True,
            "GET": None,
            "examples": [
                """curl -X POST """
                """{ADMIN_PREFIX}/acme-account/{ID}/acme-server/key-change.json""",
            ],
            "form_fields": {
                "key_pem_existing": "the active key as md5(PEM) or PEM",
            },
        }
    )
    def focus__acme_server_key_change(self):
        """
        this just hits the api, hoping we authenticate correctly.
        """
        dbAcmeAccount = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._focus__acme_server_key_change__submit()
        if not dbAcmeAccount.is_can_key_change:
            error_message = "This AcmeAccount can not be key changed"
            if self.request.wants_json:
                return {
                    "error": error_message,
                }
            url_error = "%s?result=error&error=%s&operation=acme-server--key-change" % (
                self._focus_url,
                error_message.replace(" ", "+"),
            )
            return HTTPSeeOther(url_error)
        return self._focus__acme_server_key_change__print()

    def _focus__acme_server_key_change__print(self):
        dbAcmeAccount = self._focus()
        if self.request.wants_json:
            return formatted_get_docs(
                self, "/acme-account/{ID}/acme-server/key-change.json"
            )
        return render_to_response(
            "/admin/acme_account-focus-key_change.mako",
            {"AcmeAccount": dbAcmeAccount},
            self.request,
        )

    def _focus__acme_server_key_change__submit(self):
        dbAcmeAccount = self._focus()
        try:
            try:
                (result, formStash) = formhandling.form_validate(
                    self.request,
                    schema=Form_AcmeAccount_key_change,
                    validate_get=False,
                )
                if not result:
                    raise formhandling.FormInvalid(formStash)

                # `key_pem` can match the full or md5
                _key_pem_old = formStash.results["key_pem_existing"]
                if _key_pem_old != dbAcmeAccount.acme_account_key.key_pem_md5:
                    _key_pem_old = cert_utils.cleanup_pem_text(_key_pem_old)
                    if _key_pem_old != dbAcmeAccount.acme_account_key.key_pem:
                        formStash.fatal_field(
                            field="key_pem_existing",
                            error_field="This does not match the active account key",
                        )
                is_did_keychange: bool = False
                try:
                    (athdUser, is_did_keychange) = (
                        lib_db.actions_acme.do__AcmeV2_AcmeAccount__key_change(  # noqa: F841
                            self.request.api_context,
                            dbAcmeAccount=dbAcmeAccount,
                            key_pem_new=None,
                            transaction_commit=True,
                        )
                    )
                except errors.ConflictingObject as exc:
                    # args[0] = tuple(conflicting_object, error_message_string)
                    formStash.fatal_form(error_main=str(exc.args[0][1]))

                if self.request.wants_json:
                    if not is_did_keychange:
                        return {
                            "result": "success",
                            "AcmeAccount": dbAcmeAccount.as_json,
                            "note": "A key was generated, but the change did not persist on the ACMEServer",
                        }
                    return {
                        "result": "success",
                        "AcmeAccount": dbAcmeAccount.as_json,
                    }
                if not is_did_keychange:
                    return HTTPSeeOther(
                        "%s?&result=success&operation=acme-server--key-change&note=acme-server-failure"
                        % (self._focus_url,)
                    )
                return HTTPSeeOther(
                    "%s?&result=success&operation=acme-server--key-change"
                    % (self._focus_url,)
                )
            except formhandling.FormInvalid:
                raise
            except Exception as exc:
                formStash.fatal_form(error_main=str(exc))
        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(
                self.request, self._focus__acme_server_key_change__print
            )
