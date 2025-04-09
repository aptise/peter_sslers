# stdlib
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
import cert_utils
from typing_extensions import Literal

# local
from . import formhandling
from ...lib import db as lib_db
from ...model import utils as model_utils

if TYPE_CHECKING:
    from pyramid.request import Request
    from pyramid_formencode_classic import FormStash
    from ...lib.context import ApiContext
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeDnsServer
    from ...model.objects import PrivateKey
    from ...model.objects import SystemConfiguration


# ==============================================================================


def decode_args(getcreate_args: Dict) -> Dict:
    """
    support for Python2/3
    """
    for k, v in list(getcreate_args.items()):
        if isinstance(v, bytes):
            getcreate_args[k] = v.decode("utf8")
    return getcreate_args


# standardized mapping for `model_utils.DomainsChallenged` to a formStash
DOMAINS_CHALLENGED_FIELDS: Dict[str, str] = {
    "http-01": "domain_names_http01",
    "dns-01": "domain_names_dns01",
}


class AcmeAccountUploadParser(object):
    """
    An AcmeAccount may be uploaded multiple ways:
    * a single PEM file
    * an intra-associated three file triplet from a Certbot installation

    This parser operates on a validated FormEncode results object (via `pyramid_formencode_classic`)
    """

    # set in __init__
    getcreate_args: Dict
    formStash: "FormStash"

    # tracked
    acme_server_id: Optional[int] = None
    account_key_pem: Optional[str] = None
    le_meta_jsons: Optional[str] = None
    le_pkey_jsons: Optional[str] = None
    le_reg_jsons: Optional[str] = None
    private_key_technology_id: Optional[int] = None
    order_default_private_key_cycle_id: Optional[int] = None
    order_default_private_key_technology_id: Optional[int] = None
    order_default_acme_profile: Optional[str] = None

    upload_type: Optional[str] = None  # pem OR letsencrypt

    def __init__(self, formStash: "FormStash"):
        self.formStash = formStash
        self.getcreate_args = {}

    def require_new(
        self,
        require_contact: Optional[bool] = None,
        require_technology: Optional[bool] = True,
    ) -> None:
        """
        routine for creating a NEW AcmeAccount (peter_sslers generates the credentials)

        :param require_contact: ``True`` if required; ``False`` if not; ``None`` for conditional logic
        :param require_technology: ``True`` if required; ``False`` if not; ``None`` for conditional logic
        """
        formStash = self.formStash

        acme_server_id = formStash.results.get("acme_server_id", None)
        if acme_server_id is None:
            formStash.fatal_field(
                field="acme_server_id", error_field="No provider submitted."
            )

        contact = formStash.results.get("account__contact", None)
        if not contact and require_contact:
            formStash.fatal_field(
                field="account__contact",
                error_field="`account__contact` is required.",
            )

        private_key_technology_id = None
        private_key_technology = formStash.results.get(
            "account__private_key_technology", None
        )
        if private_key_technology:
            private_key_technology_id = model_utils.KeyTechnology.from_string(
                private_key_technology
            )
        if not private_key_technology_id and require_technology:
            formStash.fatal_field(
                field="account__private_key_technology",
                error_field="No PrivateKey technology submitted.",
            )

        order_default_private_key_cycle = formStash.results.get(
            "account__order_default_private_key_cycle", None
        )
        if order_default_private_key_cycle is None:
            formStash.fatal_field(
                field="account__order_default_private_key_cycle",
                error_field="No PrivateKey cycle submitted for AcmeOrder defaults.",
            )
        order_default_private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            order_default_private_key_cycle
        )

        order_default_private_key_technology = formStash.results.get(
            "account__order_default_private_key_technology", None
        )
        if order_default_private_key_technology is None:
            formStash.fatal_field(
                field="account__order_default_private_key_technology",
                error_field="No PrivateKey cycle submitted for AcmeOrder defaults.",
            )
        order_default_private_key_technology_id = model_utils.KeyTechnology.from_string(
            order_default_private_key_technology
        )

        order_default_acme_profile = formStash.results.get(
            "account__order_default_acme_profile", None
        )

        getcreate_args = {}
        self.contact = getcreate_args["contact"] = contact
        self.acme_server_id = getcreate_args["acme_server_id"] = acme_server_id
        self.private_key_technology_id = getcreate_args["private_key_technology_id"] = (
            private_key_technology_id
        )
        self.order_default_private_key_cycle_id = getcreate_args[
            "order_default_private_key_cycle_id"
        ] = order_default_private_key_cycle_id
        self.order_default_private_key_technology_id = getcreate_args[
            "order_default_private_key_technology_id"
        ] = order_default_private_key_technology_id
        self.order_default_acme_profile = getcreate_args[
            "order_default_acme_profile"
        ] = order_default_acme_profile
        self.getcreate_args = decode_args(getcreate_args)

    def require_upload(
        self,
        require_contact: Optional[bool] = None,
        require_technology: Optional[bool] = None,
    ) -> None:
        """
        routine for uploading an exiting AcmeAccount+AcmeAccountKey

        :param require_contact: ``True`` if required; ``False`` if not; ``None`` for conditional logic
        :param require_technology: ``True`` if required; ``False`` if not; ``None`` for conditional logic
        """
        formStash = self.formStash

        # -------------------
        # do a quick parse...
        requirements_either_or = (
            (
                "account_key_file_pem",
                "acme_server_id",
            ),
            (
                "account_key_file_le_meta",
                "account_key_file_le_pkey",
                "account_key_file_le_reg",
            ),
        )
        failures = []
        passes = []
        for idx, option_set in enumerate(requirements_either_or):
            option_set_results = [
                True if formStash.results[option_set_item] is not None else False
                for option_set_item in option_set
            ]
            # if we have any item, we need all of them
            if any(option_set_results):
                if not all(option_set_results):
                    failures.append(
                        "If any of %s is provided, all must be provided."
                        % str(option_set)
                    )
                else:
                    passes.append(idx)

        if (len(passes) != 1) or failures:
            formStash.fatal_form(
                "You must upload `account_key_file_pem` or all of (`account_key_file_le_meta`, `account_key_file_le_pkey`, `account_key_file_le_reg`)."
            )

        # -------------------

        # validate the provider option
        # will be None unless a pem is uploaded
        # required for PEM, ignored otherwise
        acme_server_id = formStash.results.get("acme_server_id", None)

        # require `contact` when uploading a PEM file
        if formStash.results["account_key_file_pem"] is not None:
            require_contact = True

        contact = formStash.results.get("account__contact")
        if not contact and require_contact:
            formStash.fatal_field(
                field="account__contact",
                error_field="`account__contact` is required.",
            )

        private_key_technology_id = None
        private_key_technology = formStash.results.get(
            "account__private_key_technology", None
        )
        if private_key_technology is not None:
            private_key_technology_id = model_utils.KeyTechnology.from_string(
                private_key_technology
            )
        if not private_key_technology_id and require_technology:
            formStash.fatal_field(
                field="account__private_key_technology",
                error_field="No PrivateKey technology submitted.",
            )

        order_default_private_key_cycle = formStash.results.get(
            "account__order_default_private_key_cycle", None
        )
        if order_default_private_key_cycle is None:
            formStash.fatal_field(
                field="account__order_default_private_key_cycle",
                error_field="No PrivateKey cycle submitted for AcmeOrder defaults.",
            )
        order_default_private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            order_default_private_key_cycle
        )

        order_default_private_key_technology = formStash.results.get(
            "account__order_default_private_key_technology", None
        )
        if order_default_private_key_technology is None:
            formStash.fatal_field(
                field="account__order_default_private_key_technology",
                error_field="No PrivateKey Technology submitted for AcmeOrder defaults.",
            )
        order_default_private_key_technology_id = model_utils.KeyTechnology.from_string(
            order_default_private_key_technology
        )

        order_default_acme_profile = formStash.results.get(
            "order_default_acme_profile", None
        )

        getcreate_args = {}
        self.contact = getcreate_args["contact"] = contact
        self.private_key_technology_id = getcreate_args["private_key_technology_id"] = (
            private_key_technology_id
        )
        self.order_default_private_key_cycle_id = getcreate_args[
            "order_default_private_key_cycle_id"
        ] = order_default_private_key_cycle_id
        self.order_default_private_key_technology_id = getcreate_args[
            "order_default_private_key_technology_id"
        ] = order_default_private_key_technology_id
        self.order_default_acme_profile = getcreate_args[
            "order_default_acme_profile"
        ] = order_default_acme_profile

        if formStash.results["account_key_file_pem"] is not None:
            if acme_server_id is None:
                formStash.fatal_field(
                    field="acme_server_id",
                    error_field="No provider submitted.",
                )
            self.upload_type = "pem"
            self.acme_server_id = getcreate_args["acme_server_id"] = acme_server_id
            self.account_key_pem = getcreate_args["key_pem"] = (
                formhandling.slurp_file_field(formStash, "account_key_file_pem")
            )
        else:
            # note that we use `jsonS` to indicate a string
            self.le_meta_jsons = getcreate_args["le_meta_jsons"] = (
                formhandling.slurp_file_field(formStash, "account_key_file_le_meta")
            )
            self.le_pkey_jsons = getcreate_args["le_pkey_jsons"] = (
                formhandling.slurp_file_field(formStash, "account_key_file_le_pkey")
            )
            self.le_reg_jsons = getcreate_args["le_reg_jsons"] = (
                formhandling.slurp_file_field(formStash, "account_key_file_le_reg")
            )

        # okay some more sanity checks...
        if self.le_meta_jsons:
            if contact is not None:
                formStash.fatal_field(
                    field="account__contact",
                    error_field="`account__contact` must not be submitted with LE data.",
                )

        self.getcreate_args = decode_args(getcreate_args)

    def validate_acme_server(
        self,
        ctx: "ApiContext",
    ) -> int:
        _acme_server_ids__all = [i.id for i in ctx.dbAcmeServers]
        _acme_server_ids__enabled = [i.id for i in ctx.dbAcmeServers if i.is_enabled]

        acme_server_id = self.formStash.results["acme_server_id"]
        if acme_server_id not in _acme_server_ids__all:
            self.formStash.fatal_field(
                field="acme_server_id",
                error_field="Invalid provider submitted.",
            )

        if acme_server_id not in _acme_server_ids__enabled:
            self.formStash.fatal_field(
                field="acme_server_id",
                error_field="This provider is no longer enabled.",
            )
        return acme_server_id

    def generate_create_args(self):
        key_create_args = self.getcreate_args
        for _field in (
            "contact",
            "acme_server_id",
            "private_key_technology_id",
            "order_default_private_key_cycle_id",
            "order_default_private_key_technology_id",
            "order_default_acme_profile",
        ):
            assert _field in key_create_args

        # convert the args to cert_utils
        _private_key_technology_id = key_create_args["private_key_technology_id"]
        cu_new_args = model_utils.KeyTechnology.to_new_args(_private_key_technology_id)
        key_pem = cert_utils.new_account_key(
            key_technology_id=cu_new_args["key_technology_id"],
            rsa_bits=cu_new_args.get("rsa_bits"),
            ec_curve=cu_new_args.get("ec_curve"),
        )
        key_create_args["key_pem"] = key_pem
        key_create_args["event_type"] = "AcmeAccount__create"
        key_create_args["acme_account_key_source_id"] = (
            model_utils.AcmeAccountKeySource.GENERATED
        )
        return key_create_args


class _PrivateKeyUploadParser(object):
    """
    A PrivateKey is not a complex upload to parse itself
    This code exists to mimic the AcmeAccount uploading.
    """

    # overwritten in __init__
    getcreate_args: Dict
    formStash: "FormStash"

    # tracked
    private_key_pem: Optional[str] = None
    upload_type: Optional[str] = None  # pem

    def __init__(self, formStash: "FormStash"):
        self.formStash = formStash
        self.getcreate_args = {}

    def require_upload(self) -> None:
        """
        routine for uploading an exiting PrivateKey
        """
        formStash = self.formStash

        getcreate_args = {}

        if formStash.results["private_key_file_pem"] is not None:
            self.upload_type = "pem"
            self.private_key_pem = getcreate_args["key_pem"] = (
                formhandling.slurp_file_field(formStash, "private_key_file_pem")
            )

        self.getcreate_args = decode_args(getcreate_args)


class _AcmeAccountSelection(object):
    """
    Class used to manage an uploaded AcmeAccount
    """

    selection: Optional[str] = None
    upload_parsed: Optional["AcmeAccountUploadParser"] = None
    AcmeAccount: Optional["AcmeAccount"] = None

    def _ensure(self):
        if self.AcmeAccount is None:
            raise ValueError("No!")


class _PrivateKeySelection(object):
    private_key_option: str
    selection: Optional[str] = None
    upload_parsed: Optional["_PrivateKeyUploadParser"] = None
    PrivateKey: Optional["PrivateKey"] = None

    # this should be set by the parser
    private_key_generate: Optional[str] = None  # see model_utils.KeyTechnology

    def __init__(self, private_key_option: str):
        self.private_key_option = private_key_option

    @property
    def private_key_technology_id(self) -> int:
        if TYPE_CHECKING:
            # this will be set before this function is run
            assert self.private_key_generate
            assert self.PrivateKey
        if self.private_key_option == "account_default":
            return model_utils.KeyTechnology.ACCOUNT_DEFAULT
        elif self.private_key_option == "private_key_generate":
            return model_utils.KeyTechnology.from_string(self.private_key_generate)
        elif self.private_key_option == "private_key_existing":
            return self.PrivateKey.key_technology_id
        else:
            raise ValueError("Unsupported `private_key_option")

    @property
    def private_key_technology(self) -> str:
        return model_utils.KeyTechnology.as_string(self.private_key_technology_id)


class _PrivateKeySelection_v2(object):
    dbPrivateKey: Optional["PrivateKey"] = None
    private_key_option: Literal["private_key_existing", "private_key_generate", "none"]
    private_key_technology: str
    private_key_technology__effective: Optional[
        str
    ]  # required for Primary; optional for Backup

    def __init__(
        self,
        private_key_option: Literal[
            "private_key_existing", "private_key_generate", "none"
        ],
    ):
        self.private_key_option = private_key_option


def parse_AcmeAccountSelection(
    request: "Request",
    formStash: "FormStash",
    allow_none: Optional[bool] = None,
    require_contact: Optional[bool] = None,
    support_upload: Optional[bool] = None,
) -> _AcmeAccountSelection:
    """
    :param formStash: an instance of `pyramid_formencode_classic.FormStash`
    :param allow_none:
    :param require_contact: ``True`` if required; ``False`` if not;
    :param support_upload: ``True`` if supported; ``False`` if not;
    """
    account_key_pem_md5: Optional[str] = None
    acme_account_id: Optional[int] = None
    dbAcmeAccount: Optional["AcmeAccount"] = None

    account_key_option = formStash.results["account_key_option"]

    # handle the explicit-option
    acmeAccountSelection = _AcmeAccountSelection()
    if account_key_option == "account_key_file":
        if not support_upload:
            formStash.fatal_form("This form does not support AccountKey Uploads")
        # this will handle form validation and raise errors.
        parser = AcmeAccountUploadParser(formStash)

        # this will have: `contact`, `private_key_technology`, private_key_cycle
        parser.require_upload(require_contact=require_contact)

        # update our object
        acmeAccountSelection.selection = "upload"
        acmeAccountSelection.upload_parsed = parser

        return acmeAccountSelection
    else:
        if account_key_option == "account_key_global_default":
            acmeAccountSelection.selection = "global_default"
            account_key_pem_md5 = formStash.results["account_key_global_default"]
        elif account_key_option == "account_key_existing":
            acmeAccountSelection.selection = "existing"
            account_key_pem_md5 = formStash.results["account_key_existing"]
        elif account_key_option == "account_key_reuse":
            acmeAccountSelection.selection = "reuse"
            account_key_pem_md5 = formStash.results["account_key_reuse"]
        elif account_key_option == "acme_account_id":
            acmeAccountSelection.selection = "acme_account_id"
            acme_account_id = formStash.results["acme_account_id"]
        elif account_key_option == "none":
            if not allow_none:
                formStash.fatal_form("This form requires an AcmeAccount selection.")
            # note the lowercase "none"; this is an explicit "no item" selection
            # only certain routes allow this
            acmeAccountSelection.selection = "none"
            account_key_pem_md5 = None
            return acmeAccountSelection
        else:
            formStash.fatal_form(
                error_main="Invalid `account_key_option`",
            )
        if not account_key_pem_md5 and not acme_account_id:
            formStash.fatal_field(
                field=account_key_option,
                error_field="You did not provide a value",
            )
        if account_key_pem_md5:
            dbAcmeAccount = lib_db.get.get__AcmeAccount__by_pemMd5(
                request.api_context, account_key_pem_md5, is_active=True
            )
        elif acme_account_id:
            dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(
                request.api_context, acme_account_id
            )
        if not dbAcmeAccount:
            formStash.fatal_field(
                field=account_key_option,
                error_field="The selected AcmeAccount is not enrolled in the system.",
            )
        if TYPE_CHECKING:
            assert dbAcmeAccount is not None

        # Ensure it is the Global Default
        if account_key_option == "account_key_global_default":
            if (
                not request.api_context.dbSystemConfiguration_global
                or not request.api_context.dbSystemConfiguration_global.is_configured
            ):
                formStash.fatal_field(
                    field=account_key_option,
                    error_field="There is no Global Default configured.",
                )
            if (
                request.api_context.dbSystemConfiguration_global.acme_account_id__primary
                != dbAcmeAccount.id
            ):
                formStash.fatal_field(
                    field=account_key_option,
                    error_field="The selected AcmeAccount is not the global default.",
                )

        acmeAccountSelection.AcmeAccount = dbAcmeAccount
        return acmeAccountSelection
    formStash.fatal_form("There was an error validating your form.")


def parse_AcmeAccountSelection_backup(
    request: "Request",
    formStash: "FormStash",
    allow_none: Optional[bool] = True,
) -> _AcmeAccountSelection:
    """
    :param formStash: an instance of `pyramid_formencode_classic.FormStash`
    :param allow_none:
    """
    account_key_pem_md5: Optional[str] = None
    acme_account_id: Optional[int] = None
    dbAcmeAccount: Optional["AcmeAccount"] = None

    account_key_option = formStash.results["account_key_option_backup"]

    # handle the explicit-option
    acmeAccountSelection = _AcmeAccountSelection()
    error_field = "Error_Main"
    if account_key_option == "account_key_global_backup":
        error_field = "account_key_global_backup"
        acmeAccountSelection.selection = "global_backup"
        account_key_pem_md5 = formStash.results["account_key_global_backup"]
    elif account_key_option == "account_key_existing":
        error_field = "account_key_existing_backup"
        acmeAccountSelection.selection = "existing"
        account_key_pem_md5 = formStash.results["account_key_existing_backup"]
    elif account_key_option == "account_key_reuse":
        acmeAccountSelection.selection = "reuse"
        account_key_pem_md5 = formStash.results["account_key_reuse_backup"]
    elif account_key_option == "acme_account_id":
        acmeAccountSelection.selection = "acme_account_id"
        acme_account_id = formStash.results["acme_account_id"]
    elif account_key_option in ("none", None):
        error_field = "account_key_existing_backup"
        if not allow_none:
            formStash.fatal_form("This form requires a backup AcmeAccount selection.")
        # note the lowercase "none"; this is an explicit "no item" selection
        # only certain routes allow this
        acmeAccountSelection.selection = "none"
        account_key_pem_md5 = None
        return acmeAccountSelection
    else:
        formStash.fatal_field(
            field="account_key_option_backup",
            error_field="Invalid selection.",
        )
    if not account_key_pem_md5 and not acme_account_id:
        formStash.fatal_field(
            field=error_field,
            error_field="You did not provide a value",
        )
    if account_key_pem_md5:
        dbAcmeAccount = lib_db.get.get__AcmeAccount__by_pemMd5(
            request.api_context, account_key_pem_md5, is_active=True
        )
    elif acme_account_id:
        dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(
            request.api_context, acme_account_id
        )
    if not dbAcmeAccount:
        formStash.fatal_field(
            field=error_field,
            error_field="The selected AcmeAccount is not enrolled in the system.",
        )
    if TYPE_CHECKING:
        assert dbAcmeAccount is not None

    if account_key_option == "account_key_global_backup":
        # Ensure it is the Global Default
        if (
            not request.api_context.dbSystemConfiguration_global
            or not request.api_context.dbSystemConfiguration_global.is_configured
        ):
            formStash.fatal_field(
                field=account_key_option,
                error_field="The Global Backup is not configured.",
            )
        if (
            request.api_context.dbSystemConfiguration_global.acme_account_id__backup
            != dbAcmeAccount.id
        ):
            formStash.fatal_field(
                field=account_key_option,
                error_field="The selected AcmeAccount is not the Global Backup.",
            )

    acmeAccountSelection.AcmeAccount = dbAcmeAccount
    return acmeAccountSelection


def parse_AcmeAccountSelections_v2(
    request: "Request",
    formStash: "FormStash",
    dbSystemConfiguration: "SystemConfiguration",
) -> Tuple["AcmeAccount", Optional["AcmeAccount"]]:
    dbAcmeAccount_primary: "AcmeAccount"
    dbAcmeAccount_backup: Optional["AcmeAccount"] = None

    # !!!: dbAcmeAccount_primary
    if (
        formStash.results["account_key_option__primary"]
        == "system_configuration_default"
    ):
        dbAcmeAccount_primary = dbSystemConfiguration.acme_account__primary
    elif formStash.results["account_key_option__primary"] == "account_key_existing":
        account_key_pem_md5 = formStash.results["account_key_existing__primary"]
        _candidate = lib_db.get.get__AcmeAccount__by_pemMd5(
            request.api_context, account_key_pem_md5
        )
        if not _candidate:
            formStash.fatal_field(
                field="account_key_existing__primary",
                error_field="The selected AcmeAccount is not enrolled in the system.",
            )
        elif not _candidate.is_active:
            formStash.fatal_field(
                field="account_key_existing__primary",
                error_field="The selected AcmeAccount is not active.",
            )
        if TYPE_CHECKING:
            assert _candidate
        dbAcmeAccount_primary = _candidate
    else:
        formStash.fatal_field(
            field="account_key_option__primary",
            error_field="Invalid option.",
        )

    # !!!: dbAcmeAccount_backup
    if (
        formStash.results["account_key_option__backup"]
        == "system_configuration_default"
    ):
        dbAcmeAccount_backup = dbSystemConfiguration.acme_account__backup
    elif formStash.results["account_key_option__backup"] == "none":
        # explicitly declared
        dbAcmeAccount_backup = None
    elif formStash.results["account_key_option__backup"] is None:
        # not submitted
        dbAcmeAccount_backup = None
    elif formStash.results["account_key_option__backup"] == "account_key_existing":
        account_key_pem_md5 = formStash.results["account_key_existing__backup"]
        dbAcmeAccount_backup = lib_db.get.get__AcmeAccount__by_pemMd5(
            request.api_context, account_key_pem_md5
        )
        if not dbAcmeAccount_backup:
            formStash.fatal_field(
                field="account_key_option__backup",
                error_field="The selected AcmeAccount is not enrolled in the system.",
            )
        elif not dbAcmeAccount_backup.is_active:
            formStash.fatal_field(
                field="account_key_option__backup",
                error_field="The selected AcmeAccount is not active.",
            )
    else:
        formStash.fatal_field(
            field="account_key_option__backup",
            error_field="Invalid option.",
        )

    return dbAcmeAccount_primary, dbAcmeAccount_backup


def parse_PrivateKeySelections_v2(
    request: "Request",
    formStash: "FormStash",
    dbSystemConfiguration: "SystemConfiguration",
) -> Tuple[_PrivateKeySelection_v2, _PrivateKeySelection_v2]:

    pkeySelection__primary = _PrivateKeySelection_v2(
        formStash.results["private_key_option__primary"]
    )
    pkeySelection__backup = _PrivateKeySelection_v2(
        formStash.results["private_key_option__backup"]
    )

    # !!!: primary
    if formStash.results["private_key_option__primary"] == "private_key_existing":
        private_key_pem_md5 = formStash.results["private_key_existing__primary"]
        dbPrivateKey_primary = lib_db.get.get__PrivateKey__by_pemMd5(
            request.api_context,
            private_key_pem_md5,
        )
        if not dbPrivateKey_primary:
            formStash.fatal_field(
                field="private_key_existing__primary",
                error_field="The selected PrivateKey is not enrolled in the system.",
            )
        elif not dbPrivateKey_primary.is_active:
            formStash.fatal_field(
                field="private_key_existing__primary",
                error_field="The selected PrivateKey is not active.",
            )
        pkeySelection__primary.dbPrivateKey = dbPrivateKey_primary

    elif formStash.results["private_key_option__primary"] == "private_key_generate":
        dbPrivateKey_primary = lib_db.get.get__PrivateKey__by_id(request.api_context, 0)
        if not dbPrivateKey_primary:
            formStash.fatal_field(
                field="private_key_option__primary",
                error_field="Could not load the placeholder PrivateKey.",
            )
        pkeySelection__primary.dbPrivateKey = dbPrivateKey_primary

        private_key_technology__primary = formStash.results[
            "private_key_technology__primary"
        ]
        pkeySelection__primary.private_key_technology = private_key_technology__primary

        # note, this will not show the account effectiveness
        private_key_technology__effective_primary: str
        if private_key_technology__primary == "system_configuration_default":
            private_key_technology__effective_primary = (
                dbSystemConfiguration.private_key_technology__primary
            )
        else:
            private_key_technology__effective_primary = private_key_technology__primary
        pkeySelection__primary.private_key_technology__effective = (
            private_key_technology__effective_primary
        )
    else:
        formStash.fatal_field(
            field="private_key_option__primary",
            error_field="Invalid option.",
        )

    # !!!: backup
    if formStash.results["private_key_option__backup"] == "private_key_existing":
        private_key_pem_md5 = formStash.results["private_key_existing__backup"]
        dbPrivateKey_backup = lib_db.get.get__PrivateKey__by_pemMd5(
            request.api_context,
            private_key_pem_md5,
        )
        if not dbPrivateKey_backup:
            formStash.fatal_field(
                field="private_key_existing__backup",
                error_field="The selected PrivateKey is not enrolled in the system.",
            )
        elif not dbPrivateKey_backup.is_active:
            formStash.fatal_field(
                field="private_key_existing__backup",
                error_field="The selected PrivateKey is not active.",
            )
        pkeySelection__backup.dbPrivateKey = dbPrivateKey_backup

    elif formStash.results["private_key_option__backup"] == "private_key_generate":
        dbPrivateKey_backup = lib_db.get.get__PrivateKey__by_id(request.api_context, 0)
        if not dbPrivateKey_backup:
            formStash.fatal_field(
                field="private_key_option__backup",
                error_field="Could not load the placeholder PrivateKey.",
            )
        pkeySelection__backup.dbPrivateKey = dbPrivateKey_backup

        private_key_technology__backup = formStash.results[
            "private_key_technology__backup"
        ]
        pkeySelection__backup.private_key_technology = private_key_technology__backup

        # note, this will not show the account effectiveness
        private_key_technology__effective_backup: Optional[str]
        if private_key_technology__backup == "system_configuration_default":
            if not dbSystemConfiguration.private_key_technology__backup:
                formStash.fatal_field(
                    field="private_key_option__backup",
                    error_field="SystemConfiguration not configured.",
                )
            private_key_technology__effective_backup = (
                dbSystemConfiguration.private_key_technology__backup
            )
        else:
            private_key_technology__effective_backup = private_key_technology__backup
        pkeySelection__backup.private_key_technology__effective = (
            private_key_technology__effective_backup
        )
    elif formStash.results["private_key_option__backup"] == "none":
        # explicitly declare None
        pass
    elif formStash.results["private_key_option__backup"] is None:
        # value not submitted
        pass
    else:
        formStash.fatal_field(
            field="private_key_option__backup",
            error_field="Invalid option.",
        )

    return pkeySelection__primary, pkeySelection__backup


def parse_PrivateKeySelection(
    request: "Request",
    formStash: "FormStash",
    private_key_option: str,
    support_upload: Optional[bool] = None,
) -> _PrivateKeySelection:
    private_key_pem_md5: Optional[str] = None
    # PrivateKey = None  # :class:`model.objects.PrivateKey`

    # handle the explicit-option
    privateKeySelection = _PrivateKeySelection(private_key_option)
    if private_key_option == "private_key_file":
        if not support_upload:
            formStash.fatal_form("This form does not support PrivateKey Uploads")

        # this will handle form validation and raise errors.
        parser = _PrivateKeyUploadParser(formStash)
        parser.require_upload()

        # update our object
        privateKeySelection.selection = "upload"
        privateKeySelection.upload_parsed = parser

        # Return Early
        return privateKeySelection

    elif private_key_option in (
        "private_key_generate",
        "account_default",
    ):
        dbPrivateKey = lib_db.get.get__PrivateKey__by_id(request.api_context, 0)
        if not dbPrivateKey:
            formStash.fatal_field(
                field=private_key_option,
                error_field="Could not load the placeholder PrivateKey.",
            )
        privateKeySelection.PrivateKey = dbPrivateKey
        if private_key_option == "private_key_generate":
            privateKeySelection.selection = "generate"
            private_key_technology_str = formStash.results[
                "private_key_generate"
            ]  # this is a model_utils.KeyTechnology
            privateKeySelection.private_key_generate = private_key_technology_str

        elif private_key_option == "account_default":
            privateKeySelection.selection = "account_default"

        # Return Early
        return privateKeySelection

    # The following do not return early and share some logic:

    if private_key_option == "private_key_existing":
        privateKeySelection.selection = "existing"
        private_key_pem_md5 = formStash.results["private_key_existing"]

    elif private_key_option == "private_key_reuse":
        privateKeySelection.selection = "reuse"
        private_key_pem_md5 = formStash.results["private_key_reuse"]

    else:
        formStash.fatal_form("Invalid `private_key_option`")

    if not private_key_pem_md5:
        formStash.fatal_field(
            field=private_key_option,
            error_field="You did not provide a value",
        )
    if TYPE_CHECKING:
        assert private_key_pem_md5 is not None
    dbPrivateKey = lib_db.get.get__PrivateKey__by_pemMd5(
        request.api_context, private_key_pem_md5, is_active=True
    )
    if not dbPrivateKey:
        formStash.fatal_field(
            field=private_key_option,
            error_field="The selected PrivateKey is not enrolled in the system.",
        )
    privateKeySelection.PrivateKey = dbPrivateKey
    return privateKeySelection


def form_key_selection(
    request: "Request",
    formStash: "FormStash",
    require_contact: Optional[bool] = None,
    support_upload_AcmeAccount: Optional[bool] = None,
    support_upload_PrivateKey: Optional[bool] = None,
) -> Tuple[_AcmeAccountSelection, _PrivateKeySelection]:
    """
    :param formStash: an instance of `pyramid_formencode_classic.FormStash`
    :param require_contact: ``True`` if required; ``False`` if not; ``None`` for conditional logic

    note: currently only used by `acme_order/new-freeform`
    """
    acmeAccountSelection = parse_AcmeAccountSelection(
        request,
        formStash,
        require_contact=require_contact,
        support_upload=support_upload_AcmeAccount,
    )
    if acmeAccountSelection.selection == "upload":
        assert acmeAccountSelection.upload_parsed
        key_create_args = acmeAccountSelection.upload_parsed.getcreate_args
        key_create_args["acme_account_key_source_id"] = (
            model_utils.AcmeAccountKeySource.IMPORTED
        )
        key_create_args["event_type"] = "AcmeAccount__insert"
        (
            dbAcmeAccount,
            _is_created,
        ) = lib_db.getcreate.getcreate__AcmeAccount(
            request.api_context, **key_create_args
        )
        acmeAccountSelection.AcmeAccount = dbAcmeAccount

    privateKeySelection = parse_PrivateKeySelection(
        request,
        formStash,
        private_key_option=formStash.results["private_key_option"],
        support_upload=support_upload_PrivateKey,
    )

    dbPrivateKey: Optional["PrivateKey"] = None
    if privateKeySelection.selection == "upload":
        assert privateKeySelection.upload_parsed
        key_create_args = privateKeySelection.upload_parsed.getcreate_args
        key_create_args["discovery_type"] = "upload"
        key_create_args["event_type"] = "PrivateKey__insert"
        key_create_args["private_key_source_id"] = model_utils.PrivateKeySource.IMPORTED
        key_create_args["private_key_type_id"] = model_utils.PrivateKeyType.STANDARD
        # TODO: We should infer the above based on the private_key_cycle
        (
            dbPrivateKey,
            _is_created,
        ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
            request.api_context, **key_create_args
        )
        privateKeySelection.PrivateKey = dbPrivateKey

    elif privateKeySelection.selection == "generate":
        dbPrivateKey = lib_db.get.get__PrivateKey__by_id(request.api_context, 0)
        if not dbPrivateKey:
            formStash.fatal_field(
                field="private_key_option",
                error_field="Could not load the placeholder PrivateKey for autogeneration.",
            )
        privateKeySelection.PrivateKey = dbPrivateKey

    if privateKeySelection.PrivateKey is None:
        raise ValueError("no PrivateKey parsed")

    return (acmeAccountSelection, privateKeySelection)


def form_domains_challenge_typed(
    request: "Request",
    formStash: "FormStash",
    http01_only: bool = False,
    dbAcmeDnsServer_GlobalDefault: Optional["AcmeDnsServer"] = None,
) -> model_utils.DomainsChallenged:
    domains_challenged = model_utils.DomainsChallenged()
    domain_names_all = []
    try:
        # 1: iterate over the submitted domains by segment
        for target_, source_ in DOMAINS_CHALLENGED_FIELDS.items():
            submitted_ = formStash.results.get(source_)
            if submitted_:
                # this function checks the domain names match a simple regex
                # it will raise a `ValueError("invalid domain")` on the first invalid domain
                # domains will also be lowercase+strip
                submitted_ = cert_utils.utils.domains_from_string(submitted_)
                if submitted_:
                    domain_names_all.extend(submitted_)
                    domains_challenged[target_] = submitted_

        # 2: ensure there are domains
        if not domain_names_all:
            formStash.fatal_form(error_main="no domain names submitted")

        # 3: ensure there is no overlap
        domain_names_all_set = set(domain_names_all)
        if len(domain_names_all) != len(domain_names_all_set):
            formStash.fatal_form(
                error_main="a domain name can only be associated to one challenge type",
            )

        # 4: maybe we only want http01 domains submitted?
        if http01_only:
            for k, v in domains_challenged.items():
                if k == "http-01":
                    continue
                if v:
                    formStash.fatal_form(
                        error_main="only http-01 domains are accepted by this form",
                    )

        # ensure wildcards are only in dns-01
        for chall, ds in domains_challenged.items():
            if chall == "dns-01":
                continue
            if ds:
                for d in ds:
                    if d[0] == "*":
                        formStash.fatal_form(
                            error_main="wildcards (*) MUST use `dns-01`.",
                        )

        # see DOMAINS_CHALLENGED_FIELDS
        if domains_challenged["dns-01"]:
            if not dbAcmeDnsServer_GlobalDefault:
                formStash.fatal_field(
                    field="domain_names_dns01",
                    error_field="The global acme-dns server is not configured.",
                )

    except ValueError as exc:  # noqa: F841
        raise
        formStash.fatal_form(error_main="invalid domain names detected")

    return domains_challenged


def form_single_domain_challenge_typed(
    request: "Request",
    formStash: "FormStash",
    challenge_type: str = "http-01",
) -> model_utils.DomainsChallenged:
    """
    Creates a `model_utils.DomainsChallenged` with only 1 domain from a form
    """
    domains_challenged = model_utils.DomainsChallenged()

    # this function checks the domain names match a simple regex
    # domains will also be lowercase+strip
    domain_names = cert_utils.utils.domains_from_string(
        formStash.results["domain_name"]
    )
    if not domain_names:
        formStash.fatal_field(
            field="domain_name",
            error_field="Found no domain names",
        )
    if len(domain_names) != 1:
        formStash.fatal_field(
            field="domain_name",
            error_field="This endpoint currently supports only 1 domain name",
        )

    domains_challenged[challenge_type] = domain_names

    return domains_challenged
