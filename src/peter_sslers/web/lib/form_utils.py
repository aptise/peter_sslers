# stdlib
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
import cert_utils
from pyramid_formencode_classic import FormStash

# local
from . import formhandling
from ...lib import db as lib_db
from ...model import utils as model_utils

if TYPE_CHECKING:
    from pyramid.request import Request


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
DOMAINS_CHALLENGED_FIELDS = {
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
    formStash: FormStash

    # tracked
    acme_account_provider_id: Optional[int] = None
    account_key_pem = None
    le_meta_jsons = None
    le_pkey_jsons = None
    le_reg_jsons = None
    private_key_cycle_id = None
    private_key_technology_id: Optional[int] = None
    upload_type = None  # pem OR letsencrypt

    def __init__(self, formStash: FormStash):
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

        acme_account_provider_id = formStash.results.get(
            "acme_account_provider_id", None
        )
        if acme_account_provider_id is None:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="acme_account_provider_id", message="No provider submitted."
            )

        private_key_cycle = formStash.results.get("account__private_key_cycle", None)
        if private_key_cycle is None:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="account__private_key_cycle",
                message="No PrivateKey cycle submitted.",
            )
        private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            private_key_cycle
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
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="account__private_key_technology",
                message="No PrivateKey technology submitted.",
            )

        contact = formStash.results.get("account__contact", None)
        if not contact and require_contact:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="account__contact",
                message="`account__contact` is required.",
            )

        getcreate_args = {}
        self.contact = getcreate_args["contact"] = contact
        self.acme_account_provider_id = getcreate_args[
            "acme_account_provider_id"
        ] = acme_account_provider_id
        self.private_key_cycle_id = getcreate_args[
            "private_key_cycle_id"
        ] = private_key_cycle_id
        self.private_key_technology_id = getcreate_args[
            "private_key_technology_id"
        ] = private_key_technology_id
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
                # "acme_account_provider_id",
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
            # `formStash.fatal_form()` will raise `FormInvalid()`
            formStash.fatal_form(
                "You must upload `account_key_file_pem` or all of (`account_key_file_le_meta`, `account_key_file_le_pkey`, `account_key_file_le_reg`)."
            )

        # -------------------

        # validate the provider option
        # will be None unless a pem is uploaded
        # required for PEM, ignored otherwise
        acme_account_provider_id = formStash.results.get(
            "acme_account_provider_id", None
        )

        private_key_cycle = formStash.results.get("account__private_key_cycle", None)
        if private_key_cycle is None:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="account__private_key_cycle",
                message="No PrivateKey cycle submitted.",
            )
        private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            private_key_cycle
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
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="account__private_key_technology",
                message="No PrivateKey technology submitted.",
            )

        # require `contact` when uploading a PEM file
        if formStash.results["account_key_file_pem"] is not None:
            require_contact = True

        contact = formStash.results.get("account__contact")
        if not contact and require_contact:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="account__contact",
                message="`account__contact` is required.",
            )

        getcreate_args = {}
        self.contact = getcreate_args["contact"] = contact
        self.private_key_cycle_id = getcreate_args[
            "private_key_cycle_id"
        ] = private_key_cycle_id
        self.private_key_technology_id = getcreate_args[
            "private_key_technology_id"
        ] = private_key_technology_id

        if formStash.results["account_key_file_pem"] is not None:
            if acme_account_provider_id is None:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="acme_account_provider_id", message="No provider submitted."
                )
            self.upload_type = "pem"
            self.acme_account_provider_id = getcreate_args[
                "acme_account_provider_id"
            ] = acme_account_provider_id
            self.account_key_pem = getcreate_args[
                "key_pem"
            ] = formhandling.slurp_file_field(formStash, "account_key_file_pem")
        else:
            # note that we use `jsonS` to indicate a string
            self.le_meta_jsons = getcreate_args[
                "le_meta_jsons"
            ] = formhandling.slurp_file_field(formStash, "account_key_file_le_meta")
            self.le_pkey_jsons = getcreate_args[
                "le_pkey_jsons"
            ] = formhandling.slurp_file_field(formStash, "account_key_file_le_pkey")
            self.le_reg_jsons = getcreate_args[
                "le_reg_jsons"
            ] = formhandling.slurp_file_field(formStash, "account_key_file_le_reg")
        self.getcreate_args = decode_args(getcreate_args)


class _PrivateKeyUploadParser(object):
    """
    A PrivateKey is not a complex upload to parse itself
    This code exists to mimic the AcmeAccount uploading.
    """

    # overwritten in __init__
    getcreate_args: Dict
    formStash: FormStash

    # tracked
    private_key_pem = None
    upload_type = None  # pem

    def __init__(self, formStash: FormStash):
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
            self.private_key_pem = getcreate_args[
                "key_pem"
            ] = formhandling.slurp_file_field(formStash, "private_key_file_pem")

        self.getcreate_args = decode_args(getcreate_args)


class _AcmeAccountSelection(object):
    """
    Class used to manage an uploaded AcmeAccount
    """

    selection: Optional[str] = None
    upload_parsed: Optional["AcmeAccountUploadParser"] = None
    AcmeAccount = None


class _PrivateKeySelection(object):
    selection: Optional[str] = None
    upload_parsed: Optional["_PrivateKeyUploadParser"] = None
    private_key_strategy__requested: str
    PrivateKey = None

    @property
    def private_key_strategy_id__requested(self) -> int:
        return model_utils.PrivateKeyStrategy.from_string(
            self.private_key_strategy__requested
        )


def parse_AcmeAccountSelection(
    request,
    formStash: FormStash,
    account_key_option: Optional[str] = None,
    allow_none: Optional[bool] = None,
    require_contact: Optional[bool] = None,
) -> _AcmeAccountSelection:
    """
    :param formStash: an instance of `pyramid_formencode_classic.FormStash`
    :param account_key_option:
    :param allow_none:
    :param require_contact: ``True`` if required; ``False`` if not; ``None`` for conditional logic
    """
    account_key_pem_md5 = None
    dbAcmeAccount = None
    is_global_default = None

    # handle the explicit-option
    acmeAccountSelection = _AcmeAccountSelection()
    if account_key_option == "account_key_file":
        # this will handle form validation and raise errors.
        parser = AcmeAccountUploadParser(formStash)

        # this will have: `contact`, `private_key_cycle`, `private_key_technology`
        parser.require_upload(require_contact=require_contact)

        # update our object
        acmeAccountSelection.selection = "upload"
        acmeAccountSelection.upload_parsed = parser

        return acmeAccountSelection
    else:
        if account_key_option == "account_key_global_default":
            acmeAccountSelection.selection = "global_default"
            account_key_pem_md5 = formStash.results["account_key_global_default"]
            is_global_default = True
        elif account_key_option == "account_key_existing":
            acmeAccountSelection.selection = "existing"
            account_key_pem_md5 = formStash.results["account_key_existing"]
        elif account_key_option == "account_key_reuse":
            acmeAccountSelection.selection = "reuse"
            account_key_pem_md5 = formStash.results["account_key_reuse"]
        elif account_key_option == "none":
            if not allow_none:
                # `formStash.fatal_form()` will raise `FormInvalid()`
                formStash.fatal_form(
                    "This form does not support no AcmeAccount selection."
                )
            # note the lowercase "none"; this is an explicit "no item" selection
            # only certain routes allow this
            acmeAccountSelection.selection = "none"
            account_key_pem_md5 = None
            return acmeAccountSelection
        else:
            formStash.fatal_form(
                message="Invalid `account_key_option`",
            )
        if not account_key_pem_md5:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=account_key_option, message="You did not provide a value"
            )
        dbAcmeAccount = lib_db.get.get__AcmeAccount__by_pemMd5(
            request.api_context, account_key_pem_md5, is_active=True
        )
        if not dbAcmeAccount:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=account_key_option,
                message="The selected AcmeAccount is not enrolled in the system.",
            )
        if is_global_default and not dbAcmeAccount.is_global_default:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=account_key_option,
                message="The selected AcmeAccount is not the current default.",
            )
        acmeAccountSelection.AcmeAccount = dbAcmeAccount
        return acmeAccountSelection
    # `formStash.fatal_form()` will raise `FormInvalid()`
    formStash.fatal_form("There was an error validating your form.")


def parse_PrivateKeySelection(
    request: "Request",
    formStash: FormStash,
    private_key_option: Optional[str] = None,
) -> _PrivateKeySelection:
    private_key_pem_md5 = None
    # PrivateKey = None  # :class:`model.objects.PrivateKey`

    # handle the explicit-option
    privateKeySelection = _PrivateKeySelection()
    if private_key_option == "private_key_file":
        # this will handle form validation and raise errors.
        parser = _PrivateKeyUploadParser(formStash)
        parser.require_upload()

        # update our object
        privateKeySelection.selection = "upload"
        privateKeySelection.upload_parsed = parser
        privateKeySelection.private_key_strategy__requested = (
            model_utils.PrivateKeySelection_2_PrivateKeyStrategy["upload"]
        )

        return privateKeySelection

    else:
        if private_key_option == "private_key_existing":
            privateKeySelection.selection = "existing"
            privateKeySelection.private_key_strategy__requested = (
                model_utils.PrivateKeySelection_2_PrivateKeyStrategy["existing"]
            )
            private_key_pem_md5 = formStash.results["private_key_existing"]
        elif private_key_option == "private_key_reuse":
            privateKeySelection.selection = "reuse"
            privateKeySelection.private_key_strategy__requested = (
                model_utils.PrivateKeySelection_2_PrivateKeyStrategy["reuse"]
            )
            private_key_pem_md5 = formStash.results["private_key_reuse"]
        elif private_key_option in (
            "private_key_generate",
            "private_key_for_account_key",
        ):
            dbPrivateKey = lib_db.get.get__PrivateKey__by_id(request.api_context, 0)
            if not dbPrivateKey:
                formStash.fatal_field(
                    field=private_key_option,
                    message="Could not load the placeholder PrivateKey.",
                )
            privateKeySelection.PrivateKey = dbPrivateKey
            if private_key_option == "private_key_generate":
                privateKeySelection.selection = "generate"
                privateKeySelection.private_key_strategy__requested = (
                    model_utils.PrivateKeySelection_2_PrivateKeyStrategy["generate"]
                )
            elif private_key_option == "private_key_for_account_key":
                privateKeySelection.selection = "private_key_for_account_key"
                privateKeySelection.private_key_strategy__requested = (
                    model_utils.PrivateKeySelection_2_PrivateKeyStrategy[
                        "private_key_for_account_key"
                    ]
                )
            return privateKeySelection
        else:
            # `formStash.fatal_form()` will raise `FormInvalid()`
            formStash.fatal_form("Invalid `private_key_option`")

        if not private_key_pem_md5:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=private_key_option, message="You did not provide a value"
            )
        dbPrivateKey = lib_db.get.get__PrivateKey__by_pemMd5(
            request.api_context, private_key_pem_md5, is_active=True
        )
        if not dbPrivateKey:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=private_key_option,
                message="The selected PrivateKey is not enrolled in the system.",
            )
        privateKeySelection.PrivateKey = dbPrivateKey
        return privateKeySelection

    # `formStash.fatal_form()` will raise `FormInvalid()`
    formStash.fatal_form("There was an error validating your form.")


def form_key_selection(
    request: "Request",
    formStash: FormStash,
    require_contact: Optional[bool] = None,
) -> Tuple:
    """
    :param formStash: an instance of `pyramid_formencode_classic.FormStash`
    :param require_contact: ``True`` if required; ``False`` if not; ``None`` for conditional logic
    """
    acmeAccountSelection = parse_AcmeAccountSelection(
        request,
        formStash,
        account_key_option=formStash.results["account_key_option"],
        require_contact=require_contact,
    )
    if acmeAccountSelection.selection == "upload":
        assert acmeAccountSelection.upload_parsed
        key_create_args = acmeAccountSelection.upload_parsed.getcreate_args
        key_create_args["event_type"] = "AcmeAccount__insert"
        key_create_args[
            "acme_account_key_source_id"
        ] = model_utils.AcmeAccountKeySource.from_string("imported")
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
    )

    if privateKeySelection.selection == "upload":
        assert privateKeySelection.upload_parsed
        key_create_args = privateKeySelection.upload_parsed.getcreate_args
        key_create_args["event_type"] = "PrivateKey__insert"
        key_create_args[
            "private_key_source_id"
        ] = model_utils.PrivateKeySource.from_string("imported")
        key_create_args["private_key_type_id"] = model_utils.PrivateKeyType.from_string(
            "standard"
        )
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
                message="Could not load the placeholder PrivateKey for autogeneration.",
            )
        privateKeySelection.PrivateKey = dbPrivateKey

    return (acmeAccountSelection, privateKeySelection)


def form_domains_challenge_typed(
    request: "Request",
    formStash: FormStash,
    http01_only: bool = False,
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
                submitted_ = cert_utils.utils.domains_from_string(submitted_)
                if submitted_:
                    domain_names_all.extend(submitted_)
                    domains_challenged[target_] = submitted_

        # 2: ensure there are domains
        if not domain_names_all:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="Error_Main",
                message="no domain names submitted",
            )

        # 3: ensure there is no overlap
        domain_names_all_set = set(domain_names_all)
        if len(domain_names_all) != len(domain_names_all_set):
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="Error_Main",
                message="a domain name can only be associated to one challenge type",
            )

        # 4: maybe we only want http01 domains submitted?
        if http01_only:
            for k, v in domains_challenged.items():
                if k == "http-01":
                    continue
                if v:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="Error_Main",
                        message="only http-01 domains are accepted by this form",
                    )

    except ValueError as exc:  # noqa: F841
        # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
        formStash.fatal_field(
            field="Error_Main", message="invalid domain names detected"
        )

    return domains_challenged


def form_single_domain_challenge_typed(
    request: "Request",
    formStash: FormStash,
    challenge_type: str = "http-01",
) -> model_utils.DomainsChallenged:
    domains_challenged = model_utils.DomainsChallenged()

    # this function checks the domain names match a simple regex
    domain_names = cert_utils.utils.domains_from_string(
        formStash.results["domain_name"]
    )
    if not domain_names:
        # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
        formStash.fatal_field(field="domain_name", message="Found no domain names")
    if len(domain_names) != 1:
        # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
        formStash.fatal_field(
            field="domain_name",
            message="This endpoint currently supports only 1 domain name",
        )

    domains_challenged[challenge_type] = domain_names

    return domains_challenged
