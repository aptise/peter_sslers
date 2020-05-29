# pypi
import six

# local
from ...lib import db as lib_db
from ...model import objects as model_objects
from ...model import utils as model_utils
from . import formhandling


# ==============================================================================


def decode_args(getcreate_args):
    """
    support for Python2/3
    """
    if six.PY3:
        for (k, v) in list(getcreate_args.items()):
            if isinstance(v, bytes):
                getcreate_args[k] = v.decode("utf8")
    return getcreate_args


class AcmeAccountUploadParser(object):
    """
    An AcmeAccount may be uploaded multiple ways:
    * a single PEM file
    * an intra-associated three file triplet from a Certbot installation

    This parser operates on a validated FormEncode results object (via `pyramid_formencode_classic`)
    """

    # overwritten in __init__
    getcreate_args = None
    formStash = None
    # tracked
    acme_account_provider_id = None
    account_key_pem = None
    le_meta_jsons = None
    le_pkey_jsons = None
    le_reg_jsons = None
    private_key_cycle_id = None
    upload_type = None  # pem OR letsencrypt

    def __init__(self, formStash):
        self.formStash = formStash
        self.getcreate_args = {}

    def require_new(self, require_contact=None):
        """
        routine for creating a NEW AcmeAccount (peter_sslers generates the credentials)
        
        :param require_contact: ``True`` if required; ``False`` if not; ``None`` for conditional logic
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

        contact = formStash.results.get("account__contact", None)
        if not contact and require_contact:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="account__contact", message="`account__contact` is required.",
            )

        getcreate_args = {}
        self.contact = getcreate_args["contact"] = contact
        self.acme_account_provider_id = getcreate_args[
            "acme_account_provider_id"
        ] = acme_account_provider_id
        self.private_key_cycle_id = getcreate_args[
            "private_key_cycle_id"
        ] = private_key_cycle_id
        self.getcreate_args = decode_args(getcreate_args)

    def require_upload(self, require_contact=None):
        """
        routine for uploading an exiting AcmeAccount+AcmeAccountKey

        :param require_contact: ``True`` if required; ``False`` if not; ``None`` for conditional logic
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

        # require `contact` when uploading a PEM file
        if formStash.results["account_key_file_pem"] is not None:
            require_contact = True

        contact = formStash.results.get("account__contact")
        if not contact and require_contact:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="account__contact", message="`account__contact` is required.",
            )

        getcreate_args = {}
        self.contact = getcreate_args["contact"] = contact
        self.private_key_cycle_id = getcreate_args[
            "private_key_cycle_id"
        ] = private_key_cycle_id

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
    getcreate_args = None
    formStash = None

    # tracked
    private_key_pem = None
    upload_type = None  # pem

    def __init__(self, formStash):
        self.formStash = formStash
        self.getcreate_args = {}

    def require_upload(self):
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

    selection = None
    upload_parsed = None  # instance of AcmeAccountUploadParser or None
    AcmeAccount = None


class _PrivateKeySelection(object):
    selection = None
    upload_parsed = None  # instance of AcmeAccountUploadParser or None
    private_key_strategy__requested = None
    PrivateKey = None

    @property
    def private_key_strategy_id__requested(self):
        return model_utils.PrivateKeyStrategy.from_string(
            self.private_key_strategy__requested
        )


def parse_AcmeAccountSelection(
    request, formStash, account_key_option=None, allow_none=None, require_contact=None,
):
    """
    :param formStash: an instance of `pyramid_formencode_classic.FormStash`
    :param account_key_option:
    :param allow_none:
    :param require_contact: ``True`` if required; ``False`` if not; ``None`` for conditional logic
    """
    account_key_pem = None
    account_key_pem_md5 = None
    dbAcmeAccount = None
    is_global_default = None

    # handle the explicit-option
    acmeAccountSelection = _AcmeAccountSelection()
    if account_key_option == "account_key_file":
        # this will handle form validation and raise errors.
        parser = AcmeAccountUploadParser(formStash)

        # this will have `contact` and `private_key_cycle`
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
            formStash.fatal_form(message="Invalid `account_key_option`",)
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


def parse_PrivateKeySelection(request, formStash, private_key_option=None):
    private_key_pem = None
    private_key_pem_md5 = None
    PrivateKey = None  # :class:`model.objects.PrivateKey`

    # handle the explicit-option
    privateKeySelection = _PrivateKeySelection()
    if private_key_option == "private_key_file":
        # this will handle form validation and raise errors.
        parser = _PrivateKeyUploadParser(formStash)
        parser.require_upload()

        # update our object
        privateKeySelection.selection = "upload"
        privateKeySelection.upload_parsed = parser
        privateKeySelection.private_key_strategy__requested = model_utils.PrivateKeySelection_2_PrivateKeyStrategy[
            "upload"
        ]

        return privateKeySelection

    else:
        if private_key_option == "private_key_existing":
            privateKeySelection.selection = "existing"
            privateKeySelection.private_key_strategy__requested = model_utils.PrivateKeySelection_2_PrivateKeyStrategy[
                "existing"
            ]
            private_key_pem_md5 = formStash.results["private_key_existing"]
        elif private_key_option == "private_key_reuse":
            privateKeySelection.selection = "reuse"
            privateKeySelection.private_key_strategy__requested = model_utils.PrivateKeySelection_2_PrivateKeyStrategy[
                "reuse"
            ]
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
                privateKeySelection.private_key_strategy__requested = model_utils.PrivateKeySelection_2_PrivateKeyStrategy[
                    "generate"
                ]
            elif private_key_option == "private_key_for_account_key":
                privateKeySelection.selection = "private_key_for_account_key"
                privateKeySelection.private_key_strategy__requested = model_utils.PrivateKeySelection_2_PrivateKeyStrategy[
                    "private_key_for_account_key"
                ]
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


def form_key_selection(request, formStash, require_contact=None):
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
        key_create_args = acmeAccountSelection.upload_parsed.getcreate_args
        key_create_args["event_type"] = "AcmeAccount__insert"
        key_create_args[
            "acme_account_key_source_id"
        ] = model_utils.AcmeAccountKeySource.from_string("imported")
        (dbAcmeAccount, _is_created,) = lib_db.getcreate.getcreate__AcmeAccount(
            request.api_context, **key_create_args
        )
        acmeAccountSelection.AcmeAccount = dbAcmeAccount

    privateKeySelection = parse_PrivateKeySelection(
        request, formStash, private_key_option=formStash.results["private_key_option"],
    )

    if privateKeySelection.selection == "upload":
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
