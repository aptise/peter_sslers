# pypi
import six

# local
from ...lib import db as lib_db
from ...model import utils as model_utils
from . import formhandling


# ==============================================================================


def decode_args(getcreate_args):
    if six.PY3:
        for (k, v) in list(getcreate_args.items()):
            if isinstance(v, bytes):
                getcreate_args[k] = v.decode("utf8")
    return getcreate_args


class AccountKeyUploadParser(object):
    """
    this is a complex upload to parse
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
    upload_type = None  # pem OR letsencrypt

    def __init__(self, formStash):
        self.formStash = formStash
        self.getcreate_args = {}

    def require_new(self):
        formStash = self.formStash
        acme_account_provider_id = formStash.results.get(
            "acme_account_provider_id", None
        )
        if acme_account_provider_id is None:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field="acme_account_provider_id", message="No provider submitted."
            )

        getcreate_args = {
            "acme_account_provider_id": acme_account_provider_id,
            "contact": formStash.results["contact"],
        }
        self.getcreate_args = decode_args(getcreate_args)

    def require_upload(self):
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

        getcreate_args = {}
        if formStash.results["contact"] is not None:
            getcreate_args["contact"] = formStash.results["contact"]

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


class PrivateKeyUploadParser(object):
    """
    this is NOT a complex upload to parse, but consolidating the code to be like the AccountKey
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
        formStash = self.formStash

        getcreate_args = {}

        if formStash.results["private_key_file_pem"] is not None:
            self.upload_type = "pem"
            self.private_key_pem = getcreate_args[
                "key_pem"
            ] = formhandling.slurp_file_field(formStash, "private_key_file_pem")

        self.getcreate_args = decode_args(getcreate_args)


class AccountKeySelection(object):
    selection = None
    upload_parsed = None  # instance of AccountKeyUploadParser or None
    AcmeAccountKey = None


class PrivateKeySelection(object):
    selection = None
    upload_parsed = None  # instance of AccountKeyUploadParser or None
    PrivateKey = None


def parse_AccountKeySelection(request, formStash, seek_selected=None):
    account_key_pem = None
    account_key_pem_md5 = None
    dbAcmeAccountKey = None
    is_global_default = None

    # handle the explicit-option
    accountKeySelection = AccountKeySelection()
    if seek_selected == "none":
        return accountKeySelection
    elif seek_selected == "account_key_file":
        # this will handle form validation and raise errors.
        parser = AccountKeyUploadParser(formStash)
        parser.require_upload()

        # update our object
        accountKeySelection.selection = "upload"
        accountKeySelection.upload_parsed = parser

        return accountKeySelection
    else:
        if seek_selected == "account_key_global_default":
            accountKeySelection.selection = "global_default"
            account_key_pem_md5 = formStash.results["account_key_global_default"]
            is_global_default = True
        elif seek_selected == "account_key_existing":
            accountKeySelection.selection = "existing"
            account_key_pem_md5 = formStash.results["account_key_existing"]
        elif seek_selected == "account_key_reuse":
            accountKeySelection.selection = "reuse"
            account_key_pem_md5 = formStash.results["account_key_reuse"]
        if not account_key_pem_md5:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=seek_selected, message="You did not provide a value"
            )
        dbAcmeAccountKey = lib_db.get.get__AcmeAccountKey__by_pemMd5(
            request.api_context, account_key_pem_md5, is_active=True
        )
        if not dbAcmeAccountKey:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=seek_selected,
                message="The selected AcmeAccountKey is not enrolled in the system.",
            )
        if is_global_default and not dbAcmeAccountKey.is_global_default:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=seek_selected,
                message="The selected AcmeAccountKey is not the current default.",
            )
        accountKeySelection.AcmeAccountKey = dbAcmeAccountKey
        return accountKeySelection
    # `formStash.fatal_form()` will raise `FormInvalid()`
    formStash.fatal_form("There was an error validating your form.")


def parse_PrivateKeySelection(request, formStash, seek_selected=None):
    private_key_pem = None
    private_key_pem_md5 = None
    dbPrivateKey = None
    is_global_default = None

    # handle the explicit-option
    privateKeySelection = PrivateKeySelection()
    if seek_selected == "none":
        return privateKeySelection
    elif seek_selected == "private_key_file":
        # this will handle form validation and raise errors.
        parser = PrivateKeyUploadParser(formStash)
        parser.require_upload()

        # update our object
        privateKeySelection.selection = "upload"
        privateKeySelection.upload_parsed = parser

        return privateKeySelection
    else:
        if seek_selected == "private_key_global_default":
            privateKeySelection.selection = "global_default"
            private_key_pem_md5 = formStash.results["private_key_global_default"]
            is_global_default = True
        elif seek_selected == "private_key_existing":
            privateKeySelection.selection = "existing"
            private_key_pem_md5 = formStash.results["private_key_existing"]
        elif seek_selected == "private_key_reuse":
            privateKeySelection.selection = "reuse"
            private_key_pem_md5 = formStash.results["private_key_reuse"]
        elif seek_selected == "private_key_generate":
            privateKeySelection.selection = "generate"
            return privateKeySelection
        elif seek_selected == "private_key_for_account_key":
            privateKeySelection.selection = "private_key_for_account_key"
            return privateKeySelection

        if not private_key_pem_md5:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=seek_selected, message="You did not provide a value"
            )
        dbPrivateKey = lib_db.get.get__PrivateKey__by_pemMd5(
            request.api_context, private_key_pem_md5, is_active=True
        )
        if not dbPrivateKey:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=seek_selected,
                message="The selected PrivateKey is not enrolled in the system.",
            )
        if is_global_default and not dbPrivateKey.is_global_default:
            # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
            formStash.fatal_field(
                field=seek_selected,
                message="The selected PrivateKey is not the current default.",
            )
        privateKeySelection.PrivateKey = dbPrivateKey
        return privateKeySelection

    # `formStash.fatal_form()` will raise `FormInvalid()`
    formStash.fatal_form("There was an error validating your form.")


def form_key_selection(request, formStash):
    accountKeySelection = parse_AccountKeySelection(
        request, formStash, seek_selected=formStash.results["account_key_option"],
    )
    if accountKeySelection.selection == "upload":
        key_create_args = accountKeySelection.upload_parsed.getcreate_args
        key_create_args["event_type"] = "AcmeAccountKey__insert"
        key_create_args[
            "acme_account_key_source_id"
        ] = model_utils.AcmeAccountKeySource.from_string("imported")
        (dbAcmeAccountKey, _is_created,) = lib_db.getcreate.getcreate__AcmeAccountKey(
            request.api_context, **key_create_args
        )
        accountKeySelection.AcmeAccountKey = dbAcmeAccountKey

    privateKeySelection = parse_PrivateKeySelection(
        request, formStash, seek_selected=formStash.results["private_key_option"],
    )

    if privateKeySelection.selection == "upload":
        key_create_args = privateKeySelection.upload_parsed.getcreate_args
        key_create_args["event_type"] = "PrivateKey__insert"
        key_create_args[
            "private_key_source_id"
        ] = model_utils.PrivateKeySource.from_string("imported")
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

    return (accountKeySelection, privateKeySelection)
