from . import db as lib_db
from ..models import models


# ==============================================================================


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

    def require_upload(self):
        formStash = self.formStash

        # -------------------
        # do a quick parse...
        requirements_either_or = (('account_key_file_pem', ),
                                  ('account_key_file_le_meta', 'account_key_file_le_pkey', 'account_key_file_le_reg', )
                                  )
        failures = []
        passes = []
        for idx, option_set in enumerate(requirements_either_or):
            option_set_results = [True if formStash.results[option_set_item] is not None else False
                                  for option_set_item in option_set
                                  ]
            # if we have any item, we need all of them
            if any(option_set_results):
                if not all(option_set_results):
                    failures.append("If any of %s is provided, all must be provided." % str(option_set))
                else:
                    passes.append(idx)

        if (len(passes) != 1) or failures:
            formStash.set_error(field="Error_Main",
                                message="You must upload `account_key_file_pem` or all of (`account_key_file_le_meta`, `account_key_file_le_pkey`, `account_key_file_le_reg`).",
                                raise_FormInvalid=True,
                                )

        # -------------------

        # validate the provider option
        # will be None unless a pem is uploaded
        # required for PEM, ignored otherwise
        acme_account_provider_id = formStash.results.get('acme_account_provider_id', None)
        if formStash.results.get('account_key_file_pem') is not None:
            if acme_account_provider_id is None:
                formStash.set_error(field="acme_account_provider_id",
                                    message="No provider submitted.",
                                    raise_FormInvalid=True,
                                    )
            if acme_account_provider_id not in models.AcmeAccountProvider.registry.keys():
                formStash.set_error(field="acme_account_provider_id",
                                    message="Invalid provider submitted.",
                                    raise_FormInvalid=True,
                                    )

        getcreate_args = {}
        if formStash.results['account_key_file_pem'] is not None:
            self.upload_type = 'pem'
            self.acme_account_provider_id = getcreate_args['acme_account_provider_id'] = acme_account_provider_id
            self.account_key_pem = getcreate_args['key_pem'] = formStash.results['account_key_file_pem'].file.read()
        else:
            # note that we use `jsonS` to indicate a string
            self.le_meta_jsons = getcreate_args['le_meta_jsons'] = formStash.results['account_key_file_le_meta'].file.read()
            self.le_pkey_jsons = getcreate_args['le_pkey_jsons'] = formStash.results['account_key_file_le_pkey'].file.read()
            self.le_reg_jsons = getcreate_args['le_reg_jsons'] = formStash.results['account_key_file_le_reg'].file.read()

        self.getcreate_args = getcreate_args


class AccountKeySelection(object):
    selection = None  # upload,
    upload_parsed = None  # instance of AccountKeyUploadParser or None
    SslAcmeAccountKey = None


def parse_AccountKeySelection(request, formStash, seek_selected=None):
    account_key_pem = None
    account_key_pem_md5 = None
    dbAccountKey = None
    is_default = None
    # handle the explicit-option

    accountKeySelection = AccountKeySelection()
    if seek_selected == 'account_key_file':
        # this will handle form validation and raise errors.
        parser = AccountKeyUploadParser(formStash)
        parser.require_upload()

        # update our object
        accountKeySelection.selection = 'upload'
        accountKeySelection.upload_parsed = parser

        return accountKeySelection
    else:
        if seek_selected == 'account_key_default':
            accountKeySelection.selection = 'default'
            account_key_pem_md5 = formStash.results['account_key_default']
            is_default = True
        elif seek_selected == 'account_key_existing':
            accountKeySelection.selection = 'existing'
            account_key_pem_md5 = formStash.results['account_key_existing']
        elif seek_selected == 'account_key_reuse':
            accountKeySelection.selection = 'reuse'
            account_key_pem_md5 = formStash.results['account_key_reuse']
        if not account_key_pem_md5:
            formStash.set_error(field=seek_selected,
                                message="You did not provide a value",
                                raise_FormInvalid=True,
                                )
        dbAccountKey = lib_db.get.get__SslAcmeAccountKey__by_pemMd5(
            request.api_context,
            account_key_pem_md5,
            is_active=True,
        )
        if not dbAccountKey:
            formStash.set_error(field=seek_selected,
                                message="This account key is not tracked.",
                                raise_FormInvalid=True,
                                )
        if is_default and not dbAccountKey.is_default:
            formStash.set_error(field=seek_selected,
                                message="This account key is not the default any more.",
                                raise_FormInvalid=True,
                                )
        accountKeySelection.SslAcmeAccountKey = dbAccountKey
        return accountKeySelection
    formStash.set_error(field='Error_Main',
                        message="There was an error Validating your form.",
                        raise_FormInvalid=True,
                        )


def parse_PrivateKeyPem(request, formStash, seek_selected=None):
    private_key_pem = None
    private_key_pem_md5 = None
    dbPrivateKey = None
    # handle the explicit-option
    if seek_selected:
        if seek_selected == 'private_key_file':
            try:
                private_key_pem = formStash.results['private_key_file'].file.read()
            except Exception as e:
                # we'll still error out...'
                pass
            if not private_key_pem:
                formStash.set_error(field='private_key_file',
                                    message="There was an error uploading your file.",
                                    raise_FormInvalid=True,
                                    )
            return private_key_pem
        else:
            if seek_selected == 'private_key_existing':
                private_key_pem_md5 = formStash.results['private_key_existing']
            elif seek_selected == 'private_key_reuse':
                private_key_pem_md5 = formStash.results['private_key_reuse']
            if not private_key_pem_md5:
                formStash.set_error(field=seek_selected,
                                    message="You did not provide a value",
                                    raise_FormInvalid=True,
                                    )
            dbPrivateKey = lib_db.get.get__SslPrivateKey__by_pemMd5(
                request.api_context,
                private_key_pem_md5,
                is_active=True,
            )
            if not dbPrivateKey:
                formStash.set_error(field=seek_selected,
                                    message="This private key is not tracked.",
                                    raise_FormInvalid=True,
                                    )
            return dbPrivateKey.key_pem
        formStash.set_error(field='Error_Main',
                            message="There was an error Validating your form.",
                            raise_FormInvalid=True,
                            )
    # handle the best-option now
    if formStash.results['private_key_file'] is not None:
        private_key_pem = formStash.results['private_key_file'].file.read()
    else:
        private_key_pem_md5 = None
        field_source = None
        if formStash.results['private_key_existing'] is not None:
            private_key_pem_md5 = formStash.results['private_key_existing']
            field_source = 'private_key_existing'
        if not private_key_pem_md5:
            raise ValueError("form validation should prevent this condition")
        dbPrivateKey = lib_db.get.get__SslPrivateKey__by_pemMd5(
            request.api_context,
            private_key_pem_md5,
            is_active=True,
        )
        if not dbPrivateKey:
            formStash.set_error(field=field_source,
                                message="this private key is not tracked.",
                                raise_FormInvalid=True,
                                )
        private_key_pem = dbPrivateKey.key_pem
    return private_key_pem
