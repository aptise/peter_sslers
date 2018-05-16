from . import db as lib_db


# ==============================================================================


def parse_AccountKeyPem(request, formStash):
    account_key_pem = None
    if formStash.results['account_key_file'] is not None:
        account_key_pem = formStash.results['account_key_file'].file.read()
    else:
        account_key_pem_md5 = None
        is_default = False
        field_source = None
        if formStash.results['account_key_default'] is not None:
            account_key_pem_md5 = formStash.results['account_key_default']
            is_default = True
            field_source = 'account_key_default'
        elif formStash.results['account_key_existing'] is not None:
            account_key_pem_md5 = formStash.results['account_key_existing']
            field_source = 'account_key_existing'
        if not account_key_pem_md5:
            raise ValueError("form validation should prevent this condition")
        dbAccountKey = lib_db.get.get__SslLetsEncryptAccountKey__by_pemMd5(
            request.api_context, account_key_pem_md5, default_only=is_default, is_active=True,
        )
        if not dbAccountKey:
            formStash.set_error(field=field_source, 
                                message="this account key is not tracked.",
                                raise_FormInvalid=True,
                                )
        account_key_pem = dbAccountKey.key_pem
    return account_key_pem


def parse_PrivateKeyPem(request, formStash):
    private_key_pem = None
    if formStash.results['private_key_file'] is not None:
        private_key_pem = formStash.results['private_key_file'].file.read()
    else:
        private_key_pem_md5 = None
        is_default = False
        field_source = None
        if formStash.results['private_key_default'] is not None:
            private_key_pem_md5 = formStash.results['private_key_default']
            is_default = True
            field_source = 'private_key_default'
        elif formStash.results['private_key_existing'] is not None:
            private_key_pem_md5 = formStash.results['private_key_existing']
            field_source = 'private_key_existing'
        if not private_key_pem_md5:
            raise ValueError("form validation should prevent this condition")
        dbPrivateKey = lib_db.get.get__SslPrivateKey__by_pemMd5(
            request.api_context, private_key_pem_md5, default_only=is_default, is_active=True
        )
        if not dbPrivateKey:
            formStash.set_error(field=field_source, 
                                message="this private key is not tracked.",
                                raise_FormInvalid=True,
                                )
        private_key_pem = dbPrivateKey.key_pem
    return private_key_pem
