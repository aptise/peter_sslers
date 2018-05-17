from . import db as lib_db


# ==============================================================================


def parse_AccountKeyPem(request, formStash, seek_selected=None):
    account_key_pem = None
    account_key_pem_md5 = None
    dbAccountKey = None
    is_default = None
    # handle the explicit-option
    if seek_selected:
        if seek_selected == 'account_key_file':
            try:
                account_key_pem = formStash.results['account_key_file'].file.read()
            except:
                # we'll still error out...'
                pass
            if not account_key_pem:
                formStash.set_error(field='account_key_file', 
                                    message="There was an error uploading your file.",
                                    raise_FormInvalid=True,
                                    )
            return account_key_pem
        else:
            if seek_selected == 'account_key_default':
                account_key_pem_md5 = formStash.results['account_key_default']
                is_default = True
            elif seek_selected == 'account_key_existing':
                account_key_pem_md5 = formStash.results['account_key_existing']
            elif seek_selected == 'account_key_reuse':
                account_key_pem_md5 = formStash.results['account_key_reuse']
            if not account_key_pem_md5:
                formStash.set_error(field=seek_selected, 
                                    message="You did not provide a value",
                                    raise_FormInvalid=True,
                                    )
            dbAccountKey = lib_db.get.get__SslLetsEncryptAccountKey__by_pemMd5(
                request.api_context,
                account_key_pem_md5,
                is_active=True,
            )
            if not dbAccountKey:
                formStash.set_error(field=field_source, 
                                    message="This account key is not tracked.",
                                    raise_FormInvalid=True,
                                    )
            if is_default and not dbAccountKey.is_default:
                formStash.set_error(field=field_source, 
                                    message="This account key is not the default any more.",
                                    raise_FormInvalid=True,
                                    )
            return dbAccountKey.key_pem
        formStash.set_error(field='Error_Main', 
                            message="There was an error Validating your form.",
                            raise_FormInvalid=True,
                            )
    # handle the best-option now
    if formStash.results['account_key_file'] is not None:
        account_key_pem = formStash.results['account_key_file'].file.read()
    else:
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
            request.api_context,
            account_key_pem_md5,
            is_active=True,
        )
        if not dbAccountKey:
            formStash.set_error(field=field_source, 
                                message="this account key is not tracked.",
                                raise_FormInvalid=True,
                                )
        if is_default and not dbAccountKey.is_default:
            formStash.set_error(field=field_source, 
                                message="This account key is not the default any more.",
                                raise_FormInvalid=True,
                                )
        account_key_pem = dbAccountKey.key_pem
    return account_key_pem


def parse_PrivateKeyPem(request, formStash, seek_selected=None):
    private_key_pem = None
    private_key_pem_md5 = None
    dbPrivateKey = None
    # handle the explicit-option
    if seek_selected:
        if seek_selected == 'private_key_file':
            try:
                private_key_pem = formStash.results['private_key_file'].file.read()
            except:
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
                formStash.set_error(field=field_source, 
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
