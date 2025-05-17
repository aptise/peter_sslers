from peter_sslers.lib.db.update import update_AcmeAccount__account_url


def update_AcmeAccount_from_new_duplicate(
    ctx: "ApiContext",
    dbAcmeAccountTarget: "AcmeAccount",
    dbAcmeAccountDuplicate: "AcmeAccount",
) -> bool:
    """
    This function was developed for an early test harness,
    when acme account urls were often reused/reassigned due to pebble losing
    state.  Originally this would be triggered only when we create a new
    account.

    It has been very difficult to find situations where this could actually
    happen.  A current test case requires re-assigning an account key from
    one existing account to another.

    Because this is so unlikely and rare, the function has been archived
    outside of the active code

    ----


    Invoke this to Transfer the duplicate `AcmeAccount`'s information onto the original account

    ONLY INVOKE THIS ON A NEWLY CREATED DUPLICATE

    Account Fields:
        - account_url
        - terms_of_service
    """
    if dbAcmeAccountTarget.id == dbAcmeAccountDuplicate.id:
        raise ValueError("The Target and Duplicate `AcmeAccount` must be different")

    # make sure this is the right provider
    if dbAcmeAccountTarget.acme_server_id != dbAcmeAccountDuplicate.acme_server_id:
        raise ValueError("New Account `deduplication` requires a single `AcmeServer`")

    with ctx.dbSession.no_autoflush:
        log.info("Attempting to Transfer the following:")
        log.info("TARGET record:")
        log.info(" dbAcmeAccountTarget.id", dbAcmeAccountTarget.id)
        log.info(" dbAcmeAccountTarget.account_url", dbAcmeAccountTarget.account_url)
        log.info(
            " dbAcmeAccountTarget.acme_account_key.id",
            dbAcmeAccountTarget.acme_account_key.acme_account_id,
        )
        log.info("SOURCE record:")
        log.info(" dbAcmeAccountDuplicate.id", dbAcmeAccountDuplicate.id)
        log.info(
            " dbAcmeAccountDuplicate.account_url", dbAcmeAccountDuplicate.account_url
        )
        log.info(
            " dbAcmeAccountDuplicate.acme_account_key.id",
            dbAcmeAccountDuplicate.acme_account_key.acme_account_id,
        )

        # stash & clear the account_url
        account_url = dbAcmeAccountDuplicate.account_url
        account_url_sha256 = dbAcmeAccountDuplicate.account_url
        update_AcmeAccount__account_url(
            ctx, dbAcmeAccount=dbAcmeAccountDuplicate, account_url=None
        )
        ctx.dbSession.flush([dbAcmeAccountDuplicate])

        # Transfer the Account fields:
        # PART-1 this will fail; see part 2
        update_AcmeAccount__account_url(
            ctx, dbAcmeAccount=dbAcmeAccountDuplicate, account_url=account_url
        )
        dbAcmeAccountTarget.terms_of_service = dbAcmeAccountDuplicate.terms_of_service
        ctx.dbSession.flush([dbAcmeAccountTarget])
        # # PART-2 the above was descoped onto this:
        # update_AcmeAccount__terms_of_service(ctx, dbAcmeAccount, acme_tos)

        # Transfer the AcmeAccountKey
        # alias the keys
        dbAcmeAccountKey_old = dbAcmeAccountTarget.acme_account_key
        dbAcmeAccountKey_new = dbAcmeAccountDuplicate.acme_account_key
        if not dbAcmeAccountKey_new.is_active:
            raise ValueError(
                "the Duplicate AcmeAccount's AcmeAccountKey should be active!"
            )
        # Step 1 - Disable the Target's OLD key
        dbAcmeAccountKey_old.is_active = None  # False violates the unique index

        # Step 2: ReAssociate the NEW key
        dbAcmeAccountKey_new.acme_account_id = dbAcmeAccountTarget.id
        dbAcmeAccountTarget.acme_account_key = dbAcmeAccountKey_new
        ctx.dbSession.flush()

        # now, handle the OperationsObject logs:
        # first, get all the logs for the Duplicate account
        logs = (
            ctx.dbSession.query(model_objects.OperationsObjectEvent)
            .filter(
                model_objects.OperationsObjectEvent.acme_account_id
                == dbAcmeAccountDuplicate.id
            )
            .all()
        )
        for _log in logs:
            if _log.acme_account_key_id == dbAcmeAccountKey_new.id:
                # if the record references the new key, upgrade the account id to the Target
                _log.acme_account_id = dbAcmeAccountTarget.id
            elif _log.acme_account_key_id is None:
                # if the record does not mention the key, it is safe to delete
                ctx.dbSession.delete(_log)
            else:
                raise ValueError("this should not happen")
        ctx.dbSession.flush()

        # finally, delete the duplicate
        ctx.dbSession.delete(dbAcmeAccountDuplicate)
        ctx.dbSession.flush()

    return True
