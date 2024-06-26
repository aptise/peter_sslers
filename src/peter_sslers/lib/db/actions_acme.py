# stdlib
import datetime
import logging
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
import cert_utils

# localapp
from .create import create__AcmeOrder
from .create import create__AcmeOrderSubmission
from .create import create__CertificateRequest
from .create import create__CertificateSigned
from .create import create__PrivateKey
from .get import get__AcmeAccount__by_account_url
from .get import get__AcmeAccountKey__by_key_pem
from .get import get__AcmeAuthorizations__by_ids
from .get import get__AcmeChallenges__by_DomainId__active
from .get import get__AcmeOrder__by_order_url
from .getcreate import getcreate__AcmeAuthorization
from .getcreate import getcreate__AcmeAuthorizationUrl
from .getcreate import getcreate__AcmeChallenges_via_payload
from .getcreate import getcreate__CertificateCAChain__by_pem_text
from .getcreate import getcreate__CertificateSigned
from .getcreate import getcreate__PrivateKey_for_AcmeAccount
from .getcreate import getcreate__UniqueFQDNSet__by_domains
from .getcreate import process__AcmeAuthorization_payload
from .logger import AcmeLogger
from .logger import log__OperationsEvent
from .update import update_AcmeAuthorization_from_payload
from .. import errors
from ..exceptions import AcmeAccountNeedsPrivateKey
from ..exceptions import PrivateKeyOk
from ..exceptions import ReassignedPrivateKey
from ...lib import acme_v2
from ...model import objects as model_objects
from ...model import utils as model_utils

if TYPE_CHECKING:
    from tempfile import _TemporaryFileWrapper
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeChallenge
    from ...model.objects import AcmeOrder
    from ...model.objects import AcmeAuthorization
    from ...model.objects import PrivateKey
    from ..acme_v2 import AcmeOrderRFC
    from ..acme_v2 import AuthenticatedUser
    from ..utils import ApiContext


# from .logger import _log_object_event

# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

TEST_CERTIFICATE_CHAIN = True

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeAccount_AcmeV2_register(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    account_key_path: Optional[str] = None,
) -> "AuthenticatedUser":
    """
    Registers an AcmeAccount against the LetsEncrypt ACME Directory

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param account_key_path: (optional) If there is a tempfile for the
        `dbAcmeAccount`

    !!! WARNING !!!

    If `account_key_path` is not provided, the ACME library will be unable to
    perform any operations after authentication.
    """
    try:
        if not dbAcmeAccount.contact:
            raise ValueError("no `contact`")

        acmeLogger = AcmeLogger(ctx, dbAcmeAccount=dbAcmeAccount)

        # create account, update contact details (if any), and set
        # the global key identifier
        # result is either: `new-account` or `existing-account`
        # failing will raise an exception
        authenticatedUser = acme_v2.AuthenticatedUser(
            acmeLogger=acmeLogger,
            acmeAccount=dbAcmeAccount,
            account_key_path=account_key_path,
            log__OperationsEvent=log__OperationsEvent,
        )
        authenticatedUser.authenticate(ctx, contact=dbAcmeAccount.contact)

        # update based off the ACME service
        # the server's TOS should take precedence
        acme_tos = authenticatedUser.acme_directory["meta"]["termsOfService"]
        if acme_tos:
            if acme_tos != dbAcmeAccount.terms_of_service:
                dbAcmeAccount.terms_of_service = acme_tos
        assert authenticatedUser._api_account_headers
        acme_account_url = authenticatedUser._api_account_headers["Location"]
        if acme_account_url != dbAcmeAccount.account_url:
            # this is a bit tricky
            # this library defends against most duplicate accounts by checking
            # the account key for duplication
            # there are two situations, however, in which a duplicate account
            # can get past the defenses:
            # 1) On testing scenarios, the pebble server may lose state and
            #    reassign the account_url to a different account.
            # 2) In production scenarios, an account key may be changed one or
            #    more times, and this library is not notified of the changes
            #    in those situations, it becomes difficult to reconcile what is
            #    happening. nevertheless we should try
            _dbAcmeAccountOther = get__AcmeAccount__by_account_url(
                ctx, acme_account_url
            )
            if _dbAcmeAccountOther and (_dbAcmeAccountOther.id != dbAcmeAccount.id):
                # another AcmeAccount is registered to this account_url
                # update this after the get, so it's not flushed and it
                # does not trigger an IntegrityError
                dbAcmeAccount.account_url = acme_account_url

                # args[0] MUST be the duplicate AcmeAccount
                raise errors.AcmeDuplicateAccount(_dbAcmeAccountOther)

            # this is now safe to set
            dbAcmeAccount.account_url = acme_account_url
        return authenticatedUser
    except Exception as exc:  # noqa: F841
        raise


def do__AcmeAccount_AcmeV2_authenticate(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    account_key_path: Optional[str] = None,
    onlyReturnExisting: Optional[bool] = None,
) -> "AuthenticatedUser":
    """
    Authenticates an AcmeAccount against the LetsEncrypt ACME Directory

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param account_key_path: (optional) If there is a tempfile for the
        `dbAcmeAccount`
    :param onlyReturnExisting: (optional) Boolean. passed on to `:meth:authenticate`.

    !!! WARNING !!!

    If `account_key_path` is not provided, the ACME library will be unable to
    perform any operations after authentication.
    """
    acmeLogger = AcmeLogger(ctx, dbAcmeAccount=dbAcmeAccount)

    # unless `onlyReturnExisting` is True, this will
    # create an account, update contact details (if any), and set
    # the global key identifier
    # result is either: `new-account` or `existing-account`
    # failing will raise an exception
    #
    # if `onlyReturnExisting` is True,
    authenticatedUser = acme_v2.AuthenticatedUser(
        acmeLogger=acmeLogger,
        acmeAccount=dbAcmeAccount,
        account_key_path=account_key_path,
        log__OperationsEvent=log__OperationsEvent,
    )
    authenticatedUser.authenticate(ctx, onlyReturnExisting=onlyReturnExisting)
    return authenticatedUser


def do__AcmeV2_AcmeAccount__deactivate(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    transaction_commit: Optional[bool] = None,
) -> "AuthenticatedUser":
    """
    Deactivates an AcmeAccount against the LetsEncrypt ACME Directory

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param transaction_commit: (required) Boolean. User must indicate they know
        this will commit, as 3rd party API can not be rolled back.
    """
    if transaction_commit is not True:
        raise ValueError("must invoke this knowing it will commit")

    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("AcmeAccount__deactivate"),
    )

    acmeLogger = AcmeLogger(ctx, dbAcmeAccount=dbAcmeAccount)

    # create account, update contact details (if any), and set
    # the global key identifier
    # result is either: `new-account` or `existing-account`
    # failing will raise an exception
    authenticatedUser = acme_v2.AuthenticatedUser(
        acmeLogger=acmeLogger,
        acmeAccount=dbAcmeAccount,
        log__OperationsEvent=log__OperationsEvent,
    )
    authenticatedUser.authenticate(ctx)
    is_did_deactivate = authenticatedUser.deactivate(ctx, transaction_commit=True)
    if is_did_deactivate:
        if transaction_commit:
            ctx.pyramid_transaction_commit()
    return authenticatedUser


def do__AcmeV2_AcmeAccount__key_change(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    key_pem_new: Optional[str] = None,
    transaction_commit: Optional[bool] = None,
) -> "AuthenticatedUser":
    """
    Deactivates an AcmeAccount against the LetsEncrypt ACME Directory

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param key_pem_new: (optional) The new key PEM form, will be autogenerated if empty
    :param transaction_commit: (required) Boolean. User must indicate they know
        this will commit, as 3rd party API can not be rolled back.
    """
    if transaction_commit is not True:
        raise ValueError("must invoke this knowing it will commit")

    assert ctx.timestamp

    dbOperationsEvent_AcmeAccount = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("AcmeAccount__key_change"),
    )

    if key_pem_new is not None:
        key_pem_new = cert_utils.cleanup_pem_text(key_pem_new)
        acme_account_key_source_id = model_utils.AcmeAccountKeySource.from_string(
            "imported"
        )
    else:
        key_pem_new = cert_utils.new_account_key()  # rsa_bits=None
        acme_account_key_source_id = model_utils.AcmeAccountKeySource.from_string(
            "generated"
        )
    dbAcmeAccountKeyNew = get__AcmeAccountKey__by_key_pem(ctx, key_pem_new)
    if dbAcmeAccountKeyNew:
        raise errors.ConflictingObject(
            (dbAcmeAccountKeyNew, "The new key already exists")
        )

    key_pem_new_md5 = cert_utils.utils.md5_text(key_pem_new)

    # scoping
    key_technology = None
    acckey__spki_sha256 = None

    _tmpfile_new = None
    try:
        if cert_utils.NEEDS_TEMPFILES:
            _tmpfile_new = cert_utils.new_pem_tempfile(key_pem_new)

        # validate + grab the technology
        key_technology = cert_utils.validate_key(
            key_pem=key_pem_new,
            key_pem_filepath=_tmpfile_new.name if _tmpfile_new else None,
        )

        # grab the spki
        acckey__spki_sha256 = cert_utils.parse_key__spki_sha256(
            key_pem=key_pem_new,
            key_pem_filepath=_tmpfile_new.name if _tmpfile_new else None,
        )
        assert key_technology
    finally:
        if _tmpfile_new is not None:
            _tmpfile_new.close()

    dbOperationsEvent_AcmeAccountKey_new = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("AcmeAccountKey__create"),
        dbOperationsEvent_child_of=dbOperationsEvent_AcmeAccount,
    )
    dbOperationsEvent_AcmeAccountKey_old = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("AcmeAccountKey__mark__inactive"),
        dbOperationsEvent_child_of=dbOperationsEvent_AcmeAccount,
    )

    # then, create the new AcmeAccountKey
    # IMPORTANT: with `.is_active = None`
    dbAcmeAccountKey_new = model_objects.AcmeAccountKey()
    dbAcmeAccountKey_new.is_active = None
    dbAcmeAccountKey_new.acme_account_id = dbAcmeAccount.id
    dbAcmeAccountKey_new.timestamp_created = ctx.timestamp
    dbAcmeAccountKey_new.key_pem = key_pem_new
    dbAcmeAccountKey_new.key_pem_md5 = key_pem_new_md5
    dbAcmeAccountKey_new.key_technology_id = model_utils.KeyTechnology.from_string(
        key_technology
    )
    dbAcmeAccountKey_new.spki_sha256 = acckey__spki_sha256
    dbAcmeAccountKey_new.acme_account_key_source_id = acme_account_key_source_id
    dbAcmeAccountKey_new.operations_event_id__created = (
        dbOperationsEvent_AcmeAccountKey_new.id
    )
    ctx.dbSession.add(dbAcmeAccountKey_new)
    ctx.dbSession.flush(objects=[dbAcmeAccountKey_new])

    acmeLogger = AcmeLogger(ctx, dbAcmeAccount=dbAcmeAccount)

    # create account, update contact details (if any), and set
    # the global key identifier
    # result is either: `new-account` or `existing-account`
    # failing will raise an exception
    authenticatedUser = acme_v2.AuthenticatedUser(
        acmeLogger=acmeLogger,
        acmeAccount=dbAcmeAccount,
        log__OperationsEvent=log__OperationsEvent,
    )
    authenticatedUser.authenticate(ctx)
    is_did_keychange = authenticatedUser.key_change(
        ctx, dbAcmeAccountKey_new, transaction_commit=True
    )
    if is_did_keychange:
        if transaction_commit:
            ctx.pyramid_transaction_commit()

    return authenticatedUser


def new_Authenticated_user(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
) -> Tuple["AuthenticatedUser", Optional["_TemporaryFileWrapper"]]:
    """
    helper function to authenticate the user


    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    """
    account_key_pem = dbAcmeAccount.acme_account_key.key_pem

    tmpfile_account = None
    if cert_utils.NEEDS_TEMPFILES:
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)

    # register the account / ensure that it is registered
    # the authenticatedUser will have a `logger.AcmeLogger` object as the
    # `.acmeLogger` attribtue
    # the `acmeLogger` may need to have the `AcmeOrder` registered
    authenticatedUser = do__AcmeAccount_AcmeV2_authenticate(
        ctx,
        dbAcmeAccount,
        account_key_path=tmpfile_account.name if tmpfile_account else None,
    )
    return (authenticatedUser, tmpfile_account)


def update_AcmeAuthorization_status(
    ctx: "ApiContext",
    dbAcmeAuthorization: "AcmeAuthorization",
    status_text: str,
    timestamp: Optional[datetime.datetime] = None,
    transaction_commit: Optional[bool] = None,
    is_via_acme_sync: Optional[bool] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAuthorization: (required) A
        :class:`model.objects.AcmeAuthorization` object
    :param status_text: (required) The status_text for the order
    :param timestamp: (required) `datetime.datetime`.
    :param transaction_commit: (required) Boolean. User must indicate they know
        this will commit, as 3rd party API can not be rolled back.
    :param is_via_acme_sync: (optional) Boolean. Is this operation based off a
        direct ACME Server sync?
    """
    if transaction_commit is not True:
        raise ValueError("must invoke this knowing it will commit")
    _edited = False
    status_text = status_text.lower()
    if dbAcmeAuthorization.acme_status_authorization != status_text:
        dbAcmeAuthorization.acme_status_authorization_id = (
            model_utils.Acme_Status_Authorization.from_string(status_text)
        )
        _edited = True
    if _edited:
        if not timestamp:
            timestamp = datetime.datetime.utcnow()
        dbAcmeAuthorization.timestamp_updated = timestamp
        if (
            dbAcmeAuthorization.acme_status_authorization_id
            == model_utils.Acme_Status_Authorization.from_string("deactivated")
        ):
            dbAcmeAuthorization.timestamp_deactivated = timestamp
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def update_AcmeChallenge_status(
    ctx: "ApiContext",
    dbAcmeChallenge: "AcmeChallenge",
    status_text: str,
    timestamp: Optional[datetime.datetime] = None,
    transaction_commit: Optional[bool] = None,
    is_via_acme_sync: Optional[bool] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge`
        object
    :param status_text: (required) The status_text for the order
    :param timestamp: (required) `datetime.datetime`.
    :param transaction_commit: (required) Boolean. User must indicate they know
        this will commit, as 3rd party API can not be rolled back.
    :param is_via_acme_sync: (optional) Boolean. Is this operation based off a
        direct ACME Server sync?
    """
    if transaction_commit is not True:
        raise ValueError("must invoke this knowing it will commit")
    _edited = False
    status_text = status_text.lower()
    if dbAcmeChallenge.acme_status_challenge != status_text:
        dbAcmeChallenge.acme_status_challenge_id = (
            model_utils.Acme_Status_Challenge.from_string(status_text)
        )
        _edited = True
    if _edited:
        if not timestamp:
            timestamp = datetime.datetime.utcnow()
        dbAcmeChallenge.timestamp_updated = timestamp
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def updated_AcmeOrder_status(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
    acme_order_object: Dict,
    acme_order_processing_status_id: Optional[int] = None,
    is_processing_False: Optional[bool] = None,
    timestamp: Optional[datetime.datetime] = None,
    transaction_commit: Optional[bool] = None,
    is_via_acme_sync: Optional[bool] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param acme_order_object: (required) An RFC compliant dict; must at least
        have `status`
    :param acme_order_processing_status_id: (optional) If provided, update the
        `acme_order_processing_status_id` of the order
    :param is_processing_False: (optional) if True, set `is_processing` to False.
    :param timestamp: (required) `datetime.datetime`.
    :param transaction_commit: (required) Boolean. User must indicate they know
        this will commit, as 3rd party API can not be rolled back.
    :param is_via_acme_sync: (optional) Boolean. Is this operation based off a
        direct ACME Server sync?
    """
    if transaction_commit is not True:
        raise ValueError("must invoke this knowing it will commit")
    _edited = False
    status_text = acme_order_object.get("status", "").lower()
    if dbAcmeOrder.acme_status_order != status_text:
        try:
            dbAcmeOrder.acme_status_order_id = (
                model_utils.Acme_Status_Order.from_string(status_text)
            )
        except KeyError:
            dbAcmeOrder.acme_status_order_id = (
                model_utils.Acme_Status_Order.from_string("*406*")
            )
        _edited = True
    if status_text in model_utils.Acme_Status_Order.OPTIONS_UPDATE_DEACTIVATE:
        if dbAcmeOrder.is_processing is True:
            dbAcmeOrder.is_processing = None
            _edited = True
    if acme_order_processing_status_id is not None:
        if (
            dbAcmeOrder.acme_order_processing_status_id
            != acme_order_processing_status_id
        ):
            dbAcmeOrder.acme_order_processing_status_id = (
                acme_order_processing_status_id
            )
            _edited = True
    if is_processing_False:
        if dbAcmeOrder.is_processing is True:
            dbAcmeOrder.is_processing = False
            _edited = True

    certificate_url = acme_order_object.get("certificate")
    if certificate_url and not dbAcmeOrder.certificate_url:
        dbAcmeOrder.certificate_url = certificate_url
        _edited = True

    if _edited:
        if not timestamp:
            timestamp = datetime.datetime.utcnow()
        dbAcmeOrder.timestamp_updated = timestamp
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def updated_AcmeOrder_ProcessingStatus(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
    acme_status_order_id: Optional[int] = None,
    acme_order_processing_status_id: Optional[int] = None,
    timestamp: Optional[datetime.datetime] = None,
    transaction_commit: Optional[bool] = None,
    is_via_acme_sync: Optional[bool] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param acme_status_order_id: (optional) If provided, update the
        `acme_status_order_id` of the order
    :param acme_order_processing_status_id: (required) If provided, update the
        `acme_order_processing_status_id` of the order
    :param timestamp: (required) `datetime.datetime`.
    :param transaction_commit: (required) Boolean. User must indicate they know
        this will commit, as 3rd party API can not be rolled back.
    :param is_via_acme_sync: (optional) Boolean. Is this operation based off a
        direct ACME Server sync?
    """
    if transaction_commit is not True:
        raise ValueError("must invoke this knowing it will commit")
    _edited = False
    if acme_status_order_id is not None:
        if dbAcmeOrder.acme_status_order_id != acme_status_order_id:
            dbAcmeOrder.acme_status_order_id = acme_status_order_id
            _edited = True
            _status_text = model_utils.Acme_Status_Order.as_string(acme_status_order_id)
            if _status_text in model_utils.Acme_Status_Order.OPTIONS_UPDATE_DEACTIVATE:
                if dbAcmeOrder.is_processing is True:
                    dbAcmeOrder.is_processing = None
    if acme_order_processing_status_id is not None:
        if (
            dbAcmeOrder.acme_order_processing_status_id
            != acme_order_processing_status_id
        ):
            dbAcmeOrder.acme_order_processing_status_id = (
                acme_order_processing_status_id
            )
            _edited = True
    if _edited:
        if not timestamp:
            timestamp = datetime.datetime.utcnow()
        dbAcmeOrder.timestamp_updated = timestamp
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def _audit_AcmeChallenge_against_server_response(
    ctx: "ApiContext",
    dbAcmeChallenge: "AcmeChallenge",
    challenge_response: Dict,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge`
        object
    :param challenge_response: (required) The payload from the acme server
    """
    # the AcmeChallenge payload has the following info:
    # - url
    # - type
    # - token
    # - status

    # pretty much everything should match up
    # audit all fields EXCEPT status
    _mismatch = {}  # key = field; value=(expected, received)
    if dbAcmeChallenge.challenge_url != challenge_response["url"]:
        _mismatch["url"] = (dbAcmeChallenge.challenge_url, challenge_response["url"])
    if dbAcmeChallenge.token != challenge_response["token"]:
        _mismatch["token"] = (
            dbAcmeChallenge.challenge_url,
            challenge_response["token"],
        )
    if dbAcmeChallenge.acme_challenge_type != challenge_response["type"]:
        _mismatch["type"] = (
            dbAcmeChallenge.acme_challenge_type,
            challenge_response["type"],
        )
    if _mismatch:
        log.critical("Mismatch in AcmeChallenge(%s) sync:", dbAcmeChallenge.id)
        for k, v in _mismatch.items():
            log.critical("  . %s : %s | %s", (k, v[0], v[1]))
    return True


def disable_missing_AcmeAuthorization_AcmeChallenges(
    ctx: "ApiContext",
    dbAcmeAuthorization: "AcmeAuthorization",
    authorization_response: Dict,
    timestamp: Optional[datetime.datetime] = None,
    transaction_commit: Optional[bool] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAuthorization: (required) A
        :class:`model.objects.AcmeAuthorization` object
    :param authorization_response: (required) A dict that is the response from
        the AcmeServer
    :param timestamp: (required) `datetime.datetime`.
    :param transaction_commit: (required) Boolean. User must indicate they know
        this will commit, as 3rd party API can not be rolled back.
    """
    if transaction_commit is not True:
        raise ValueError("must invoke this knowing it will commit")
    _challenges_expected = {
        _chall.challenge_url: _chall for _chall in dbAcmeAuthorization.acme_challenges
    }
    if _challenges_expected:
        if not timestamp:
            timestamp = datetime.datetime.utcnow()
        _challenges_edited = False
        _status_410 = model_utils.Acme_Status_Challenge.from_string("*410*")
        for _chall_url in _challenges_expected.keys():
            if _chall_url not in authorization_response["challenges"]:
                _chall = _challenges_expected[_chall_url]
                _chall.acme_status_challenge_id = _status_410
                _chall.timestamp_updated = timestamp
                _challenges_edited = True
        if _challenges_edited:
            ctx.pyramid_transaction_commit()
    return True


def _AcmeV2_factory_AuthHandlers(
    ctx: "ApiContext",
    authenticatedUser: "AuthenticatedUser",
    dbAcmeOrder: "AcmeOrder",
) -> Callable:
    """
    This factory dynamically generates functions for handling an order's
    Authorization(s)

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authenticatedUser: (required) A
        :class:`acme_v2.AuthenticatedUser` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    """

    def handle_authorization_payload(
        authorization_url: str,
        authorization_response: Dict,
        dbAcmeAuthorization: Optional["AcmeAuthorization"] = None,
        transaction_commit: Optional[bool] = None,
    ):
        """
        :param authorization_url: (required) The URL of the ACME Directory's
            Authorization Object.
        :param authorization_response: (required) The JSON object corresponding
            to the ACME Directory's Authorization Object.
        :param dbAcmeAuthorization: (required) A
            :class:`model.objects.AcmeAuthorization` object for the
            authorization_url if it already exists
        :param transaction_commit: (required) Boolean. User must indicate they know
            this will commit, as 3rd party API can not be rolled back.

        the getcreate will do the following:
            create/update the Authorization object
            create/update the Challenge object
        """
        log.info(
            "_AcmeV2_factory_AuthHandlers.handle_authorization_payload( %s",
            authorization_url,
        )
        if transaction_commit is not True:
            raise ValueError("must invoke this knowing it will commit")

        if dbAcmeAuthorization is not None:
            if authorization_url != dbAcmeAuthorization.authorization_url:
                raise ValueError("`authorization_url` does not match")

        if dbAcmeAuthorization is None:
            # this will sync the payload via `update_AcmeAuthorization_from_payload`
            (
                dbAcmeAuthorization,
                _is_created,
            ) = getcreate__AcmeAuthorization(
                ctx,
                authorization_url=authorization_url,
                authorization_payload=authorization_response,
                authenticatedUser=authenticatedUser,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=transaction_commit,
            )
            if _is_created:
                raise errors.GarfieldMinusGarfield(
                    "the dbAcmeAuthorization should exist already"
                )
        else:
            _result = process__AcmeAuthorization_payload(
                ctx,
                authorization_payload=authorization_response,
                authenticatedUser=authenticatedUser,
                dbAcmeAuthorization=dbAcmeAuthorization,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=transaction_commit,
            )

        log.info(") handle_authorization_payload(")
        return dbAcmeAuthorization

    return handle_authorization_payload


def _AcmeV2_AcmeOrder__process_authorizations(
    ctx: "ApiContext",
    authenticatedUser,
    dbAcmeOrder: "AcmeOrder",
    acmeOrderRfcObject: "AcmeOrderRFC",
) -> Optional[bool]:
    """
    Consolidated AcmeOrder routine for processing multiple Authorizations

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authenticatedUser: (required) A
        :class:`acme_v2.AuthenticatedUser` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param acmeRfcOrder: (required) a :class:`acme_v2.AcmeOrderRFC` instance
    """
    handle_authorization_payload = _AcmeV2_factory_AuthHandlers(
        ctx, authenticatedUser, dbAcmeOrder
    )

    _task_finalize_order = None
    _order_status = acmeOrderRfcObject.rfc_object["status"]
    if _order_status == "pending":
        # if we are retrying an order, we can try to handle it
        try:
            _handled = authenticatedUser.acme_order_process_authorizations(
                ctx,
                acmeOrderRfcObject=acmeOrderRfcObject,
                dbAcmeOrder=dbAcmeOrder,
                handle_authorization_payload=handle_authorization_payload,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
                updated_AcmeOrder_ProcessingStatus=updated_AcmeOrder_ProcessingStatus,
                transaction_commit=True,
            )
            if not _handled:
                raise ValueError("Order Authorizations failed")
            _task_finalize_order = True
        except errors.AcmeAuthorizationFailure as exc:
            # if an Authorization fails, the entire order fails
            (
                acmeOrderRfcObject,
                dbAcmeOrderEventLogged,
            ) = authenticatedUser.acme_order_load(
                ctx,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acmeOrderRfcObject.rfc_object,
                acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_completed_failure,
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )
            assert ctx.request
            if ctx.request.registry.settings["app_settings"][
                "cleanup_pending_authorizations"
            ]:
                log.info(
                    "AcmeOrder failed, going to deactivate remaining authorizations"
                )
                do__AcmeV2_AcmeOrder__acme_server_deactivate_authorizations(
                    ctx,
                    dbAcmeOrder=dbAcmeOrder,
                    authenticatedUser=authenticatedUser,
                )

            raise errors.AcmeOrderFatal(
                "`pending` AcmeOrder failed an AcmeAuthorization"
            )
    else:
        if _order_status == "invalid":
            # order abandoned
            raise errors.AcmeOrderFatal("Order Already Abandoned")
        elif _order_status == "ready":
            # requirements/challenges fulfilled
            _task_finalize_order = True
        elif _order_status == "processing":
            # The certificate is being issued.
            # Send a POST-as-GET request after the time given in the Retry-After header field of the response, if any.
            raise errors.AcmeOrderProcessing()
        elif _order_status == "valid":
            # The server has issued the certificate and provisioned its URL to the "certificate" field of the order
            raise errors.AcmeOrderValid()
        else:
            raise ValueError("unsure how to handle this status: `%s`" % _order_status)
    return _task_finalize_order


def do__AcmeV2_AcmeAuthorization__acme_server_deactivate(
    ctx: "ApiContext",
    dbAcmeAuthorization: Optional["AcmeAuthorization"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object to deactivate on the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    # TODO: sync the AcmeOrder objects instead

    if not dbAcmeAuthorization:
        raise ValueError("Must submit `dbAcmeAuthorization`")
    if not dbAcmeAuthorization.is_can_acme_server_deactivate:
        raise ValueError("Can not deactivate this `AcmeAuthorization`")

    tmpfiles = []
    try:
        # the authorization could be on multiple AcmeOrders
        # see :method:`AcmeAuthorization.to_acme_orders`
        # however the first order is cached onto the object so we can access the account
        # the account-key will be the same across linked orders/auths
        dbAcmeOrderCreated = dbAcmeAuthorization.acme_order_created

        # we need to use tmpfiles on the disk
        if authenticatedUser is None:
            dbAcmeAccount = dbAcmeAuthorization.acme_order_created.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrderCreated)

        try:
            (
                authorization_response,
                dbAcmeEventLog_authorization_fetch,
            ) = authenticatedUser.acme_authorization_deactivate(
                ctx,
                dbAcmeAuthorization=dbAcmeAuthorization,
                transaction_commit=True,
            )
            _server_status = authorization_response["status"]
            if _server_status != "deactivated":
                raise ValueError(
                    "Authorization status should be `deactivated`; instead it is `%s`",
                    _server_status,
                )
            _result = update_AcmeAuthorization_status(
                ctx,
                dbAcmeAuthorization,
                _server_status,
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )

            # fields in the authorization_response:
            # - status
            # - challenges
            # - identifier
            # - expires
            # there is no point in updating those.
            # but...
            # figure out all the challenges we have and set them to *410* if they are no longer there
            #
            disable_missing_AcmeAuthorization_AcmeChallenges(
                ctx,
                dbAcmeAuthorization,
                authorization_response,
                transaction_commit=True,
            )

            # the RFC requires an AcmeOrder transitions to "invalid" when an
            # AcmeAuthorization is deactivated
            # TODO: sync the AcmeOrder objects instead
            for _to_acme_order in dbAcmeAuthorization.to_acme_orders:
                updated_AcmeOrder_ProcessingStatus(
                    ctx,
                    _to_acme_order.acme_order,
                    acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_deactivated,
                    acme_status_order_id=model_utils.Acme_Status_Order.from_string(
                        "invalid"
                    ),
                    timestamp=ctx.timestamp,
                    transaction_commit=True,
                )
            return True
        except errors.AcmeServer404 as exc:
            update_AcmeAuthorization_status(
                ctx,
                dbAcmeAuthorization,
                "*404*",
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )
            return False

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def do__AcmeV2_AcmeAuthorization__acme_server_sync(
    ctx: "ApiContext",
    dbAcmeAuthorization: Optional["AcmeAuthorization"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object to refresh against the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    # TODO: sync the AcmeOrder objects instead

    if not dbAcmeAuthorization:
        raise ValueError("Must submit `dbAcmeAuthorization`")
    if not dbAcmeAuthorization.is_can_acme_server_sync:
        raise ValueError("Can not sync this `AcmeAuthorization`")

    tmpfiles = []
    try:
        # the authorization could be on multiple AcmeOrders
        # see :method:`AcmeAuthorization.to_acme_orders`
        # however the first order is cached onto the object so we can access the account
        # the account-key will be the same across linked orders/auths
        dbAcmeOrderCreated = dbAcmeAuthorization.acme_order_created

        if authenticatedUser is None:
            dbAcmeAccount = dbAcmeAuthorization.acme_order_created.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrderCreated)

        try:
            (
                authorization_response,
                dbAcmeEventLog_authorization_fetch,
            ) = authenticatedUser.acme_authorization_load(
                ctx,
                dbAcmeAuthorization=dbAcmeAuthorization,
                transaction_commit=True,
            )

            # trigger this now, so we do not attempt to load the chalenges
            if authorization_response["status"] == "*404*":
                raise errors.AcmeServer404()

            # update the the Authorization object
            _updated = update_AcmeAuthorization_from_payload(
                ctx, dbAcmeAuthorization, authorization_response
            )

            # it's possible we are missing older challenges
            disable_missing_AcmeAuthorization_AcmeChallenges(
                ctx,
                dbAcmeAuthorization,
                authorization_response,
                transaction_commit=True,
            )

            # and it's possible we have new challenges
            try:
                dbAcmeChallenges = getcreate__AcmeChallenges_via_payload(
                    ctx,
                    authenticatedUser=authenticatedUser,
                    dbAcmeAuthorization=dbAcmeAuthorization,
                    authorization_payload=authorization_response,
                )
            except errors.AcmeMissingChallenges as exc:
                # maybe there are challenges in the payload?
                if (
                    authorization_response["status"]
                    in model_utils.Acme_Status_Authorization.OPTIONS_POSSIBLY_PENDING
                ):
                    # note: perhaps better raised as `errors.InvalidRequest`
                    raise errors.AcmeCommunicationError("Missing required challenges")

            return True
        except errors.AcmeServer404 as exc:
            update_AcmeAuthorization_status(
                ctx,
                dbAcmeAuthorization,
                "*404*",
                timestamp=ctx.timestamp,
                transaction_commit=True,
            )
            return False

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def do__AcmeV2_AcmeChallenge__acme_server_trigger(
    ctx: "ApiContext",
    dbAcmeChallenge: Optional["AcmeChallenge"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge` object to trigger against the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`

    :returns: a boolean result True/False
    """
    # TODO: sync the Authorization objects instead
    # TODO: sync the AcmeOrder objects instead
    if not dbAcmeChallenge:
        raise ValueError("Must submit `dbAcmeChallenge`")
    if not dbAcmeChallenge.is_can_acme_server_trigger:
        # ensures we have 'pending' status and
        # acme order, with acme_account
        raise ValueError("Can not trigger this `AcmeChallenge`")

    tmpfiles = []
    try:
        # this is used a bit
        dbAcmeAuthorization = dbAcmeChallenge.acme_authorization

        # the authorization could be on multiple AcmeOrders
        # see :method:`AcmeAuthorization.to_acme_orders`
        # however the first order is cached onto the object so we can access the account
        # the account-key will be the same across linked orders/auths
        dbAcmeOrderCreated = dbAcmeAuthorization.acme_order_created
        _passes = None
        for _to_acme_order in dbAcmeAuthorization.to_acme_orders:
            if (
                _to_acme_order.acme_order.acme_order_processing_status_id
                in model_utils.AcmeOrder_ProcessingStatus.IDS_CAN_PROCESS_CHALLENGES
            ):
                _passes = True
        if not _passes:
            raise errors.AcmeOrphanedObject(
                "The selected AcmeChallenge is not associated to an active AcmeOrder."
            )

        if authenticatedUser is None:
            # the associated AcmeOrders should all have the same AcmeAccount
            dbAcmeAccount = dbAcmeOrderCreated.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrderCreated)

        try:
            authenticatedUser.prepare_acme_challenge(
                ctx,
                dbAcmeAuthorization=dbAcmeAuthorization,
                dbAcmeChallenge=dbAcmeChallenge,
            )

            challenge_response = authenticatedUser.acme_challenge_trigger(
                ctx,
                dbAcmeChallenge=dbAcmeChallenge,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
                transaction_commit=True,
            )

            # this only logs
            _audit_AcmeChallenge_against_server_response(
                ctx, dbAcmeChallenge, challenge_response
            )

            assert challenge_response

            # update the AcmeChallenge.status if it's not the same on the database
            update_AcmeChallenge_status(
                ctx,
                dbAcmeChallenge,
                challenge_response["status"],
                timestamp=ctx.timestamp,
                transaction_commit=True,
            )

            return True

        except errors.AcmeServer404 as exc:
            update_AcmeChallenge_status(
                ctx,
                dbAcmeChallenge,
                "*404*",
                timestamp=ctx.timestamp,
                transaction_commit=True,
            )

        except errors.AcmeAuthorizationFailure as exc:
            # the Authorization has failed
            update_AcmeAuthorization_status(
                ctx,
                dbAcmeAuthorization,
                "invalid",
                timestamp=ctx.timestamp,
                transaction_commit=True,
            )
            # re-raise, so the Order can fail
            raise

        finally:
            for _to_acme_order in dbAcmeAuthorization.to_acme_orders:
                if (
                    _to_acme_order.acme_order.acme_order_processing_status_id
                    == model_utils.AcmeOrder_ProcessingStatus.created_acme
                ):
                    updated_AcmeOrder_ProcessingStatus(
                        ctx,
                        _to_acme_order.acme_order,
                        acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_started,
                        timestamp=ctx.timestamp,
                        transaction_commit=True,
                    )

    except errors.AcmeAuthorizationFailure as exc:
        for _to_acme_order in dbAcmeAuthorization.to_acme_orders:
            if (
                _to_acme_order.acme_order.acme_order_processing_status_id
                != model_utils.AcmeOrder_ProcessingStatus.processing_completed_failure
            ):
                updated_AcmeOrder_ProcessingStatus(
                    ctx,
                    _to_acme_order.acme_order,
                    acme_status_order_id=model_utils.Acme_Status_Order.from_string(
                        "invalid"
                    ),
                    acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_completed_failure,
                    timestamp=ctx.timestamp,
                    transaction_commit=True,
                )

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()
    return True


def do__AcmeV2_AcmeChallenge__acme_server_sync(
    ctx: "ApiContext",
    dbAcmeChallenge: Optional["AcmeChallenge"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge` object to refresh against the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    # TODO: sync the Authorization objects instead
    # TODO: sync the AcmeOrder objects instead

    if not dbAcmeChallenge:
        raise ValueError("Must submit `dbAcmeChallenge`")
    if not dbAcmeChallenge.is_can_acme_server_sync:
        raise ValueError("Can not sync this `dbAcmeChallenge` (0)")

    tmpfiles = []
    try:
        # this is used a bit
        dbAcmeAuthorization = dbAcmeChallenge.acme_authorization

        # the authorization could be on multiple AcmeOrders
        # see :method:`AcmeAuthorization.to_acme_orders`
        # however the first order is cached onto the object so we can access the account
        # the account-key will be the same across linked orders/auths
        dbAcmeOrderCreated = dbAcmeAuthorization.acme_order_created
        if authenticatedUser is None:
            dbAcmeAccount = dbAcmeOrderCreated.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrderCreated)

        try:
            (
                challenge_response,
                dbAcmeEventLog_challenge_fetch,
            ) = authenticatedUser.acme_challenge_load(
                ctx,
                dbAcmeChallenge=dbAcmeChallenge,
                transaction_commit=True,
            )

            # this only logs
            _audit_AcmeChallenge_against_server_response(
                ctx, dbAcmeChallenge, challenge_response
            )

            # update the AcmeChallenge.status if it's not the same on the database
            _server_status = challenge_response["status"]
            update_AcmeChallenge_status(
                ctx,
                dbAcmeChallenge,
                _server_status,
                timestamp=ctx.timestamp,
                transaction_commit=True,
            )

            if _server_status == "invalid":
                if dbAcmeChallenge.acme_authorization:
                    # the RFC requires an AcmeAuthorization transitions to "invalid"
                    # if an AcmeChallenge transitions to "invalid"
                    if (
                        dbAcmeChallenge.acme_authorization.acme_status_authorization
                        != "invalid"
                    ):
                        update_AcmeAuthorization_status(
                            ctx,
                            dbAcmeChallenge.acme_authorization,
                            "invalid",
                            timestamp=ctx.timestamp,
                            transaction_commit=True,
                            is_via_acme_sync=False,
                        )
                    # the RFC requires an AcmeOrder transitions to "invalid"
                    # if an AcmeAuthorization transitions to "invalid"
                    for (
                        _to_acme_order
                    ) in dbAcmeChallenge.acme_authorization.to_acme_orders:
                        updated_AcmeOrder_ProcessingStatus(
                            ctx,
                            _to_acme_order.acme_order,
                            acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_completed_failure,
                            acme_status_order_id=model_utils.Acme_Status_Order.from_string(
                                "invalid"
                            ),
                            timestamp=ctx.timestamp,
                            transaction_commit=True,
                        )
        except errors.AcmeServer404 as exc:
            update_AcmeChallenge_status(
                ctx,
                dbAcmeChallenge,
                "*404*",
                timestamp=ctx.timestamp,
                transaction_commit=True,
            )

        return True

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def do__AcmeV2_AcmeOrder__acme_server_sync(
    ctx: "ApiContext",
    dbAcmeOrder: Optional["AcmeOrder"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> "AcmeOrder":
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to refresh against the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`

    returns:
        dbAcmeOrder
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")

    tmpfiles = []
    try:
        if authenticatedUser is None:
            dbAcmeAccount = dbAcmeOrder.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        is_order_404 = None
        try:
            (
                acmeOrderRfcObject,
                dbAcmeOrderEventLogged,
            ) = authenticatedUser.acme_order_load(
                ctx,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            is_order_404 = False

            # update the AcmeOrder if it's not the same on the database
            # always invoke this, as it handles it's own cleanup of the model
            result = updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acmeOrderRfcObject.rfc_object,
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )
            return dbAcmeOrder

        except errors.AcmeServer404 as exc:
            is_order_404 = True
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acme_v2.new_response_404(),
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )
            # Do not reflect the 404 status on AcmeAuthoriztions, as the ACME
            # server may elect to reuse them
            return dbAcmeOrder

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def do__AcmeV2_AcmeOrder__acme_server_sync_authorizations(
    ctx: "ApiContext",
    dbAcmeOrder: Optional["AcmeOrder"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> "AcmeOrder":
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to refresh against the server
    :param authenticatedUser: (optional) a loaded `authenticatedUser`

    :returns:  The :class:`model.objects.AcmeOrder` originally passed in as `dbAcmeOrder`
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")

    tmpfiles = []
    try:
        if authenticatedUser is None:
            dbAcmeAccount = dbAcmeOrder.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        handle_authorization_payload = _AcmeV2_factory_AuthHandlers(
            ctx, authenticatedUser, dbAcmeOrder
        )

        is_order_404 = None
        try:
            (
                acmeOrderRfcObject,
                dbAcmeOrderEventLogged,
            ) = authenticatedUser.acme_order_load(
                ctx,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            is_order_404 = False

            # always invoke this, as it handles it's own cleanup of the model
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acmeOrderRfcObject.rfc_object,
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )

        except errors.AcmeServer404 as exc:
            is_order_404 = True
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acme_v2.new_response_404(),
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )
            # just continue, as the internal orders are what we care about

        # make sure we have all the authorizations
        if not is_order_404:
            _changed = None
            for authorization_url in acmeOrderRfcObject.rfc_object.get(
                "authorizations"
            ):
                (
                    _dbAuthPlacholder,
                    _is_auth_created,
                    _is_auth_2_order_created,
                ) = getcreate__AcmeAuthorizationUrl(
                    ctx, authorization_url=authorization_url, dbAcmeOrder=dbAcmeOrder
                )
                if not _changed and (_is_auth_created or _is_auth_2_order_created):
                    _changed = True
            if _changed:
                # the major benefit to commit here is to expire `dbAcmeOrder.acme_authorizations`
                ctx.pyramid_transaction_commit()

        for dbAcmeAuthorization in dbAcmeOrder.acme_authorizations:
            try:
                result = do__AcmeV2_AcmeAuthorization__acme_server_sync(
                    ctx,
                    dbAcmeAuthorization=dbAcmeAuthorization,
                    authenticatedUser=authenticatedUser,
                )
            except Exception as exc:
                print(exc)
                raise

        return dbAcmeOrder

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def do__AcmeV2_AcmeAccount__acme_server_deactivate_authorizations(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    acme_authorization_ids: Iterable[int],
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> Dict:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object that owns the authorization ids
    :param int acme_authorization_ids: (required) An iterable of AcmeAuthoriationIds to deactivate
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    # TODO: sync the AcmeAuthorization objects instead
    # TODO: sync the AcmeOrder objects instead
    if not dbAcmeAccount:
        raise ValueError("Must submit `dbAcmeAccount`")

    tmpfiles = []
    try:
        if authenticatedUser is None:
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        dbAcmeAuthorizations = get__AcmeAuthorizations__by_ids(
            ctx, acme_authorization_ids, acme_account_id=dbAcmeAccount.id
        )
        results: Dict = {id_: False for id_ in acme_authorization_ids}
        for dbAcmeAuthorization in dbAcmeAuthorizations:
            if not dbAcmeAuthorization.is_acme_server_pending:
                # no need to attempt turning off an auth that is not (potentially) pending
                continue
            try:
                (
                    authorization_response,
                    dbAcmeEventLog_authorization_fetch,
                ) = authenticatedUser.acme_authorization_deactivate(
                    ctx,
                    dbAcmeAuthorization=dbAcmeAuthorization,
                    transaction_commit=True,
                )
                results[dbAcmeAuthorization.id] = True
            except errors.AcmeServer404 as exc:
                results[dbAcmeAuthorization.id] = None
                authorization_response = acme_v2.new_response_404()
            update_AcmeAuthorization_status(
                ctx,
                dbAcmeAuthorization,
                authorization_response["status"],
                timestamp=ctx.timestamp,
                transaction_commit=True,
            )

            if authorization_response["status"] == "deactivated":
                # disable the missing `AcmeChallenges` (should be all!)
                disable_missing_AcmeAuthorization_AcmeChallenges(
                    ctx,
                    dbAcmeAuthorization,
                    authorization_response,
                    transaction_commit=True,
                )

                """
                RFC:
                The order also moves to the "invalid"
                state if it expires or one of its authorizations enters a final state
                other than "valid" ("expired", "revoked", or "deactivated").
                """
                for _to_acme_order in dbAcmeAuthorization.to_acme_orders:
                    updated_AcmeOrder_status(
                        ctx,
                        _to_acme_order.acme_order,
                        acme_v2.new_response_invalid(),
                        timestamp=ctx.timestamp,
                        transaction_commit=True,
                    )
        return results
    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def do__AcmeV2_AcmeOrder__acme_server_deactivate_authorizations(
    ctx: "ApiContext",
    dbAcmeOrder: Optional["AcmeOrder"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to refresh against the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")

    tmpfiles = []
    try:
        if authenticatedUser is None:
            dbAcmeAccount = dbAcmeOrder.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        # first, load the order
        acmeOrderRfcObject = None
        is_order_404 = None
        try:
            (
                acmeOrderRfcObject,
                dbAcmeOrderEventLogged,
            ) = authenticatedUser.acme_order_load(
                ctx,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            is_order_404 = False
        except errors.AcmeServer404 as exc:
            is_order_404 = True
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acme_v2.new_response_404(),
                is_processing_False=True,
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )

        for dbAcmeAuthorization in dbAcmeOrder.authorizations_can_deactivate:
            try:
                (
                    authorization_response,
                    dbAcmeEventLog_authorization_fetch,
                ) = authenticatedUser.acme_authorization_deactivate(
                    ctx,
                    dbAcmeAuthorization=dbAcmeAuthorization,
                    transaction_commit=True,
                )
                update_AcmeAuthorization_status(
                    ctx,
                    dbAcmeAuthorization,
                    authorization_response["status"],
                    timestamp=ctx.timestamp,
                    transaction_commit=True,
                    is_via_acme_sync=True,
                )
                disable_missing_AcmeAuthorization_AcmeChallenges(
                    ctx,
                    dbAcmeAuthorization,
                    authorization_response,
                    transaction_commit=True,
                )
            except errors.AcmeServer404 as exc:
                authorization_response = acme_v2.new_response_404()
                update_AcmeAuthorization_status(
                    ctx,
                    dbAcmeAuthorization,
                    authorization_response["status"],
                    timestamp=ctx.timestamp,
                    transaction_commit=True,
                    is_via_acme_sync=True,
                )

        # update the AcmeOrder if it's not the same in the database
        if not is_order_404:
            try:
                (
                    acmeOrderRfcObject,
                    dbAcmeOrderEventLogged,
                ) = authenticatedUser.acme_order_load(
                    ctx,
                    dbAcmeOrder=dbAcmeOrder,
                    transaction_commit=True,
                )
                # always invoke this, as it handles some cleanup routines
                return updated_AcmeOrder_status(
                    ctx,
                    dbAcmeOrder,
                    acmeOrderRfcObject.rfc_object,
                    acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_deactivated,
                    is_processing_False=True,
                    timestamp=ctx.timestamp,
                    transaction_commit=True,
                    is_via_acme_sync=True,
                )
            except Exception as exc:
                raise

        return False

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def _do__AcmeV2_AcmeOrder__finalize(
    ctx: "ApiContext",
    authenticatedUser: "AuthenticatedUser",
    dbAcmeOrder: "AcmeOrder",
) -> "AcmeOrder":
    """
    `_do__AcmeV2_AcmeOrder__finalize` is invoked to actually finalize the order.
    :param authenticatedUser: (required) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to finalize

    :returns:  The :class:`model.objects.AcmeOrder` originally passed in as `dbAcmeOrder`

    Finalizing an order means signing the CertificateSigningRequest.
    If the PrivateKey is DEFERRED or INVALID, attempt to associate the correct one.
    """

    tmpfiles = []
    try:
        private_key_strategy__final = None
        # if there is a new PrivateKeyNew,
        # stash it into `dbPrivateKey_new` and reassign in an `except` block
        dbPrivateKey_new = None
        # outer `try/except` catches `ReassignedPrivateKey`
        try:
            # inner `try/except` catches `AcmeAccountNeedsPrivateKey`
            try:
                if dbAcmeOrder.private_key_id == 0:
                    # Multiple logic lines for `dbAcmeOrder.private_key_strategy__requested`
                    if (
                        dbAcmeOrder.private_key_strategy__requested
                        == "deferred-generate"
                    ):
                        private_key_strategy__final = "deferred-generate"
                        # NOTE: deferred-generate ; single_certificate
                        dbPrivateKey_new = create__PrivateKey(
                            ctx,
                            acme_account_id__owner=dbAcmeOrder.acme_account.id,
                            private_key_source_id=model_utils.PrivateKeySource.from_string(
                                "generated"
                            ),
                            private_key_type_id=model_utils.PrivateKeyType.from_string(
                                "single_certificate"  # this COULD be "standard", but safer to lock down for now
                            ),
                            key_technology_id=dbAcmeOrder.acme_account.private_key_technology_id,
                        )
                        raise ReassignedPrivateKey("new `generated`")
                    elif (
                        dbAcmeOrder.private_key_strategy__requested
                        == "deferred-associate"
                    ):
                        # all these items should share the same final strategy
                        private_key_strategy__final = "deferred-associate"
                        raise AcmeAccountNeedsPrivateKey()

                    else:
                        raise ValueError(
                            "Invalid `private_key_strategy__requested` for placeholder AcmeAccount"
                        )

                else:
                    # if we have an Assigned private key, we should ensure it is still active
                    # if the private key is no longer active, then we should use a backup
                    if dbAcmeOrder.private_key.is_key_usable:
                        private_key_strategy__final = (
                            dbAcmeOrder.private_key_strategy__requested
                        )
                        raise PrivateKeyOk()
                    else:
                        # all these items should share the same final strategy
                        private_key_strategy__final = "backup"
                        raise AcmeAccountNeedsPrivateKey()

                # we MUST have encountered an Exception already
                raise ValueError("Invalid Logic")

            except AcmeAccountNeedsPrivateKey as exc:
                # look the `dbAcmeOrder.acme_account.private_key_cycle`
                dbPrivateKey_new = getcreate__PrivateKey_for_AcmeAccount(
                    ctx,
                    dbAcmeAccount=dbAcmeOrder.acme_account,
                )
                raise ReassignedPrivateKey("new PrivateKey")

            # we MUST have encountered an Exception already
            raise ValueError("Invalid Logic")

        except ReassignedPrivateKey as exc:
            # assign this over!
            dbAcmeOrder.private_key = dbPrivateKey_new
            ctx.dbSession.flush(
                objects=[
                    dbAcmeOrder,
                    dbPrivateKey_new,
                ]
            )
            dbPrivateKey = dbPrivateKey_new

        except PrivateKeyOk as exc:
            pass

        # set the PrivateKeyStrategy
        assert private_key_strategy__final
        dbAcmeOrder.private_key_strategy_id__final = (
            model_utils.PrivateKeyStrategy.from_string(private_key_strategy__final)
        )
        ctx.dbSession.flush(
            objects=[
                dbAcmeOrder,
            ]
        )

        # we may need to use tmpfiles on the disk for the Private Key signing
        tmpfile_pkey = None
        private_key_pem = dbAcmeOrder.private_key.key_pem
        if cert_utils.NEEDS_TEMPFILES:
            tmpfile_pkey = cert_utils.new_pem_tempfile(private_key_pem)
            tmpfiles.append(tmpfile_pkey)

        # what are the domain names?
        domain_names = dbAcmeOrder.domains_as_list

        tmpfile_csr = None
        if dbAcmeOrder.certificate_request:
            dbCertificateRequest = dbAcmeOrder.certificate_request
            csr_pem = dbCertificateRequest.csr_pem
            if cert_utils.NEEDS_TEMPFILES:
                tmpfile_csr = cert_utils.new_pem_tempfile(csr_pem)
                tmpfiles.append(tmpfile_csr)
        else:
            # make the CSR
            csr_pem = cert_utils.make_csr(
                domain_names,
                key_pem=private_key_pem,
                key_pem_filepath=tmpfile_pkey.name if tmpfile_pkey else None,
            )
            if cert_utils.NEEDS_TEMPFILES:
                tmpfile_csr = cert_utils.new_pem_tempfile(csr_pem)
                tmpfiles.append(tmpfile_csr)

            # immediately commit this
            dbCertificateRequest = create__CertificateRequest(
                ctx,
                csr_pem,
                certificate_request_source_id=model_utils.CertificateRequestSource.ACME_ORDER,
                dbPrivateKey=dbAcmeOrder.private_key,
                dbCertificateSigned__issued=None,
                domain_names=domain_names,
            )
            # dbAcmeOrder.certificate_request_id = dbCertificateRequest.id
            dbAcmeOrder.certificate_request = dbCertificateRequest
            ctx.pyramid_transaction_commit()

        # pull domains from csr
        csr_domains = cert_utils.parse_csr_domains(
            csr_pem=csr_pem,
            csr_pem_filepath=tmpfile_csr.name if tmpfile_csr else None,
            submitted_domain_names=domain_names,
        )
        if set(csr_domains) != set(domain_names):
            raise ValueError(
                "The CertificateRequest does not have the expected Domains."
            )

        # sign and download
        try:
            fullchain_pems = authenticatedUser.acme_order_finalize(
                ctx,
                dbAcmeOrder=dbAcmeOrder,
                update_order_status=updated_AcmeOrder_status,
                csr_pem=csr_pem,
                transaction_commit=True,
            )

        except errors.AcmeServer404 as exc:
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acme_v2.new_response_404(),
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )
            raise

        # we may have downloaded the alternate chains
        # this behavior is controlled by `dbAcmeOrder.is_save_alternate_chains`
        certificate_pem = None
        dbCertificateCAChains_alternates = []
        for fullchain_pem in fullchain_pems:
            (
                _certificate_pem,
                _ca_chain_pem,
            ) = cert_utils.cert_and_chain_from_fullchain(fullchain_pem)
            if certificate_pem is None:
                certificate_pem = _certificate_pem
            else:
                if certificate_pem != _certificate_pem:
                    raise ValueError("certificate mismatch!")

            # get/create the CertificateCA
            (
                dbCertificateCAChain,
                is_created__CertificateCAChain,
            ) = getcreate__CertificateCAChain__by_pem_text(
                ctx,
                _ca_chain_pem,
                display_name="ACME Server Response",
            )
            if is_created__CertificateCAChain:
                ctx.pyramid_transaction_commit()
            dbCertificateCAChains_alternates.append(dbCertificateCAChain)

        dbCertificateSigned = create__CertificateSigned(
            ctx,
            cert_pem=certificate_pem,
            cert_domains_expected=domain_names,
            is_active=True,
            dbAcmeOrder=dbAcmeOrder,
            dbCertificateCAChain=dbCertificateCAChains_alternates[0],
            dbCertificateCAChains_alt=dbCertificateCAChains_alternates[1:],
            dbCertificateRequest=dbCertificateRequest,
        )
        ctx.pyramid_transaction_commit()

        # update the logger
        authenticatedUser.acmeLogger.log_CertificateProcured(
            "v2",
            dbCertificateSigned=dbCertificateSigned,
            dbCertificateRequest=dbAcmeOrder.certificate_request,
            transaction_commit=True,
        )

        # don't commit here, as that will trigger an error on object refresh
        return dbAcmeOrder

    except Exception as exc:
        raise

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def _do__AcmeV2_AcmeOrder__new_core(
    ctx: "ApiContext",
    acme_order_type_id=None,
    domains_challenged=None,
    private_key_cycle__renewal=None,
    private_key_strategy__requested=None,
    processing_strategy=None,
    dbAcmeAccount=None,
    dbAcmeOrder_renewal_of=None,
    dbAcmeOrder_retry_of=None,
    dbUniqueFQDNSet=None,
    dbPrivateKey=None,
    dbQueueCertificate__of=None,
) -> "AcmeOrder":
    """

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param acme_order_type_id: (required) What type of order is this? A value from :class:`model.objects.AcmeOrderType`
    :param domains_challenged: (required) An dict of ACME challenge types (keys) and lists of domain names (values)
    :param private_key_cycle__renewal: (required)  A value from :class:`model.utils.PrivateKeyCycle`
    :param private_key_strategy__requested: (required)  A value from :class:`model.utils.PrivateKeyStrategy`
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param dbAcmeOrder_renewal_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbAcmeOrder_retry_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbUniqueFQDNSet: (optional) A :class:`model.objects.dbUniqueFQDNSet` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param dbQueueCertificate__of: (optional) A :class:`model.objects.QueueCertificate` object

    One and only one of the following items must be provided:
        dbAcmeOrder_retry_of
        dbAcmeOrder_renewal_of
        dbQueueCertificate__of

    Audit:

        new:
            dbAcmeAccount
            dbPrivateKey
            dbQueueCertificate__of
            dbUniqueFQDNSet (optional)
            domains_challenged (required if dbUniqueFQDNSet)
        renew custom
            dbAcmeOrder_renewal_of=dbAcmeOrder,
            dbAcmeAccount=dbAcmeAccount,
            dbPrivateKey=dbPrivateKey,
        retry:
            dbAcmeOrder_retry_of=dbAcmeOrder,
        renew quick
            dbAcmeOrder_renewal_of=dbAcmeOrder,

    :returns: A class:`model.objects.AcmeOrder` object for the new AcmeOrder
    """
    # validate this first!
    acme_order_processing_strategy_id = (
        model_utils.AcmeOrder_ProcessingStrategy.from_string(processing_strategy)
    )
    private_key_cycle_id__renewal = model_utils.PrivateKeyCycle.from_string(
        private_key_cycle__renewal
    )
    private_key_strategy_id__requested = model_utils.PrivateKeyStrategy.from_string(
        private_key_strategy__requested
    )

    # at most, accept one of:
    if (
        sum(
            bool(i)
            for i in (
                dbAcmeOrder_retry_of,
                dbAcmeOrder_renewal_of,
                dbQueueCertificate__of,
            )
        )
        >= 2
    ):
        raise ValueError(
            "At most, provide one of `(dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of, dbQueueCertificate__of)`"
        )

    if not domains_challenged:
        if not any(
            (
                dbAcmeOrder_retry_of,
                dbAcmeOrder_renewal_of,
                dbQueueCertificate__of,
                dbUniqueFQDNSet,
            )
        ):
            raise ValueError(
                "`domains_challenged` is required unless one of `(dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of, dbQueueCertificate__of, dbUniqueFQDNSet)` is passed"
            )

    # build this off domains_challenged
    domain_names = None

    # switch this
    if dbAcmeOrder_retry_of:
        # kwargs validation
        if dbAcmeAccount:
            raise ValueError(
                "Must NOT submit `dbAcmeAccount` with `dbAcmeOrder_retry_of`"
            )

        # ensure we can transition
        if (
            dbAcmeOrder_retry_of.acme_status_order
            not in model_utils.Acme_Status_Order.OPTIONS_RETRY
        ):
            raise errors.InvalidRequest(
                "`dbAcmeOrder_retry_of.acme_status_order` must be in %s"
                % str(model_utils.Acme_Status_Order.OPTIONS_RETRY)
            )

        # re-use these related objects
        dbAcmeAccount = dbAcmeOrder_retry_of.acme_account
        dbPrivateKey = dbAcmeOrder_retry_of.private_key
        dbUniqueFQDNSet = dbAcmeOrder_retry_of.unique_fqdn_set
        domain_names = dbAcmeOrder_retry_of.domains_as_list
        if domains_challenged is None:
            # `dbAcmeOrder_retry_of` is an instance of `model_objects.AcmeOrder`
            domains_challenged = dbAcmeOrder_retry_of.domains_challenged

    elif dbAcmeOrder_renewal_of:
        # kwargs validation

        # ensure we can transition
        if (
            dbAcmeOrder_renewal_of.acme_status_order
            not in model_utils.Acme_Status_Order.OPTIONS_RENEW
        ):
            raise errors.InvalidRequest(
                "`dbAcmeOrder_renewal_of.acme_status_order` must be in %s"
                % str(model_utils.Acme_Status_Order.OPTIONS_RENEW)
            )

        # override or re-use these related objects
        if not dbAcmeAccount:
            dbAcmeAccount = dbAcmeOrder_renewal_of.acme_account

        if not dbPrivateKey:
            # raise ValueError("Must submit `dbPrivateKey`")
            dbPrivateKey = dbAcmeOrder_renewal_of.private_key

        # re-use these related objects
        dbUniqueFQDNSet = dbAcmeOrder_renewal_of.unique_fqdn_set
        domain_names = dbAcmeOrder_renewal_of.domains_as_list
        if domains_challenged is None:
            # `dbAcmeOrder_renewal_of` is an instance of `model_objects.AcmeOrder`
            domains_challenged = dbAcmeOrder_renewal_of.domains_challenged

    elif dbQueueCertificate__of:
        # kwargs validation
        if dbAcmeAccount:
            raise ValueError(
                "Must NOT submit `dbAcmeAccount` with `dbQueueCertificate__of`"
            )
        if dbPrivateKey:
            raise ValueError(
                "Must NOT submit `dbPrivateKey` with `dbQueueCertificate__of`"
            )

        # re-use these related objects
        dbAcmeAccount = dbQueueCertificate__of.acme_account
        dbPrivateKey = dbQueueCertificate__of.private_key
        dbUniqueFQDNSet = dbQueueCertificate__of.unique_fqdn_set
        domain_names = dbQueueCertificate__of.domains_as_list
        if domains_challenged is None:
            # `dbQueueCertificate__of` is an instance of `model_objects.dbQueueCertificate`
            domains_challenged = model_utils.DomainsChallenged.new_http01(
                dbQueueCertificate__of.domains_as_list
            )

        # quick validation
        if not dbAcmeAccount.is_usable:
            raise ValueError("The specified AcmeAccount is not usable")

    elif dbUniqueFQDNSet:
        # kwargs validation
        if not dbAcmeAccount:
            raise ValueError("Must submit `dbAcmeAccount` with `dbUniqueFQDNSet`")
        if not dbPrivateKey:
            raise ValueError("Must submit `dbPrivateKey`")
        domain_names = dbUniqueFQDNSet.domains_as_list
        if domains_challenged is None:
            # generate these via the default
            domains_challenged = model_utils.DomainsChallenged.new_http01(domain_names)

    else:
        if domains_challenged is None:
            raise ValueError("Must submit `domain_challenged` in this context")
        domain_names = domains_challenged.domains_as_list

    # raise a ValueError if `DomainsChallenged` object is incompatible
    domains_challenged.ensure_parity(domain_names)

    # ensure the PrivateKey is usable!
    if not dbPrivateKey.is_key_usable:
        raise errors.InvalidRequest(
            "The `dbPrivateKey` is not usable. It was deactivated or compromised.`"
        )

    # ensure we have domains names!
    if not domain_names:
        raise ValueError("No `domain_names` detected for this request")

    if not dbUniqueFQDNSet:
        (
            dbUniqueFQDNSet,
            is_created_fqdn,
        ) = getcreate__UniqueFQDNSet__by_domains(ctx, domain_names)
        ctx.pyramid_transaction_commit()

    assert ctx.request
    assert ctx.request.registry
    if ctx.request.registry.settings["app_settings"]["block_competing_challenges"]:
        # check each domain for an existing active challenge
        active_challenges = []
        for to_domain in dbUniqueFQDNSet.to_domains:
            _active_challenges = get__AcmeChallenges__by_DomainId__active(
                ctx, to_domain.domain_id
            )
            if _active_challenges:
                active_challenges.extend(_active_challenges)
        if active_challenges:
            raise errors.AcmeDuplicateChallengesExisting(active_challenges)

    tmpfiles = []
    dbAcmeOrder = None
    dbCertificateSigned = None
    try:
        (authenticatedUser, tmpfile_account) = new_Authenticated_user(
            ctx, dbAcmeAccount
        )
        tmpfiles.append(tmpfile_account)

        # create the order on the ACME server
        (acmeOrderRfcObject, dbAcmeOrderEventLogged) = authenticatedUser.acme_order_new(
            ctx,
            domain_names=domain_names,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            transaction_commit=True,
        )
        order_url = acmeOrderRfcObject.response_headers["location"]
        if not order_url:
            raise ValueError("We must receive an `order_url` in the location")

        # Boulder has an implementation detail to deal with buggy clients:
        #   duplicate order submissions may return the same AcmeOrder
        dbAcmeOrder = get__AcmeOrder__by_order_url(ctx, order_url)
        if not dbAcmeOrder:
            # this is a new AcmeOrder
            # in the current application design, `authenticatedUser.acme_order_new` created the order on the acme server
            acme_order_processing_status_id = (
                model_utils.AcmeOrder_ProcessingStatus.from_string("created_acme")
            )

            # enroll the Acme Order into our database
            dbAcmeOrder = create__AcmeOrder(
                ctx,
                acme_order_response=acmeOrderRfcObject.rfc_object,
                acme_order_type_id=acme_order_type_id,
                acme_order_processing_status_id=acme_order_processing_status_id,
                acme_order_processing_strategy_id=acme_order_processing_strategy_id,
                domains_challenged=domains_challenged,
                private_key_cycle_id__renewal=private_key_cycle_id__renewal,
                private_key_strategy_id__requested=private_key_strategy_id__requested,
                order_url=order_url,
                dbAcmeAccount=dbAcmeAccount,
                dbAcmeOrder_retry_of=dbAcmeOrder_retry_of,
                dbAcmeOrder_renewal_of=dbAcmeOrder_renewal_of,
                dbPrivateKey=dbPrivateKey,
                dbEventLogged=dbAcmeOrderEventLogged,
                dbUniqueFQDNSet=dbUniqueFQDNSet,
                transaction_commit=True,
            )

            # register the AcmeOrder into the logging utility
            authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        else:
            # the AcmeOrder is a duplicate of an existing order
            # use the same flow here as `do__AcmeV2_AcmeOrder__acme_server_sync`
            # except create a record that we submitted this
            dbAcmeOrderSubmission = create__AcmeOrderSubmission(
                ctx,
                dbAcmeOrder,
            )

            # register the AcmeOrder into the logging utility
            authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

            # update the AcmeOrder if it's not the same on the database
            # always invoke this, as it handles it's own cleanup of the model
            result = updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acmeOrderRfcObject.rfc_object,
                timestamp=ctx.timestamp,
                transaction_commit=True,
                is_via_acme_sync=True,
            )

        # the AcmeOrder is already failed or valid, somehow...
        if dbAcmeOrder.acme_status_order not in ("pending", "ready"):
            return dbAcmeOrder

        if (
            acme_order_processing_strategy_id
            == model_utils.AcmeOrder_ProcessingStrategy.create_order
        ):
            # we may have created this order, yet it is "ready" due to existing authorizations
            if dbAcmeOrder.acme_status_order == "ready":
                FINALIZE_READY_ORDERS = False
                if FINALIZE_READY_ORDERS:
                    dbAcmeOrder = _do__AcmeV2_AcmeOrder__finalize(
                        ctx,
                        authenticatedUser=authenticatedUser,
                        dbAcmeOrder=dbAcmeOrder,
                    )
            return dbAcmeOrder

        if (
            acme_order_processing_strategy_id
            == model_utils.AcmeOrder_ProcessingStrategy.process_single
        ):
            # handle the order towards finalized?
            _task_finalize_order = _AcmeV2_AcmeOrder__process_authorizations(
                ctx, authenticatedUser, dbAcmeOrder, acmeOrderRfcObject
            )
            if not _task_finalize_order:
                return dbAcmeOrder

            dbAcmeOrder = _do__AcmeV2_AcmeOrder__finalize(
                ctx,
                authenticatedUser=authenticatedUser,
                dbAcmeOrder=dbAcmeOrder,
            )
            return dbAcmeOrder

        return dbAcmeOrder

    except (errors.AcmeOrderProcessing, errors.AcmeOrderValid) as exc:
        raise errors.AcmeOrderCreatedError(dbAcmeOrder, exc)

    except errors.AcmeOrderFatal as exc:
        raise errors.AcmeOrderCreatedError(dbAcmeOrder, exc)

    except Exception as exc:
        raise

    finally:
        if dbQueueCertificate__of:
            # after creating the AcmeOrder, we need to update the `dbQueueCertificate__of` with the info
            dbQueueCertificate__of.timestamp_process_attempt = ctx.timestamp
            dbQueueCertificate__of.timestamp_processed = ctx.timestamp
            dbQueueCertificate__of.process_result = True if dbAcmeOrder else None
            dbQueueCertificate__of.is_active = False  # this as processed

            if dbAcmeOrder:
                dbQueueCertificate__of.acme_order_id__generated = dbAcmeOrder.id
                if dbAcmeOrder.certificate_request_id:
                    dbQueueCertificate__of.certificate_request_id__generated = (
                        dbAcmeOrder.certificate_request_id
                    )
                if dbAcmeOrder.certificate_signed_id:
                    dbQueueCertificate__of.certificate_signed_id__generated = (
                        dbAcmeOrder.certificate_signed_id
                    )

            ctx.dbSession.flush(objects=[dbQueueCertificate__of])

        if (
            processing_strategy
            in model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_DEACTIVATE_AUTHS
        ):
            # shut this down to deactivate the auths on our side
            if dbAcmeOrder:
                dbAcmeOrder.is_processing = None

        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


def do__AcmeV2_AcmeOrder__finalize(
    ctx: "ApiContext",
    dbAcmeOrder: Optional["AcmeOrder"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> "AcmeOrder":
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to finalize
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`

    :returns: The :class:`model.objects.AcmeOrder` object passed in as `dbAcmeOrder`
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    if not dbAcmeOrder.is_can_acme_finalize:
        raise ValueError("Can not finalize this `dbAcmeOrder`")

    tmpfiles = []
    try:
        if authenticatedUser is None:
            dbAcmeAccount = dbAcmeOrder.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        dbAcmeOrder = _do__AcmeV2_AcmeOrder__finalize(
            ctx,
            authenticatedUser=authenticatedUser,
            dbAcmeOrder=dbAcmeOrder,
        )

        return dbAcmeOrder

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeV2_AcmeOrder__process(
    ctx: "ApiContext",
    dbAcmeOrder: Optional["AcmeOrder"] = None,
    authenticatedUser: Optional["AuthenticatedUser"] = None,
) -> "AcmeOrder":
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to finalize
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`

    This processes authorizations in sequence

    :returns: The :class:`model.objects.AcmeOrder` object passed in as `dbAcmeOrder`
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    if not dbAcmeOrder.is_can_acme_process:
        raise ValueError("Can not process this `dbAcmeOrder`")

    tmpfiles = []
    try:
        if authenticatedUser is None:
            dbAcmeAccount = dbAcmeOrder.acme_account
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccount
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        if dbAcmeOrder.acme_status_order == "pending":
            #
            # what is the next validation?
            auths_pending = dbAcmeOrder.acme_authorizations_pending
            if auths_pending:
                dbAcmeAuthorization = auths_pending.pop()
                if not dbAcmeAuthorization.is_can_acme_server_process:
                    # ensures we have 'pending' status and http-01 challenge; or *discover* status
                    # acme order, with acme_account
                    raise ValueError("Can not trigger the `AcmeAuthorization`")

                handle_authorization_payload = _AcmeV2_factory_AuthHandlers(
                    ctx, authenticatedUser, dbAcmeOrder
                )

                domains_challenged = dbAcmeOrder.domains_challenged
                if (
                    dbAcmeAuthorization.acme_status_authorization_id
                    == model_utils.Acme_Status_Authorization.ID_DISCOVERED
                ):
                    _result = authenticatedUser.acme_authorization_process_url(
                        ctx,
                        dbAcmeAuthorization.authorization_url,
                        handle_authorization_payload=handle_authorization_payload,
                        update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                        update_AcmeChallenge_status=update_AcmeChallenge_status,
                        updated_AcmeOrder_ProcessingStatus=updated_AcmeOrder_ProcessingStatus,
                        dbAcmeAuthorization=dbAcmeAuthorization,
                        acme_challenge_type_id__preferred=None,
                        domains_challenged=domains_challenged,
                        transaction_commit=True,
                    )
                else:
                    _challenge_type_id = domains_challenged.domain_to_challenge_type_id(
                        dbAcmeAuthorization.domain.domain_name
                    )
                    if _challenge_type_id == model_utils.AcmeChallengeType.http_01:
                        dbAcmeChallenge = dbAcmeAuthorization.acme_challenge_http_01
                    elif _challenge_type_id == model_utils.AcmeChallengeType.dns_01:
                        dbAcmeChallenge = dbAcmeAuthorization.acme_challenge_dns_01
                    else:
                        raise ValueError("Can not process the selecte challenge type")
                    if not dbAcmeChallenge:
                        raise ValueError("Can not trigger this `AcmeChallenge`")

                    _result = do__AcmeV2_AcmeChallenge__acme_server_trigger(
                        ctx,
                        dbAcmeChallenge=dbAcmeChallenge,
                        authenticatedUser=authenticatedUser,
                    )
            else:
                # no authorizations?
                # it's possible we did the last one?
                dbAcmeOrder = do__AcmeV2_AcmeOrder__acme_server_sync(
                    ctx, dbAcmeOrder=dbAcmeOrder, authenticatedUser=authenticatedUser
                )
                if dbAcmeOrder.acme_status_order == "pending":
                    raise errors.GarfieldMinusGarfield(
                        "unsure how this happened; pending but no active authorizations"
                    )
                elif dbAcmeOrder.acme_status_order == "ready":
                    dbAcmeOrder = _do__AcmeV2_AcmeOrder__finalize(
                        ctx,
                        authenticatedUser=authenticatedUser,
                        dbAcmeOrder=dbAcmeOrder,
                    )
                else:
                    raise errors.GarfieldMinusGarfield("unsure how this happened")
        elif dbAcmeOrder.acme_status_order == "ready":
            dbAcmeOrder = _do__AcmeV2_AcmeOrder__finalize(
                ctx,
                authenticatedUser=authenticatedUser,
                dbAcmeOrder=dbAcmeOrder,
            )
        else:
            raise errors.GarfieldMinusGarfield("unsure how this happened")

        return dbAcmeOrder

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeV2_AcmeOrder__new(
    ctx: "ApiContext",
    acme_order_type_id=None,
    domains_challenged=None,
    processing_strategy=None,
    private_key_cycle__renewal=None,
    private_key_strategy__requested=None,
    dbAcmeAccount=None,
    dbPrivateKey=None,
    dbQueueCertificate__of=None,
    dbUniqueFQDNSet=None,  # only used when submitting a QueueCertificiate
) -> "AcmeOrder":
    """
    Automates a Certificate deployment from LetsEncrypt

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param acme_order_type_id: (required) What type of order is this? A value from :class:`model.objects.AcmeOrderType`
    :param domains_challenged: (required) An dict of ACME challenge types (keys) and lists of domain names (values)
    :param private_key_cycle__renewal: (required)  A value from :class:`model.utils.PrivateKeyCycle`
    :param private_key_strategy__requested: (required)  A value from :class:`model.utils.PrivateKeyStrategy`
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param dbQueueCertificate__of: (optional) A :class:`model.objects.QueueCertificate` object
    :param dbUniqueFQDNSet: (optional) A :class:`model.objects.UniqueFQDNSet` object

    :returns: A :class:`model.objects.AcmeOrder` object
    """
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("AcmeOrder_New_Automated"),
    )
    return _do__AcmeV2_AcmeOrder__new_core(
        ctx,
        domains_challenged=domains_challenged,
        acme_order_type_id=acme_order_type_id,
        private_key_cycle__renewal=private_key_cycle__renewal,
        private_key_strategy__requested=private_key_strategy__requested,
        processing_strategy=processing_strategy,
        dbAcmeAccount=dbAcmeAccount,
        dbPrivateKey=dbPrivateKey,
        dbQueueCertificate__of=dbQueueCertificate__of,
        dbUniqueFQDNSet=dbUniqueFQDNSet,
    )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeV2_AcmeOrder__download_certificate(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
) -> "AcmeOrder":
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry

    :returns: The :class:`model.objects.AcmeOrder` object passed in as `dbAcmeOrder`
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    if not dbAcmeOrder.is_can_acme_server_download_certificate:
        raise errors.InvalidRequest(
            "this AcmeOrder is not eligible for a certificate download"
        )
    assert dbAcmeOrder.certificate_url

    tmpfiles = []
    try:
        # we need to use tmpfiles on the disk
        dbAcmeAccount = dbAcmeOrder.acme_account
        (authenticatedUser, tmpfile_account) = new_Authenticated_user(
            ctx, dbAcmeAccount
        )
        tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        fullchain_pems = authenticatedUser.download_certificate(
            dbAcmeOrder.certificate_url,
            is_save_alternate_chains=dbAcmeOrder.is_save_alternate_chains,
        )

        # we may have downloaded the alternate chains
        # this behavior is controlled by `dbAcmeOrder.is_save_alternate_chains`
        certificate_pem = None
        dbCertificateCAChains_alternates = []
        for fullchain_pem in fullchain_pems:
            (
                _certificate_pem,
                _ca_chain_pem,
            ) = cert_utils.cert_and_chain_from_fullchain(fullchain_pem)
            if certificate_pem is None:
                certificate_pem = _certificate_pem
            else:
                if certificate_pem != _certificate_pem:
                    raise ValueError("certificate mismatch!")

            # get/create the CertificateCA
            (
                dbCertificateCAChain,
                is_created__CertificateCAChain,
            ) = getcreate__CertificateCAChain__by_pem_text(
                ctx,
                _ca_chain_pem,
                display_name="ACME Server Response",
            )
            if is_created__CertificateCAChain:
                ctx.pyramid_transaction_commit()
            dbCertificateCAChains_alternates.append(dbCertificateCAChain)

        (
            dbCertificateSigned,
            _is_created__cert,
        ) = getcreate__CertificateSigned(
            ctx,
            cert_pem=certificate_pem,
            cert_domains_expected=dbAcmeOrder.domains_as_list,
            dbAcmeOrder=dbAcmeOrder,
            dbCertificateCAChain=dbCertificateCAChains_alternates[0],
            dbCertificateCAChains_alt=dbCertificateCAChains_alternates[1:],
            dbPrivateKey=dbAcmeOrder.private_key,
        )
        if dbAcmeOrder.certificate_signed:
            if dbAcmeOrder.certificate_signed_id != dbCertificateSigned.id:
                raise ValueError("competing certificates for this AcmeOrder")
        else:
            # dbAcmeOrder.certificate_signed_id = dbCertificateSigned.id
            dbAcmeOrder.certificate_signed = dbCertificateSigned

        # note that we've completed this!
        dbAcmeOrder.acme_order_processing_status_id = (
            model_utils.AcmeOrder_ProcessingStatus.certificate_downloaded
        )

        ctx.pyramid_transaction_commit()

        # update the logger
        authenticatedUser.acmeLogger.log_CertificateProcured(
            "v2",
            dbCertificateSigned=dbCertificateSigned,
            dbCertificateRequest=dbAcmeOrder.certificate_request,
            transaction_commit=True,
        )

        # don't commit here, as that will trigger an error on object refresh
        return dbAcmeOrder

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            if tf is not None:
                tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeV2_AcmeOrder__retry(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
) -> "AcmeOrder":
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`

    :returns: A :class:`model.objects.AcmeOrder` object for the new AcmeOrder
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("AcmeOrder_New_Retry"),
    )
    return _do__AcmeV2_AcmeOrder__new_core(
        ctx,
        acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_RETRY,
        private_key_cycle__renewal=dbAcmeOrder.private_key_cycle__renewal,
        private_key_strategy__requested=dbAcmeOrder.private_key_strategy__requested,
        processing_strategy=dbAcmeOrder.acme_order_processing_strategy,
        dbAcmeOrder_retry_of=dbAcmeOrder,
    )


def do__AcmeV2_AcmeOrder__renew_custom(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
    dbAcmeAccount: "AcmeAccount",
    dbPrivateKey: "PrivateKey",
    private_key_cycle__renewal: Optional[str] = None,
    processing_strategy: Optional[str] = None,
) -> "AcmeOrder":
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param private_key_cycle__renewal: (required)  A value from :class:`model.utils.PrivateKeyCycle`

    :returns: A :class:`model.objects.AcmeOrder` object for the new AcmeOrder
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    if not dbAcmeAccount:
        raise ValueError("Must submit `dbAcmeAccount`")
    if not dbPrivateKey:
        raise ValueError("Must submit `dbPrivateKey`")
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("AcmeOrder_Renew_Custom"),
    )
    # private_key_strategy__requested - pull off the original
    return _do__AcmeV2_AcmeOrder__new_core(
        ctx,
        acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_RENEW_CUSTOM,
        private_key_cycle__renewal=private_key_cycle__renewal,
        private_key_strategy__requested=dbAcmeOrder.private_key_strategy__requested,
        processing_strategy=processing_strategy,
        dbAcmeOrder_renewal_of=dbAcmeOrder,
        dbAcmeAccount=dbAcmeAccount,
        dbPrivateKey=dbPrivateKey,
    )


def do__AcmeV2_AcmeOrder__renew_quick(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
    processing_strategy: Optional[str] = None,
) -> "AcmeOrder":
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`

    :returns: A :class:`model.objects.AcmeOrder` object for the new AcmeOrder
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("AcmeOrder_Renew_Quick"),
    )
    # private_key_strategy__requested - pull off the original
    # private_key_cycle__renewal = pull off the original,
    return _do__AcmeV2_AcmeOrder__new_core(
        ctx,
        dbAcmeOrder_renewal_of=dbAcmeOrder,
        acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_RENEW_QUICK,
        private_key_cycle__renewal=dbAcmeOrder.private_key_cycle__renewal,
        private_key_strategy__requested=dbAcmeOrder.private_key_strategy__requested,
        processing_strategy=processing_strategy,
    )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
