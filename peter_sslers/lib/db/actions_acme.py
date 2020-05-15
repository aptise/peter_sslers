# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime
import pdb
import pprint

# pypi
from dateutil import parser as dateutil_parser
import sqlalchemy
import transaction

# localapp
from ... import lib
from .. import acme_v2
from .. import cert_utils
from .. import letsencrypt_info
from .. import events
from .. import errors
from .. import utils
from .. import utils_certbot as utils_certbot
from ...model import utils as model_utils
from ...model import objects as model_objects
from ..exceptions import AcmeAccountKeyNeedsPrivateKey
from ..exceptions import PrivateKeyOk
from ..exceptions import ReassignedPrivateKey

# local
from .logger import AcmeLogger
from .logger import log__OperationsEvent
from .logger import _log_object_event
from .update import update_AcmeAuthorization_from_payload


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeAccountKey_AcmeV2_register(
    ctx, dbAcmeAccountKey, account_key_path=None,
):
    """
    Registers an AcmeAccountKey against the LetsEncrypt ACME Directory

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
    :param account_key_path: (optional) If there is a tempfile for the `dbAcmeAccountKey`

    !!! WARNING !!!

    If `account_key_path` is not provided, the ACME library will be unable to perform any operations after authentication.
    """
    _tmpfile = None
    try:
        if not dbAcmeAccountKey.contact:
            raise ValueError("no `contact`")

        if account_key_path is None:
            _tmpfile = cert_utils.new_pem_tempfile(dbAcmeAccountKey.key_pem)
            account_key_path = _tmpfile.name

        acmeLogger = AcmeLogger(ctx, dbAcmeAccountKey=dbAcmeAccountKey)

        # create account, update contact details (if any), and set the global key identifier
        # result is either: `new-account` or `existing-account`
        # failing will raise an exception
        authenticatedUser = acme_v2.AuthenticatedUser(
            acmeLogger=acmeLogger,
            acmeAccountKey=dbAcmeAccountKey,
            account_key_path=account_key_path,
            log__OperationsEvent=log__OperationsEvent,
        )
        authenticatedUser.authenticate(ctx, contact=dbAcmeAccountKey.contact)

        # update based off the ACME service
        dbAcmeAccountKey.account_url = authenticatedUser._api_account_headers[
            "Location"
        ]
        dbAcmeAccountKey.terms_of_service = authenticatedUser.acme_directory["meta"][
            "termsOfService"
        ]

        return authenticatedUser
    except:
        raise


def do__AcmeAccountKey_AcmeV2_authenticate(
    ctx, dbAcmeAccountKey, account_key_path=None,
):
    """
    Authenticates an AcmeAccountKey against the LetsEncrypt ACME Directory

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
    :param account_key_path: (optional) If there is a tempfile for the `dbAcmeAccountKey`

    !!! WARNING !!!

    If `account_key_path` is not provided, the ACME library will be unable to perform any operations after authentication.
    """
    _tmpfile = None
    try:
        if account_key_path is None:
            _tmpfile = cert_utils.new_pem_tempfile(dbAcmeAccountKey.key_pem)
            account_key_path = _tmpfile.name

        acmeLogger = AcmeLogger(ctx, dbAcmeAccountKey=dbAcmeAccountKey)

        # create account, update contact details (if any), and set the global key identifier
        # result is either: `new-account` or `existing-account`
        # failing will raise an exception
        authenticatedUser = acme_v2.AuthenticatedUser(
            acmeLogger=acmeLogger,
            acmeAccountKey=dbAcmeAccountKey,
            account_key_path=account_key_path,
            log__OperationsEvent=log__OperationsEvent,
        )
        authenticatedUser.authenticate(ctx)

        return authenticatedUser

    finally:
        if _tmpfile:
            _tmpfile.close()


def new_Authenticated_user(ctx, dbAcmeAccountKey):
    """
    helper function to create a new

    AcmeLogger
    """
    tmpfile_account = None
    try:
        account_key_pem = dbAcmeAccountKey.key_pem
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        account_key_path = tmpfile_account.name

        # register the account / ensure that it is registered
        # the authenticatedUser will have a `logger.AcmeLogger` object as the `.acmeLogger` attribtue
        # the `acmeLogger` may need to have the `AcmeOrder` registered
        authenticatedUser = do__AcmeAccountKey_AcmeV2_authenticate(
            ctx, dbAcmeAccountKey, account_key_path=account_key_path,
        )
        return (authenticatedUser, tmpfile_account)
    except:
        if tmpfile_account:
            tmpfile_account.close()
        raise


def update_AcmeAuthorization_status(
    ctx, dbAcmeAuthorization, status_text, transaction_commit=None
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object
    :param status_text: (required) The status_text for the order
    :param transaction_commit: (required) Boolean. Must indicate that we will commit this.
    """
    if transaction_commit is not True:
        raise ValueError("we must invoke this knowing it will commit")
    _edited = False
    status_text = status_text.lower()
    if dbAcmeAuthorization.acme_status_authorization != status_text:
        dbAcmeAuthorization.acme_status_authorization_id = model_utils.Acme_Status_Authorization.from_string(
            status_text
        )
        dbAcmeAuthorization.timestamp_updated = datetime.datetime.utcnow()
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def update_AcmeChallenge_status(
    ctx, dbAcmeChallenge, status_text, transaction_commit=None
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge` object
    :param status_text: (required) The status_text for the order
    :param transaction_commit: (required) Boolean. Must indicate that we will commit this.
    """
    if transaction_commit is not True:
        raise ValueError("we must invoke this knowing it will commit")
    _edited = False
    status_text = status_text.lower()
    if dbAcmeChallenge.acme_status_challenge != status_text:
        dbAcmeChallenge.acme_status_challenge_id = model_utils.Acme_Status_Challenge.from_string(
            status_text
        )
        dbAcmeChallenge.timestamp_updated = datetime.datetime.utcnow()
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def updated_AcmeOrder_status(
    ctx,
    dbAcmeOrder,
    acme_order_object,
    acme_order_processing_status_id=None,
    is_processing_False=None,
    transaction_commit=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param acme_order_object: (required) An RFC compliant dict; must at least have `status`
    :param acme_order_processing_status_id: (optional) If provided, update the `acme_order_processing_status_id` of the order
    :param is_processing_False: (optional) if True, set `is_processing` to false.,
    :param transaction_commit: (required) Boolean. Must indicate that we will commit this.
    """
    if transaction_commit is not True:
        raise ValueError("we must invoke this knowing it will commit")
    _edited = False
    status_text = acme_order_object.get("status", "").lower()
    if dbAcmeOrder.acme_status_order != status_text:
        try:
            dbAcmeOrder.acme_status_order_id = model_utils.Acme_Status_Order.from_string(
                status_text
            )
        except KeyError:
            dbAcmeOrder.acme_status_order_id = model_utils.Acme_Status_Order.from_string(
                "*406*"
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
        dbAcmeOrder.timestamp_updated = datetime.datetime.utcnow()
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def updated_AcmeOrder_ProcessingStatus(
    ctx, dbAcmeOrder, acme_order_processing_status_id=None, transaction_commit=None
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param acme_order_processing_status_id: (required) If provided, update the `acme_order_processing_status_id` of the order
    :param transaction_commit: (required) Boolean. Must indicate that we will commit this.
    """
    if transaction_commit is not True:
        raise ValueError("we must invoke this knowing it will commit")
    if dbAcmeOrder.acme_order_processing_status_id != acme_order_processing_status_id:
        dbAcmeOrder.acme_order_processing_status_id = acme_order_processing_status_id
        dbAcmeOrder.timestamp_updated = datetime.datetime.utcnow()
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def _AcmeV2_factory_AuthHandlers(ctx, authenticatedUser, dbAcmeOrder):
    """
    This factory dynamically generates functions for handling an order's Authorization(s)

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authenticatedUser: (required) a :class:`lib.acme_v2.AuthenticatedUser` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    """

    def handle_authorization_payload(
        authorization_url,
        authorization_response,
        dbAcmeAuthorization=None,
        transaction_commit=None,
    ):
        """
        :param authorization_url: (required) The URL of the ACME Directory's Authorization Object.
        :param authorization_response: (required) The JSON object corresponding to the ACME Directory's Authorization Object.
        :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object for the authorization_url if it already exists
        :param transaction_commit: (required) Boolean. Must indicate that we will commit this.

        the getcreate will do the following:
            create/update the Authorization object
            create/update the Challenge object
        """
        log.info(
            "_AcmeV2_factory_AuthHandlers.handle_authorization_payload( %s",
            authorization_url,
        )
        if transaction_commit is not True:
            raise ValueError("we must invoke this knowing it will commit")

        if dbAcmeAuthorization is not None:
            if authorization_url != dbAcmeAuthorization.authorization_url:
                raise ValueError("`authorization_url` does not match")

        if dbAcmeAuthorization is None:
            # this will sync the payload via `update_AcmeAuthorization_from_payload`
            (
                dbAcmeAuthorization,
                _is_created,
            ) = lib.db.getcreate.getcreate__AcmeAuthorization(
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
            _result = lib.db.getcreate.process__AcmeAuthorization_payload(
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
    ctx, authenticatedUser, dbAcmeOrder, acmeOrderRfcObject
):
    """
    Consolidated AcmeOrder routine for processing multiple Authorizations

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authenticatedUser: (required) a :class:`lib.acme_v2.AuthenticatedUser` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param acmeRfcOrder: (required) a :class:`lib.acme_v2.AcmeOrderRFC` instance
    """
    handle_authorization_payload = _AcmeV2_factory_AuthHandlers(
        ctx, authenticatedUser, dbAcmeOrder
    )

    _todo_finalize_order = None
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
            _todo_finalize_order = True
        except errors.AcmeAuthorizationFailure as exc:
            # this order is essentially failed
            (
                acmeOrderRfcObject,
                dbAcmeOrderEventLogged,
            ) = authenticatedUser.acme_order_load(
                ctx, dbAcmeOrder=dbAcmeOrder, transaction_commit=True,
            )
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acmeOrderRfcObject.rfc_object,
                acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_completed_failure,
                transaction_commit=True,
            )
            if ctx.request.registry.settings["app_settings"][
                "cleanup_pending_authorizations"
            ]:
                log.info(
                    "AcmeOrder failed, going to deactivate remaining authorizations"
                )
                do__AcmeV2_AcmeOrder__acme_server_deactivate_authorizations(
                    ctx, dbAcmeOrder=dbAcmeOrder, authenticatedUser=authenticatedUser,
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
            _todo_finalize_order = True
        elif _order_status == "processing":
            # The certificate is being issued.
            # Send a POST-as-GET request after the time given in the Retry-After header field of the response, if any.
            # TODO: Post-as-GET this semi-completed order
            raise ValueError("todo: download")
        elif _order_status == "valid":
            # The server has issued the certificate and provisioned its URL to the "certificate" field of the order
            # TODO: download the url of this order
            raise ValueError("todo: download")
        else:
            raise ValueError("unsure how to handle this status: `%s`" % _order_status)
    return _todo_finalize_order


def do__AcmeV2_AcmeAuthorization__acme_server_deactivate(
    ctx, dbAcmeAuthorization=None, authenticatedUser=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object to deactivate on the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    if not dbAcmeAuthorization:
        raise ValueError("Must submit `dbAcmeAuthorization`")
    if not dbAcmeAuthorization.is_can_acme_server_deactivate:
        raise ValueError("Can not deactivate this `AcmeAuthorization`")

    if not dbAcmeAuthorization.acme_order_id__created:
        raise ValueError("can not proceed without an order for this authorization")

    tmpfiles = []
    try:
        # the authorization could be on multiple AcmeOrders
        # see :method:`AcmeAuthorization.to_acme_orders`
        dbAcmeOrderCreated = dbAcmeAuthorization.acme_order_created

        # we need to use tmpfiles on the disk
        if authenticatedUser is None:
            dbAcmeAccountKey = dbAcmeAuthorization.acme_order_created.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrderCreated)

        try:
            (
                authorization_response,
                dbAcmeEventLog_authorization_fetch,
            ) = authenticatedUser.acme_authorization_deactivate(
                ctx, dbAcmeAuthorization=dbAcmeAuthorization, transaction_commit=True,
            )
            _result = update_AcmeAuthorization_status(
                ctx,
                dbAcmeAuthorization,
                authorization_response["status"],
                transaction_commit=True,
            )
            # todo: update the other fields and challenges from this authorization
            return True
        except errors.AcmeServer404 as exc:
            update_AcmeAuthorization_status(
                ctx, dbAcmeAuthorization, "*404*", transaction_commit=True
            )
            return False

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeV2_AcmeAuthorization__acme_server_sync(
    ctx, dbAcmeAuthorization=None, authenticatedUser=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object to refresh against the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    if not dbAcmeAuthorization:
        raise ValueError("Must submit `dbAcmeAuthorization`")
    if not dbAcmeAuthorization.is_can_acme_server_sync:
        raise ValueError("Can not sync this `AcmeAuthorization`")

    if not dbAcmeAuthorization.acme_order_id__created:
        raise ValueError("can not proceed without an order for this authorization")

    tmpfiles = []
    try:
        # the authorization could be on multiple AcmeOrders
        # see :method:`AcmeAuthorization.to_acme_orders`
        dbAcmeOrderCreated = dbAcmeAuthorization.acme_order_created

        if authenticatedUser is None:
            dbAcmeAccountKey = dbAcmeAuthorization.acme_order_created.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrderCreated)

        try:
            (
                authorization_response,
                dbAcmeEventLog_authorization_fetch,
            ) = authenticatedUser.acme_authorization_load(
                ctx, dbAcmeAuthorization=dbAcmeAuthorization, transaction_commit=True,
            )

            # update the the Authorization object
            _updated = update_AcmeAuthorization_from_payload(
                ctx, dbAcmeAuthorization, authorization_response
            )

            # maybe there are challenges in the payload?
            try:
                (
                    dbAcmeChallenge,
                    is_created_AcmeChallenge,
                ) = lib.db.getcreate.getcreate__AcmeChallengeHttp01_via_payload(
                    ctx,
                    authenticatedUser=authenticatedUser,
                    dbAcmeAuthorization=dbAcmeAuthorization,
                    authorization_payload=authorization_response,
                )
            except errors.AcmeMissingChallenges as exc:
                pass

            return True
        except errors.AcmeServer404 as exc:
            update_AcmeAuthorization_status(
                ctx, dbAcmeAuthorization, "*404*", transaction_commit=True
            )
            return False

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeV2_AcmeAuthorization__acme_server_trigger(
    ctx, dbAcmeAuthorization=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object to trigger against the server
    """
    if not dbAcmeAuthorization:
        raise ValueError("Must submit `dbAcmeAuthorization`")
    if not dbAcmeAuthorization.is_can_acme_server_trigger:
        # ensures we have 'pending' status and
        # http-01 challenge
        # acme order, with acme_account_key
        raise ValueError("Can not trigger this `AcmeAuthorization`")

    dbAcmeChallenge = dbAcmeAuthorization.acme_challenge_http01
    return do__AcmeV2_AcmeChallenge__acme_server_trigger(ctx, dbAcmeChallenge)


def do__AcmeV2_AcmeChallenge__acme_server_trigger(
    ctx, dbAcmeChallenge=None, authenticatedUser=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge` object to trigger against the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    
    :returns: a boolean result True/False
    """
    if not dbAcmeChallenge:
        raise ValueError("Must submit `dbAcmeChallenge`")
    if not dbAcmeChallenge.is_can_acme_server_trigger:
        # ensures we have 'pending' status and
        # acme order, with acme_account_key
        raise ValueError("Can not trigger this `AcmeChallenge`")

    tmpfiles = []
    try:
        # this is used a bit
        dbAcmeAuthorization = dbAcmeChallenge.acme_authorization

        if not dbAcmeAuthorization.acme_order_id__created:
            raise ValueError("can not proceed without an order for this authorization")

        # the authorization could be on multiple AcmeOrders
        # see :method:`AcmeAuthorization.to_acme_orders`
        dbAcmeOrderCreated = dbAcmeAuthorization.acme_order_created
        _passes = None
        for _to_acme_order in dbAcmeAuthorization.to_acme_orders:
            if (
                _to_acme_order.acme_order.acme_order_processing_status_id
                in model_utils.AcmeOrder_ProcessingStatus.IDS_CAN_PROCESS_CHALLENGES
            ):
                _passes = True
        if not _passes:
            raise ValueError(
                "Can not process AcmeChallenges for any associated AcmeOrders"
            )

        if authenticatedUser is None:
            # the associated AcmeOrders should all have the same AcmeAccountKey
            dbAcmeAccountKey = dbAcmeOrderCreated.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrderCreated)

        try:
            challenge_response = authenticatedUser.acme_challenge_trigger(
                ctx,
                dbAcmeChallenge=dbAcmeChallenge,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
                transaction_commit=True,
            )

            # todo: update the other fields from this challenge
            # todo: log the payload and error

            # update the AcmeAuthorization if it's not the same on the database
            update_AcmeChallenge_status(
                ctx,
                dbAcmeChallenge,
                challenge_response["status"],
                transaction_commit=True,
            )
            return True

        except errors.AcmeServer404 as exc:
            update_AcmeChallenge_status(
                ctx, dbAcmeChallenge, "*404*", transaction_commit=True
            )

        except errors.AcmeAuthorizationFailure as exc:
            # todo: log/inspect the payload and update more objects
            update_AcmeAuthorization_status(
                ctx, dbAcmeAuthorization, "invalid", transaction_commit=True
            )

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
                        transaction_commit=True,
                    )
    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()
    return True


def do__AcmeV2_AcmeChallenge__acme_server_sync(
    ctx, dbAcmeChallenge=None, authenticatedUser=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge` object to refresh against the server
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    if not dbAcmeChallenge:
        raise ValueError("Must submit `dbAcmeChallenge`")
    if not dbAcmeChallenge.is_can_acme_server_sync:
        raise ValueError("Can not sync this `dbAcmeChallenge` (0)")

    if not dbAcmeChallenge.acme_authorization.acme_order_id__created:
        raise ValueError("can not proceed without an order for this challenge")

    tmpfiles = []
    try:
        # this is used a bit
        dbAcmeAuthorization = dbAcmeChallenge.acme_authorization

        if not dbAcmeAuthorization.acme_order_id__created:
            raise ValueError("can not proceed without an order for this authorization")

        # the account-key will be the same across linked orders/auths
        dbAcmeOrderCreated = dbAcmeAuthorization.acme_order_created
        if authenticatedUser is None:
            dbAcmeAccountKey = dbAcmeOrderCreated.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrderCreated)

        try:
            (
                challenge_response,
                dbAcmeEventLog_challenge_fetch,
            ) = authenticatedUser.acme_challenge_load(
                ctx, dbAcmeChallenge=dbAcmeChallenge, transaction_commit=True,
            )
        except errors.AcmeServer404 as exc:
            update_AcmeChallenge_status(
                ctx, dbAcmeChallenge, "*404*", transaction_commit=True
            )

        # todo: update the other fields from this challenge
        # todo: log the payload and error

        # update the AcmeAuthorization if it's not the same on the database
        _server_status = challenge_response["status"]
        update_AcmeChallenge_status(
            ctx, dbAcmeChallenge, _server_status, transaction_commit=True
        )
        return True

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeV2_AcmeOrder__acme_server_sync(
    ctx, dbAcmeOrder=None, authenticatedUser=None,
):
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
            dbAcmeAccountKey = dbAcmeOrder.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
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
                ctx, dbAcmeOrder=dbAcmeOrder, transaction_commit=True,
            )
            is_order_404 = False

            # update the AcmeOrder if it's not the same on the database
            # always invoke this, as it handles it's own cleanup of the model
            result = updated_AcmeOrder_status(
                ctx, dbAcmeOrder, acmeOrderRfcObject.rfc_object, transaction_commit=True
            )
            return dbAcmeOrder

        except errors.AcmeServer404 as exc:
            is_order_404 = True
            updated_AcmeOrder_status(
                ctx, dbAcmeOrder, acme_v2.new_response_404(), transaction_commit=True
            )
            return dbAcmeOrder

        # if is_order_404:
        #    # TODO: raise an exception if we don't have an acmeOrder
        #    # TODO: update the authorizations/challenges from the order
        #    pass

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeV2_AcmeOrder__acme_server_sync_authorizations(
    ctx, dbAcmeOrder=None, authenticatedUser=None
):
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
            dbAcmeAccountKey = dbAcmeOrder.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
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
                ctx, dbAcmeOrder=dbAcmeOrder, transaction_commit=True,
            )
            is_order_404 = False

            # always invoke this, as it handles it's own cleanup of the model
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acmeOrderRfcObject.rfc_object,
                transaction_commit=True,
            )

        except errors.AcmeServer404 as exc:
            is_order_404 = True
            updated_AcmeOrder_status(
                ctx, dbAcmeOrder, acme_v2.new_response_404(), transaction_commit=True
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
                ) = lib.db.getcreate.getcreate__AcmeAuthorizationUrl(
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
            tf.close()


def do__AcmeV2_AcmeAccountKey__acme_server_deactivate_authorizations(
    ctx, dbAcmeAccountKey=None, acme_authorization_ids=None, authenticatedUser=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object that owns the authorization ids
    :param int acme_authorization_ids: (required) An iterable of AcmeAuthoriationIds to deactivate
    :param authenticatedUser: (optional) An authenticated instance of :class:`acme_v2.AuthenticatedUser`
    """
    if not dbAcmeAccountKey:
        raise ValueError("Must submit `dbAcmeAccountKey`")

    tmpfiles = []
    try:
        if authenticatedUser is None:
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
            )
            tmpfiles.append(tmpfile_account)

        dbAcmeAuthorizations = lib.db.get.get__AcmeAuthorizations__by_ids(
            ctx, acme_authorization_ids, acme_account_key_id=dbAcmeAccountKey.id
        )
        results = {id_: False for id_ in acme_authorization_ids}
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
                transaction_commit=True,
            )
            # TODO: transition AcmeOrder
            # TODO: transition AcmeChallenge
        return results
    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeV2_AcmeOrder__acme_server_deactivate_authorizations(
    ctx, dbAcmeOrder=None, authenticatedUser=None,
):
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
            dbAcmeAccountKey = dbAcmeOrder.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
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
                ctx, dbAcmeOrder=dbAcmeOrder, transaction_commit=True,
            )
            is_order_404 = False
        except errors.AcmeServer404 as exc:
            is_order_404 = True
            updated_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acme_v2.new_response_404(),
                is_processing_False=True,
                transaction_commit=True,
            )

        is_auth_404 = None
        for dbAcmeAuthorization in dbAcmeOrder.authorizations_can_deactivate:
            is_auth_404 = None
            try:
                (
                    authorization_response,
                    dbAcmeEventLog_authorization_fetch,
                ) = authenticatedUser.acme_authorization_deactivate(
                    ctx,
                    dbAcmeAuthorization=dbAcmeAuthorization,
                    transaction_commit=True,
                )
                is_auth_404 = False
            except errors.AcmeServer404 as exc:
                is_auth_404 = True
                authorization_response = acme_v2.new_response_404()
            update_AcmeAuthorization_status(
                ctx,
                dbAcmeAuthorization,
                authorization_response["status"],
                transaction_commit=True,
            )

        # TODO: raise an exception if we don't have an acmeOrderRfcObject
        # TODO: update the authorizations/challenges from the order
        #       is this allowed though? the challenge doesn't have a revoked state

        # update the AcmeOrder if it's not the same on the database
        if not is_order_404:
            try:
                (
                    acmeOrderRfcObject,
                    dbAcmeOrderEventLogged,
                ) = authenticatedUser.acme_order_load(
                    ctx, dbAcmeOrder=dbAcmeOrder, transaction_commit=True,
                )
                # always invoke this, as it handles some cleanup routines
                return updated_AcmeOrder_status(
                    ctx,
                    dbAcmeOrder,
                    acmeOrderRfcObject.rfc_object,
                    acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_deactivated,
                    is_processing_False=True,
                    transaction_commit=True,
                )
            except Exception as exc:
                raise

        return False

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def _do__AcmeV2_AcmeOrder__finalize(
    ctx, authenticatedUser=None, dbAcmeOrder=None,
):
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
        # stash it into `dbPrivateKeyNew` and reassign in an `except` block
        dbPrivateKeyNew = None
        # outer `try/except` catches `ReassignedPrivateKey`
        try:
            # inner `try/except` catches `AcmeAccountKeyNeedsPrivateKey`
            try:
                if dbAcmeOrder.private_key_id == 0:
                    # Multiple logic lines for `dbAcmeOrder.private_key_strategy__requested`
                    if (
                        dbAcmeOrder.private_key_strategy__requested
                        == "deferred-generate"
                    ):
                        private_key_strategy__final = "deferred-generate"
                        # NOTE: deferred-generate ; single_certificate
                        dbPrivateKeyNew = lib.db.create.create__PrivateKey(
                            ctx,
                            # bits=4096,
                            acme_account_key_id__owner=dbAcmeOrder.acme_account_key.id,
                            private_key_source_id=model_utils.PrivateKeySource.from_string(
                                "generated"
                            ),
                            private_key_type_id=model_utils.PrivateKeyType.from_string(
                                "single_certificate"  # this COULD be "standard", but safer to lock down for now
                            ),
                        )
                        raise ReassignedPrivateKey("new `generated`")
                    elif (
                        dbAcmeOrder.private_key_strategy__requested
                        == "deferred-associate"
                    ):

                        # all these items should share the same final strategy
                        private_key_strategy__final = "deferred-associate"
                        raise AcmeAccountKeyNeedsPrivateKey()

                    else:
                        raise ValueError(
                            "Invalid `private_key_strategy__requested` for placeholder AcmeAccountKey"
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
                        raise AcmeAccountKeyNeedsPrivateKey()

                # we MUST have encountered an Exception already
                raise ValueError("Invalid Logic")

            except AcmeAccountKeyNeedsPrivateKey as exc:
                # look the `dbAcmeOrder.acme_account_key.private_key_cycle`
                dbPrivateKey_new = lib.db.getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
                    ctx, dbAcmeAccountKey=dbAcmeOrder.acme_account_key,
                )
                raise ReassignedPrivateKey("new PrivateKey")

            # we MUST have encountered an Exception already
            raise ValueError("Invalid Logic")

        except ReassignedPrivateKey as exc:
            # assign this over!
            dbAcmeOrder.private_key = dbPrivateKey_new
            ctx.dbSession.flush(
                objects=[dbAcmeOrder, dbPrivateKey_new,]
            )
            dbPrivateKey = dbPrivateKey_new

        except PrivateKeyOk as exc:
            pass

        # set the PrivateKeyStrategy
        dbAcmeOrder.private_key_strategy_id__final = model_utils.PrivateKeyStrategy.from_string(
            private_key_strategy__final
        )
        ctx.dbSession.flush(
            objects=[dbAcmeOrder,]
        )

        # we need to use tmpfiles on the disk for the Private Key signing
        private_key_pem = dbAcmeOrder.private_key.key_pem
        tmpfile_pkey = cert_utils.new_pem_tempfile(private_key_pem)
        tmpfiles.append(tmpfile_pkey)

        # what are the domain names?
        domain_names = dbAcmeOrder.domains_as_list

        tmpfile_csr = None
        if dbAcmeOrder.certificate_request:
            dbCertificateRequest = dbAcmeOrder.certificate_request
            csr_pem = dbCertificateRequest.csr_pem
            tmpfile_csr = cert_utils.new_pem_tempfile(csr_pem)
            tmpfiles.append(tmpfile_csr)
        else:
            # make the CSR
            csr_pem = cert_utils.new_csr_for_domain_names(
                domain_names, private_key_path=tmpfile_pkey.name
            )
            tmpfile_csr = cert_utils.new_pem_tempfile(csr_pem)
            tmpfiles.append(tmpfile_csr)

            # immediately commit this
            dbCertificateRequest = lib.db.create.create__CertificateRequest(
                ctx,
                csr_pem,
                certificate_request_source_id=model_utils.CertificateRequestSource.ACME_ORDER,
                dbPrivateKey=dbAcmeOrder.private_key,
                dbServerCertificate__issued=None,
                domain_names=domain_names,
            )
            # dbAcmeOrder.certificate_request_id = dbCertificateRequest.id
            dbAcmeOrder.certificate_request = dbCertificateRequest
            ctx.pyramid_transaction_commit()

        # pull domains from csr
        csr_domains = cert_utils.parse_csr_domains(
            csr_path=tmpfile_csr.name, submitted_domain_names=domain_names
        )
        if set(csr_domains) != set(domain_names):
            raise ValueError(
                "The CertificateRequest does not have the expected Domains."
            )

        # sign and download
        try:
            fullchain_pem = authenticatedUser.acme_order_finalize(
                ctx,
                dbAcmeOrder=dbAcmeOrder,
                update_order_status=updated_AcmeOrder_status,
                csr_path=tmpfile_csr.name,
                transaction_commit=True,
            )
        except errors.AcmeServer404 as exc:
            updated_AcmeOrder_status(
                ctx, dbAcmeOrder, acme_v2.new_response_404(), transaction_commit=True
            )
            raise

        (certificate_pem, ca_chain_pem) = utils_certbot.cert_and_chain_from_fullchain(
            fullchain_pem
        )

        (
            dbCACertificate,
            is_created__CACertificate,
        ) = lib.db.getcreate.getcreate__CACertificate__by_pem_text(
            ctx,
            ca_chain_pem,
            ca_chain_name="ACME Server Response",
            le_authority_name=None,
            is_authority_certificate=None,
            is_cross_signed_authority_certificate=None,
        )
        if is_created__CACertificate:
            ctx.pyramid_transaction_commit()

        # immediately commit this
        dbServerCertificate = lib.db.create.create__ServerCertificate(
            ctx,
            cert_pem=certificate_pem,
            cert_domains_expected=domain_names,
            is_active=True,
            dbAcmeOrder=dbAcmeOrder,
            dbCACertificate=dbCACertificate,
            dbCertificateRequest=dbCertificateRequest,
        )
        # dbAcmeOrder.server_certificate_id = dbServerCertificate.id
        dbAcmeOrder.server_certificate = dbServerCertificate

        # note that we've completed this!
        dbAcmeOrder.acme_order_processing_status_id = (
            model_utils.AcmeOrder_ProcessingStatus.certificate_downloaded
        )

        ctx.pyramid_transaction_commit()

        # update the logger
        authenticatedUser.acmeLogger.log_CertificateProcured(
            "v2",
            dbServerCertificate=dbServerCertificate,
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
            tf.close()


def _do__AcmeV2_AcmeOrder__core(
    ctx,
    acme_order_type_id=None,
    domain_names=None,
    private_key_cycle__renewal=None,
    private_key_strategy__requested=None,
    processing_strategy=None,
    dbAcmeAccountKey=None,
    dbAcmeOrder_renewal_of=None,
    dbAcmeOrder_retry_of=None,
    dbUniqueFQDNSet=None,
    dbPrivateKey=None,
    dbQueueCertificate__of=None,
    dbServerCertificate__renewal_of=None,
):
    """

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param acme_order_type_id: (required) What type of order is this? A value from :class:`model.objects.AcmeOrderType`
    :param domain_names: (optional) An iteratble list of domain names
    :param private_key_cycle__renewal: (required)  A value from :class:`model.utils.PrivateKeyCycle`
    :param private_key_strategy__requested: (required)  A value from :class:`model.utils.PrivateKeyStrategy`
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
    :param dbAcmeOrder_renewal_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbAcmeOrder_retry_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbUniqueFQDNSet: (optional) A :class:`model.objects.dbUniqueFQDNSet` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param dbQueueCertificate__of: (optional) A :class:`model.objects.QueueCertificate` object
    :param dbServerCertificate__renewal_of: (optional) A :class:`model.objects.ServerCertificate` object

    One and only one of the following items must be provided:
        dbAcmeOrder_retry_of
        dbAcmeOrder_renewal_of
        dbQueueCertificate__of
        dbServerCertificate__renewal_of

    One and only one of the following items must be provided:
        domain_names
        dbUniqueFQDNSet

    :returns: A class:`model.objects.AcmeOrder` object for the new AcmeOrder
    """
    # validate this first!
    acme_order_processing_strategy_id = model_utils.AcmeOrder_ProcessingStrategy.from_string(
        processing_strategy
    )
    private_key_cycle_id__renewal = model_utils.PrivateKeyCycle.from_string(
        private_key_cycle__renewal
    )
    private_key_strategy_id__requested = model_utils.PrivateKeyStrategy.from_string(
        private_key_strategy__requested
    )

    # some things can't be triggered together
    if all((domain_names, dbUniqueFQDNSet)) or not any((domain_names, dbUniqueFQDNSet)):
        if dbAcmeOrder_retry_of or dbAcmeOrder_renewal_of:
            if any((domain_names, dbUniqueFQDNSet)):
                raise ValueError(
                    "do not submit `dbAcmeOrder_retry_of` or `dbAcmeOrder_renewal_of` with either: `domain_names, dbUniqueFQDNSet`"
                )
        else:
            raise ValueError(
                "must submit one and only one of: `domain_names, dbUniqueFQDNSet`"
            )
    if domain_names:
        if any(
            (
                dbAcmeOrder_retry_of,
                dbAcmeOrder_renewal_of,
                dbQueueCertificate__of,
                dbServerCertificate__renewal_of,
                dbUniqueFQDNSet,
            )
        ):
            raise ValueError(
                "do not pass `domain_names` with any of `(dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of, dbQueueCertificate__of, dbServerCertificate__renewal_of, dbUniqueFQDNSet)`"
            )

    if (
        sum(
            bool(i)
            for i in (
                dbAcmeOrder_retry_of,
                dbAcmeOrder_renewal_of,
                dbQueueCertificate__of,
                dbServerCertificate__renewal_of,
                dbUniqueFQDNSet,
            )
        )
        >= 2
    ):
        raise ValueError(
            "At most, provide one of (`dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of, dbQueueCertificate__of, dbServerCertificate__renewal_of`)"
        )

    # switch this
    if dbAcmeOrder_retry_of:
        # kwargs validation
        if dbAcmeAccountKey:
            raise ValueError(
                "Must NOT submit `dbAcmeAccountKey` with `dbAcmeOrder_retry_of`"
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
        dbAcmeAccountKey = dbAcmeOrder_retry_of.acme_account_key
        dbPrivateKey = dbAcmeOrder_retry_of.private_key
        dbUniqueFQDNSet = dbAcmeOrder_retry_of.unique_fqdn_set
        domain_names = dbAcmeOrder_retry_of.domains_as_list

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
        if not dbAcmeAccountKey:
            dbAcmeAccountKey = dbAcmeOrder_renewal_of.acme_account_key

        if not dbPrivateKey:
            # raise ValueError("Must submit `dbPrivateKey`")
            dbPrivateKey = dbAcmeOrder_renewal_of.private_key

        # re-use these related objects
        dbUniqueFQDNSet = dbAcmeOrder_renewal_of.unique_fqdn_set
        domain_names = dbAcmeOrder_renewal_of.domains_as_list

    elif dbQueueCertificate__of:
        # kwargs validation
        # after creating the AcmeOrder, we need to update the `dbQueueCertificate__of` with the info

        # TODO - dbQueueCertificate__of
        raise ValueError("#TODO")
        if dbQueueCertificate__of:
            dbQueueCertificate__of.timestamp_processed = ctx.timestamp
            dbQueueCertificate__of.process_result = True
            dbQueueCertificate__of.is_active = False
            ctx.dbSession.flush(objects=[dbQueueCertificate__of])

    elif dbServerCertificate__renewal_of:
        # kwargs validation
        # after creating the order, update it with info
        #            dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,

        raise ValueError("todo")

        # todo - transfer this onto the acme-order
        if dbServerCertificate__renewal_of:
            dbServerCertificate__renewal_of.is_auto_renew = False
            dbServerCertificate__renewal_of.is_renewed = True
            ctx.dbSession.flush(objects=[dbServerCertificate__renewal_of])

        if not dbAcmeAccountKey:
            raise ValueError(
                "Must submit `dbAcmeAccountKey` with `dbAcmeOrder_renewal_of`"
            )
        if not dbPrivateKey:
            raise ValueError("Must submit `dbPrivateKey`")

        # re-use these related objects
        dbUniqueFQDNSet = dbServerCertificate__renewal_of.unique_fqdn_set
        domain_names = dbServerCertificate__renewal_of.domains_as_list

    elif dbUniqueFQDNSet:
        # kwargs validation
        if not dbAcmeAccountKey:
            raise ValueError("Must submit `dbAcmeAccountKey` with `dbUniqueFQDNSet`")
        if not dbPrivateKey:
            raise ValueError("Must submit `dbPrivateKey`")

    # ensure the PrivateKey is usable!
    if not dbPrivateKey.is_key_usable:
        raise errors.InvalidRequest(
            "The `dbPrivateKey` is not usable. It was deactivated or compromised.`"
        )

    # ensure we have domains names!
    if not any((domain_names, dbUniqueFQDNSet)):
        raise ValueError("No `domain_names` detected for this request")

    if not dbUniqueFQDNSet:
        (
            dbUniqueFQDNSet,
            is_created_fqdn,
        ) = lib.db.getcreate.getcreate__UniqueFQDNSet__by_domains(ctx, domain_names)
        ctx.pyramid_transaction_commit()

    # check each domain for an existing active challenge
    active_challenges = []
    for to_domain in dbUniqueFQDNSet.to_domains:
        _active_challenge = lib.db.get.get__AcmeChallenge__by_DomainId__active(
            ctx, to_domain.domain_id
        )
        if _active_challenge:
            active_challenges.append(_active_challenge)
    if active_challenges:
        raise errors.AcmeDuplicateChallengesExisting(active_challenges)

    tmpfiles = []
    dbAcmeOrder = None
    dbServerCertificate = None
    try:
        (authenticatedUser, tmpfile_account) = new_Authenticated_user(
            ctx, dbAcmeAccountKey
        )
        tmpfiles.append(tmpfile_account)

        # create the order on the ACME server
        (acmeOrderRfcObject, dbAcmeOrderEventLogged) = authenticatedUser.acme_order_new(
            ctx,
            domain_names=domain_names,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            transaction_commit=True,
        )
        try:
            order_url = acmeOrderRfcObject.response_headers["location"]
        except:
            order_url = None

        # in the current application design, `authenticatedUser.acme_order_new` created the order on the acme server
        acme_order_processing_status_id = model_utils.AcmeOrder_ProcessingStatus.from_string(
            "created_acme"
        )

        # enroll the Acme Order into our database
        dbAcmeOrder = lib.db.create.create__AcmeOrder(
            ctx,
            acme_order_response=acmeOrderRfcObject.rfc_object,
            acme_order_type_id=acme_order_type_id,
            acme_order_processing_status_id=acme_order_processing_status_id,
            acme_order_processing_strategy_id=acme_order_processing_strategy_id,
            private_key_cycle_id__renewal=private_key_cycle_id__renewal,
            private_key_strategy_id__requested=private_key_strategy_id__requested,
            order_url=order_url,
            dbAcmeAccountKey=dbAcmeAccountKey,
            dbAcmeOrder_retry_of=dbAcmeOrder_retry_of,
            dbAcmeOrder_renewal_of=dbAcmeOrder_renewal_of,
            dbPrivateKey=dbPrivateKey,
            dbEventLogged=dbAcmeOrderEventLogged,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            transaction_commit=True,
        )

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

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
            _todo_finalize_order = _AcmeV2_AcmeOrder__process_authorizations(
                ctx, authenticatedUser, dbAcmeOrder, acmeOrderRfcObject
            )
            if not _todo_finalize_order:
                return dbAcmeOrder

            dbAcmeOrder = _do__AcmeV2_AcmeOrder__finalize(
                ctx, authenticatedUser=authenticatedUser, dbAcmeOrder=dbAcmeOrder,
            )
            return dbAcmeOrder

        return dbAcmeOrder

    except errors.AcmeOrderFatal as exc:
        raise errors.AcmeOrderCreatedError(dbAcmeOrder, exc)

    except Exception as exc:
        raise

    finally:
        if (
            processing_strategy
            in model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_DEACTIVATE_AUTHS
        ):
            # shut this down to deactivate the auths on our side
            if dbAcmeOrder:
                dbAcmeOrder.is_processing = None
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeV2_AcmeOrder__finalize(
    ctx, dbAcmeOrder=None, authenticatedUser=None,
):
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
            dbAcmeAccountKey = dbAcmeOrder.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
            )
            tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        dbAcmeOrder = _do__AcmeV2_AcmeOrder__finalize(
            ctx, authenticatedUser=authenticatedUser, dbAcmeOrder=dbAcmeOrder,
        )

        return dbAcmeOrder

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeV2_AcmeOrder__process(
    ctx, dbAcmeOrder=None, authenticatedUser=None,
):
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
            dbAcmeAccountKey = dbAcmeOrder.acme_account_key
            (authenticatedUser, tmpfile_account) = new_Authenticated_user(
                ctx, dbAcmeAccountKey
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
                    # acme order, with acme_account_key
                    raise ValueError("Can not trigger the `AcmeAuthorization`")

                handle_authorization_payload = _AcmeV2_factory_AuthHandlers(
                    ctx, authenticatedUser, dbAcmeOrder
                )

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
                        transaction_commit=True,
                    )
                else:
                    dbAcmeChallenge = dbAcmeAuthorization.acme_challenge_http01
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
                ctx, authenticatedUser=authenticatedUser, dbAcmeOrder=dbAcmeOrder,
            )
        else:
            raise errors.GarfieldMinusGarfield("unsure how this happened")

        return dbAcmeOrder

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeV2_AcmeOrder__new(
    ctx,
    acme_order_type_id=None,
    domain_names=None,
    processing_strategy=None,
    private_key_cycle__renewal=None,
    private_key_strategy__requested=None,
    dbAcmeAccountKey=None,
    dbPrivateKey=None,
    dbServerCertificate__renewal_of=None,
    dbQueueCertificate__of=None,
):
    """
    Automates a Certificate deployment from LetsEncrypt

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param acme_order_type_id: (required) What type of order is this? A value from :class:`model.objects.AcmeOrderType`
    :param domain_names: (required) An iteratble list of domain names
    :param private_key_cycle__renewal: (required)  A value from :class:`model.utils.PrivateKeyCycle`
    :param private_key_strategy__requested: (required)  A value from :class:`model.utils.PrivateKeyStrategy`
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param dbQueueCertificate__of: (optional) A :class:`model.objects.QueueCertificate` object
    :param dbServerCertificate__renewal_of: (optional) A :class:`model.objects.ServerCertificate` object

    :returns: A :class:`model.objects.AcmeOrder` object
    """
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("AcmeOrder_New_Automated"),
    )
    return _do__AcmeV2_AcmeOrder__core(
        ctx,
        domain_names=domain_names,
        acme_order_type_id=acme_order_type_id,
        private_key_cycle__renewal=private_key_cycle__renewal,
        private_key_strategy__requested=private_key_strategy__requested,
        processing_strategy=processing_strategy,
        dbAcmeAccountKey=dbAcmeAccountKey,
        dbPrivateKey=dbPrivateKey,
        dbQueueCertificate__of=dbQueueCertificate__of,
        dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
    )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeV2_AcmeOrder__download_certificate(
    ctx, dbAcmeOrder=None,
):
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
    tmpfiles = []
    try:
        # we need to use tmpfiles on the disk
        dbAcmeAccountKey = dbAcmeOrder.acme_account_key
        (authenticatedUser, tmpfile_account) = new_Authenticated_user(
            ctx, dbAcmeAccountKey
        )
        tmpfiles.append(tmpfile_account)

        # register the AcmeOrder into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        fullchain_pem = authenticatedUser.download_certificate(
            dbAcmeOrder.certificate_url
        )
        (certificate_pem, ca_chain_pem) = utils_certbot.cert_and_chain_from_fullchain(
            fullchain_pem
        )
        (
            dbCACertificate,
            is_created__CACertificate,
        ) = lib.db.getcreate.getcreate__CACertificate__by_pem_text(
            ctx,
            ca_chain_pem,
            ca_chain_name="ACME Server Response",
            le_authority_name=None,
            is_authority_certificate=None,
            is_cross_signed_authority_certificate=None,
        )
        if is_created__CACertificate:
            ctx.pyramid_transaction_commit()

        (
            dbServerCertificate,
            _is_created__cert,
        ) = lib.db.getcreate.getcreate__ServerCertificate(
            ctx,
            cert_pem=certificate_pem,
            cert_domains_expected=dbAcmeOrder.domains_as_list,
            dbAcmeOrder=dbAcmeOrder,
            dbCACertificate=dbCACertificate,
            dbPrivateKey=dbAcmeOrder.private_key,
        )
        if dbAcmeOrder.server_certificate:
            if dbAcmeOrder.server_certificate_id != dbServerCertificate.id:
                raise ValueError("competing certificates for this AcmeOrder")
        else:
            # dbAcmeOrder.server_certificate_id = dbServerCertificate.id
            dbAcmeOrder.server_certificate = dbServerCertificate

        # note that we've completed this!
        dbAcmeOrder.acme_order_processing_status_id = (
            model_utils.AcmeOrder_ProcessingStatus.certificate_downloaded
        )

        ctx.pyramid_transaction_commit()

        # update the logger
        authenticatedUser.acmeLogger.log_CertificateProcured(
            "v2",
            dbServerCertificate=dbServerCertificate,
            dbCertificateRequest=dbAcmeOrder.certificate_request,
            transaction_commit=True,
        )

        # don't commit here, as that will trigger an error on object refresh
        return dbAcmeOrder

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeV2_AcmeOrder__retry(
    ctx, dbAcmeOrder=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`

    :returns: A :class:`model.objects.AcmeOrder` object for the new AcmeOrder
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("AcmeOrder_New_Retry"),
    )
    return _do__AcmeV2_AcmeOrder__core(
        ctx,
        acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_RETRY,
        private_key_cycle__renewal=dbAcmeOrder.private_key_cycle__renewal,
        private_key_strategy__requested=dbAcmeOrder.private_key_strategy__requested,
        processing_strategy=dbAcmeOrder.acme_order_processing_strategy,
        dbAcmeOrder_retry_of=dbAcmeOrder,
    )


def do__AcmeV2_AcmeOrder__renew_custom(
    ctx,
    dbAcmeOrder=None,
    dbAcmeAccountKey=None,
    dbPrivateKey=None,
    processing_strategy=None,
    private_key_cycle__renewal=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param private_key_cycle__renewal: (required)  A value from :class:`model.utils.PrivateKeyCycle`

    :returns: A :class:`model.objects.AcmeOrder` object for the new AcmeOrder
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    if not dbAcmeAccountKey:
        raise ValueError("Must submit `dbAcmeAccountKey`")
    if not dbPrivateKey:
        raise ValueError("Must submit `dbPrivateKey`")
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("AcmeOrder_Renew_Custom"),
    )
    # private_key_strategy__requested - pull off the original
    return _do__AcmeV2_AcmeOrder__core(
        ctx,
        acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_RENEW_CUSTOM,
        private_key_cycle__renewal=private_key_cycle__renewal,
        private_key_strategy__requested=dbAcmeOrder.private_key_strategy__requested,
        processing_strategy=processing_strategy,
        dbAcmeOrder_renewal_of=dbAcmeOrder,
        dbAcmeAccountKey=dbAcmeAccountKey,
        dbPrivateKey=dbPrivateKey,
    )


def do__AcmeV2_AcmeOrder__renew_quick(
    ctx, processing_strategy=None, dbAcmeOrder=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`

    :returns: A :class:`model.objects.AcmeOrder` object for the new AcmeOrder
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("AcmeOrder_Renew_Quick"),
    )
    # private_key_strategy__requested - pull off the original
    # private_key_cycle__renewal = pull off the original,
    return _do__AcmeV2_AcmeOrder__core(
        ctx,
        dbAcmeOrder_renewal_of=dbAcmeOrder,
        acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_RENEW_QUICK,
        private_key_cycle__renewal=dbAcmeOrder.private_key_cycle__renewal,
        private_key_strategy__requested=dbAcmeOrder.private_key_strategy__requested,
        processing_strategy=processing_strategy,
    )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
