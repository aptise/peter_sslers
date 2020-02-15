# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime
import pdb

# pypi
from dateutil import parser as dateutil_parser
import sqlalchemy
import transaction
from zope.sqlalchemy import mark_changed

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

# local
from .logger import AcmeLogger
from .logger import log__OperationsEvent
from .logger import _log_object_event


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__AcmeAccountKey_AcmeV2_authenticate(
    ctx, dbAcmeAccountKey, account_key_path=None,
):
    """
    Authenticates an AcmeAccountKey against the LetsEncrypt ACME Server

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
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


def update_AcmeAuthorization_status(
    ctx, dbAcmeAuthorization, status_text, transaction_commit=None
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object
    :param status_text: (required) The status_text for the order
    :param transaction_commit: (required) Boolean. Must indicate that we will commit this.
    """
    if transaction_commit is not True:
        raise ValueError("we must invoke this knowing it will commit")
    if dbAcmeAuthorization.status_text != status_text:
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
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge` object
    :param status_text: (required) The status_text for the order
    :param transaction_commit: (required) Boolean. Must indicate that we will commit this.
    """
    if transaction_commit is not True:
        raise ValueError("we must invoke this knowing it will commit")
    if dbAcmeChallenge.status_text != status_text:
        dbAcmeChallenge.acme_status_challenge_id = model_utils.Acme_Status_Challenge.from_string(
            status_text
        )
        dbAcmeChallenge.timestamp_updated = datetime.datetime.utcnow()
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def update_AcmeOrder_status(ctx, dbAcmeOrder, status_text, transaction_commit=None):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param status_text: (required) The status_text for the order
    :param transaction_commit: (required) Boolean. Must indicate that we will commit this.
    """
    if transaction_commit is not True:
        raise ValueError("we must invoke this knowing it will commit")
    if dbAcmeOrder.status_text != status_text:
        dbAcmeOrder.acme_status_order_id = model_utils.Acme_Status_Order.from_string(
            status_text
        )
        dbAcmeOrder.timestamp_updated = datetime.datetime.utcnow()
        if transaction_commit:
            ctx.pyramid_transaction_commit()
        return True
    return False


def _factory_AcmeV2_AuthHandlers(ctx, authenticatedUser, dbAcmeOrder):
    """
    generates functions for order handling

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param authenticatedUser: (required) a :class:`lib.acme_v2.AuthenticatedUser` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    """

    def handle_authorization_payload(
        authorization_url, authorization_response, transaction_commit=None
    ):
        """
        :param authorization_url: (required) The URL of the ACME Server's Authorization Object.
        :param authorization_response: (required) The JSON object corresponding to the ACME Server's Authorization Object.
        :param transaction_commit: (required) Boolean. Must indicate that we will commit this.

        the getcreate will do the following:
            create/update the Authorization object
            create/update the Challenge object
        """
        log.info("-handle_authorization_payload %s", authorization_url)
        if transaction_commit is not True:
            raise ValueError("we must invoke this knowing it will commit")

        # this will sync the payload via `update_AcmeAuthorization_from_payload`
        (
            dbAcmeAuthorization,
            _is_created,
        ) = lib.db.getcreate.getcreate__AcmeAuthorization(
            ctx,
            authorization_url,
            authorization_response,
            authenticatedUser,
            dbAcmeOrder,
            transaction_commit=transaction_commit,
        )
        if _is_created:
            raise ValueError("wtf")

        return dbAcmeAuthorization

    def handle_challenge_setup(
        domain, token, keyauthorization, transaction_commit=None
    ):
        """
        `handle_challenge_setup` is a hook designed to setup the challenge on a server if needed.

        this hook is currently not used, because the challenge is effectively enabled by being in the database.

        :param domain: (required) The domain for the challenge, as a string.
        :param token: (required) The challenge's token.
        :param keyauthorization: (required) The keyauthorization expected to be in the challenge url
        :param transaction_commit: (required) Boolean. Must indicate that we will commit this.
        """
        log.info("-handle_challenge_setup %s", domain)
        if transaction_commit is not True:
            raise ValueError("we must invoke this knowing it will commit")
        return True

    def handle_challenge_cleanup(
        domain, token, keyauthorization, transaction_commit=None
    ):
        """
        :param domain: (required) The domain for the challenge, as a string.
        :param token: (required) The challenge's token.
        :param keyauthorization: (required) The keyauthorization expected to be in the challenge url
        :param transaction_commit: (required) Boolean. Must indicate that we will commit this.

        originally, this callback/hook was used to cleanup a challenge
        it might be unused
        """
        log.info("-handle_challenge_cleanup %s", domain)
        if transaction_commit is not True:
            raise ValueError("we must invoke this knowing it will commit")
        return True

    return (
        handle_authorization_payload,
        handle_challenge_setup,
        handle_challenge_cleanup,
    )


def _AcmeV2_AcmeOrder_process(ctx, authenticatedUser, dbAcmeOrder, acmeOrderRfcObject):
    """
    Consolidated AcmeOrder routine

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param authenticatedUser: (required) a :class:`lib.acme_v2.AuthenticatedUser` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param acmeRfcOrder: (required) a :class:`lib.acme_v2.AcmeOrderRFC` instance

    -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    About the ACME order object Status

    # https://tools.ietf.org/html/rfc8555#section-7.1.3

    status (required, string):
        The status of this order.
        Possible values are" "pending", "ready", "processing", "valid", and "invalid".  See Section 7.1.6.

    # https://tools.ietf.org/html/rfc8555#page-48

       o  "invalid": The certificate will not be issued.  Consider this
          order process abandoned.

       o  "pending": The server does not believe that the client has
          fulfilled the requirements.  Check the "authorizations" array for
          entries that are still pending.

       o  "ready": The server agrees that the requirements have been
          fulfilled, and is awaiting finalization.  Submit a finalization
          request.

       o  "processing": The certificate is being issued.  Send a POST-as-GET
          request after the time given in the Retry-After header field of
          the response, if any.

       o  "valid": The server has issued the certificate and provisioned its
          URL to the "certificate" field of the order.  Download the
          certificate.
    """

    (
        handle_authorization_payload,
        handle_challenge_setup,
        handle_challenge_cleanup,
    ) = _factory_AcmeV2_AuthHandlers(ctx, authenticatedUser, dbAcmeOrder)

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
                handle_challenge_setup=handle_challenge_setup,
                handle_challenge_cleanup=handle_challenge_cleanup,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
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
            update_AcmeOrder_status(
                ctx,
                dbAcmeOrder,
                acmeOrderRfcObject.rfc_object["status"],
                transaction_commit=True,
            )
            return False
    else:
        if _order_status == "invalid":
            # order abandoned
            raise ValueError("Order Abandoned")
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


def do__AcmeAuthorization_AcmeV2__acme_server_deactivate(
    ctx, dbAcmeAuthorization=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object to deactivate on the server
    """
    if not dbAcmeAuthorization:
        raise ValueError("Must submit `dbAcmeAuthorization`")
    if not dbAcmeAuthorization.is_can_acme_server_deactivate:
        raise ValueError("Can not deactivate this `AcmeAuthorization`")

    if not dbAcmeAuthorization.acme_order_id__created:
        raise ValueError("can not proceed without an order for this authorization")

    tmpfiles = []
    try:
        # this is used a bit
        dbAcmeAccountKey = dbAcmeAuthorization.acme_order_created.acme_account_key
        dbAcmeOrder = dbAcmeAuthorization.acme_order_created

        # we need to use tmpfiles on the disk
        account_key_pem = dbAcmeAccountKey.key_pem
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)
        account_key_path = tmpfile_account.name

        # register the account / ensure that it is registered
        # the authenticatedUser will have an `acmeLogger`
        authenticatedUser = do__AcmeAccountKey_AcmeV2_authenticate(
            ctx, dbAcmeAccountKey, account_key_path=account_key_path,
        )
        authenticatedUser.acmeLogger.register_dbAcmeOrder(
            dbAcmeOrder
        )  # required for logging
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


def do__AcmeAuthorization_AcmeV2__acme_server_sync(
    ctx, dbAcmeAuthorization=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeAuthorization: (required) A :class:`model.objects.AcmeAuthorization` object to refresh against the server
    """
    if not dbAcmeAuthorization:
        raise ValueError("Must submit `dbAcmeAuthorization`")
    if not dbAcmeAuthorization.is_can_acme_server_sync:
        raise ValueError("Can not sync this `AcmeAuthorization`")

    if not dbAcmeAuthorization.acme_order_id__created:
        raise ValueError("can not proceed without an order for this authorization")

    tmpfiles = []
    try:
        # this is used a bit
        dbAcmeAccountKey = dbAcmeAuthorization.acme_order_created.acme_account_key
        dbAcmeOrder = dbAcmeAuthorization.acme_order_created

        # we need to use tmpfiles on the disk
        account_key_pem = dbAcmeAccountKey.key_pem
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)
        account_key_path = tmpfile_account.name

        # register the account / ensure that it is registered
        # the authenticatedUser will have an `acmeLogger`
        authenticatedUser = do__AcmeAccountKey_AcmeV2_authenticate(
            ctx, dbAcmeAccountKey, account_key_path=account_key_path,
        )
        authenticatedUser.acmeLogger.register_dbAcmeOrder(
            dbAcmeOrder
        )  # required for logging
        try:
            (
                authorization_response,
                dbAcmeEventLog_authorization_fetch,
            ) = authenticatedUser.acme_authorization_load(
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


def do__AcmeChallenge_AcmeV2__acme_server_sync(
    ctx, dbAcmeChallenge=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeChallenge: (required) A :class:`model.objects.AcmeChallenge` object to refresh against the server
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
        dbAcmeAccountKey = dbAcmeAuthorization.acme_order_created.acme_account_key

        if not dbAcmeAuthorization.acme_order_id__created:
            raise ValueError("can not proceed without an order for this authorization")
        dbAcmeOrder = dbAcmeAuthorization.acme_order_created

        # we need to use tmpfiles on the disk
        account_key_pem = dbAcmeAccountKey.key_pem
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)
        account_key_path = tmpfile_account.name

        # register the account / ensure that it is registered
        # the authenticatedUser will have an `acmeLogger`
        authenticatedUser = do__AcmeAccountKey_AcmeV2_authenticate(
            ctx, dbAcmeAccountKey, account_key_path=account_key_path,
        )
        authenticatedUser.acmeLogger.register_dbAcmeOrder(
            dbAcmeOrder
        )  # required for logging
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
        if _server_status != dbAcmeChallenge.status_text:
            update_AcmeChallenge_status(
                ctx, dbAcmeChallenge, _server_status, transaction_commit=True
            )
            return True
        return None

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeOrder_AcmeV2__acme_server_sync(
    ctx, dbAcmeOrder=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to refresh against the server
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")

    tmpfiles = []
    try:
        # we need to use tmpfiles on the disk
        account_key_pem = dbAcmeOrder.acme_account_key.key_pem
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)
        account_key_path = tmpfile_account.name

        # register the account / ensure that it is registered
        # the authenticatedUser will have an `acmeLogger`
        authenticatedUser = do__AcmeAccountKey_AcmeV2_authenticate(
            ctx, dbAcmeOrder.acme_account_key, account_key_path=account_key_path,
        )
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
        except errors.AcmeServer404 as exc:
            is_order_404 = True
            update_AcmeOrder_status(ctx, dbAcmeOrder, "*404*", transaction_commit=True)
            return True

        if is_order_404:
            # TODO: raise an exception if we don't have an acmeOrder
            # TODO: update the authorizations/challenges from the order
            pass

        # update the AcmeOrder if it's not the same on the database
        _server_status = acmeOrderRfcObject.rfc_object["status"]
        if dbAcmeOrder.status_text != _server_status:
            update_AcmeOrder_status(
                ctx, dbAcmeOrder, _server_status, transaction_commit=True
            )
            return True

        return False

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeOrder_AcmeV2__acme_server_deactivate_authorizations(
    ctx, dbAcmeOrder=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to refresh against the server
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")

    tmpfiles = []
    try:
        # we need to use tmpfiles on the disk
        account_key_pem = dbAcmeOrder.acme_account_key.key_pem
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)
        account_key_path = tmpfile_account.name

        # register the account / ensure that it is registered
        # the authenticatedUser will have an `acmeLogger`
        authenticatedUser = do__AcmeAccountKey_AcmeV2_authenticate(
            ctx, dbAcmeOrder.acme_account_key, account_key_path=account_key_path,
        )
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
            print("which authorizations are okay to kill?")
            pdb.set_trace()
        except errors.AcmeServer404 as exc:
            is_order_404 = True
            update_AcmeOrder_status(ctx, dbAcmeOrder, "*404*", transaction_commit=True)

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
                authorization_response = {"status": "*404*"}
            update_AcmeAuthorization_status(
                ctx,
                dbAcmeAuthorization,
                authorization_response["status"],
                transaction_commit=True,
            )

        # TODO: raise an exception if we don't have an acmeOrderRfcObject
        # TODO: update the authorizations/challenges from the order

        # update the AcmeOrder if it's not the same on the database
        if not is_order_404:
            try:
                (
                    acmeOrderRfcObject,
                    dbAcmeOrderEventLogged,
                ) = authenticatedUser.acme_order_load(
                    ctx, dbAcmeOrder=dbAcmeOrder, transaction_commit=True,
                )
                _server_status = acmeOrderRfcObject.rfc_object["status"]
                if dbAcmeOrder.status_text != _server_status:
                    update_AcmeOrder_status(
                        ctx, dbAcmeOrder, _server_status, transaction_commit=True
                    )
                    return True
            except:
                raise

        return False

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def _do__AcmeOrder__AcmeV2__core_finalize(
    ctx,
    authenticatedUser=None,  # optional?
    acmeOrderRfcObject=None,
    dbAcmeOrder=None,  # required
    dbPrivateKey=None,  # required
    dbCertificateRequest=None,  # optional
    dbQueueRenewal__of=None,
    certificate_request_source_id=None,  # required
    dbServerCertificate__renewal_of=None,  # optional
    domain_names=None,  # required
    update_AcmeOrder_status=None,
):
    tmpfiles = []
    try:
        # we need to use tmpfiles on the disk for the Private Key signing
        private_key_pem = dbPrivateKey.key_pem
        tmpfile_pkey = cert_utils.new_pem_tempfile(private_key_pem)
        tmpfiles.append(tmpfile_pkey)

        tmpfile_csr = None
        if dbCertificateRequest:
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
                certificate_request_source_id=certificate_request_source_id,
                dbPrivateKey=dbPrivateKey,
                dbServerCertificate__issued=None,
                dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
                domain_names=domain_names,
            )
            ctx.pyramid_transaction_commit()

        if not dbAcmeOrder.certificate_request:
            dbAcmeOrder.certificate_request = dbCertificateRequest

        # pull domains from csr
        csr_domains = cert_utils.parse_csr_domains(
            csr_path=tmpfile_csr.name, submitted_domain_names=domain_names
        )
        if set(csr_domains) != set(domain_names):
            raise ValueError("Did not make a valid set")

        # sign and download
        fullchain_pem = authenticatedUser.acme_order_finalize(
            ctx,
            acmeOrderRfcObject=acmeOrderRfcObject,
            dbAcmeOrder=dbAcmeOrder,
            update_order_status=update_AcmeOrder_status,
            csr_path=tmpfile_csr.name,
            transaction_commit=True,
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

        # immediately commit this
        dbServerCertificate = lib.db.create.create__ServerCertificate(
            ctx,
            cert_pem=certificate_pem,
            dbAcmeOrder=dbAcmeOrder,
            dbCACertificate=dbCACertificate,
            # ca_chain_pem=ca_chain_pem,
            # ca_chain_name=None,
            # dbCertificateRequest=dbCertificateRequest,
            # dbPrivateKey=dbPrivateKey,
            # dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
            is_active=True,
            cert_domains_expected=domain_names,
        )
        if dbServerCertificate__renewal_of:
            dbServerCertificate__renewal_of.is_auto_renew = False
            dbServerCertificate__renewal_of.is_renewed = True
            ctx.dbSession.flush(objects=[dbServerCertificate__renewal_of])
        if dbQueueRenewal__of:
            dbQueueRenewal__of.timestamp_processed = ctx.timestamp
            dbQueueRenewal__of.process_result = True
            dbQueueRenewal__of.is_active = False
            ctx.dbSession.flush(objects=[dbQueueRenewal__of])
        ctx.pyramid_transaction_commit()

        # update the logger
        authenticatedUser.acmeLogger.log_CertificateProcured(
            "v2", dbServerCertificate, transaction_commit=True
        )

        # don't commit here, as that will trigger an error on object refresh
        return (dbAcmeOrder, True)

    except Exception as exc:
        raise

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def _do__AcmeOrder__AcmeV2__core(
    ctx,
    domain_names=None,
    certificate_request_source_id=None,
    single_process=None,
    dbAcmeAccountKey=None,
    dbAcmeOrder_renewal_of=None,
    dbAcmeOrder_retry_of=None,
    dbCertificateRequest=None,
    dbUniqueFQDNSet=None,
    dbPrivateKey=None,
    dbQueueRenewal__of=None,
    dbServerCertificate__renewal_of=None,
):
    """

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain_names: (optional) An iteratble list of domain names
    :param certificate_request_source_id: (optional)
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
    :param dbAcmeOrder_renewal_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbAcmeOrder_retry_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbCertificateRequest: (optional) A :class:`model.objects.CertificateRequest` object
    :param dbUniqueFQDNSet: (optional) A :class:`model.objects.dbUniqueFQDNSet` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param dbQueueRenewal__of: (optional) A :class:`model.objects.QueueRenewal` object
    :param dbServerCertificate__renewal_of: (optional) A :class:`model.objects.ServerCertificate` object
    :param single_process: (optional) Should this be attempted in a single, long, process?

    One and only one of the following items must be provided:
        dbAcmeOrder_retry_of
        dbAcmeOrder_renewal_of
        dbCertificateRequest
        dbQueueRenewal__of
        dbServerCertificate__renewal_of
        
    One and only one of the following items must be provided:
        domain_names        
        dbUniqueFQDNSet        

    :returns: A two element tuple consisting of:
        0 :class:`model.objects.AcmeOrder` object
        1 A `Boolean` representing success or failure)
    """
    # some things can't be triggered together
    if all((domain_names, dbUniqueFQDNSet)) or not any((domain_names, dbUniqueFQDNSet)):
        raise ValueError(
            "must submit one and only one of: `domain_names, dbUniqueFQDNSet`"
        )
    if domain_names:
        if any(
            (
                dbAcmeOrder_retry_of,
                dbAcmeOrder_renewal_of,
                dbCertificateRequest,
                dbQueueRenewal__of,
                dbServerCertificate__renewal_of,
                dbUniqueFQDNSet,
            )
        ):
            raise ValueError(
                "do not pass `domain_names` with any of `(dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of, dbCertificateRequest, dbQueueRenewal__of, dbServerCertificate__renewal_of, dbUniqueFQDNSet)`"
            )

    if (
        sum(
            bool(i)
            for i in (
                dbAcmeOrder_retry_of,
                dbAcmeOrder_renewal_of,
                dbCertificateRequest,
                dbQueueRenewal__of,
                dbServerCertificate__renewal_of,
                dbUniqueFQDNSet,
            )
        )
        >= 2
    ):
        raise ValueError(
            "At most, provide one of (`dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of, dbCertificateRequest, dbQueueRenewal__of, dbServerCertificate__renewal_of`)"
        )

    # switch this
    if dbAcmeOrder_retry_of:
        # kwargs validation
        if dbAcmeAccountKey:
            raise ValueError(
                "Must NOT submit `dbAcmeAccountKey` with `dbAcmeOrder_retry_of`"
            )

        # ensure we can transition
        if dbAcmeOrder_retry_of.status_text != "invalid":
            raise errors.InvalidRequest(
                "`dbAcmeOrder_retry_of.status_text` must be 'invalid'"
            )

        # re-use these related objects
        dbAcmeAccountKey = dbAcmeOrder_retry_of.acme_account_key
        dbCertificateRequest = dbAcmeOrder_retry_of.certificate_request
        dbPrivateKey = dbAcmeOrder_retry_of.certificate_request.private_key
        dbUniqueFQDNSet = dbAcmeOrder_retry_of.unique_fqdn_set
        certificate_request_source_id = (
            dbAcmeOrder_retry_of.certificate_request_source_id
        )
        domain_names = dbAcmeOrder_retry_of.domains_as_list

    elif dbAcmeOrder_renewal_of:
        # kwargs validation
        if not dbAcmeAccountKey:
            raise ValueError(
                "Must submit `dbAcmeAccountKey` with `dbAcmeOrder_renewal_of`"
            )
        if not dbPrivateKey:
            raise ValueError("Must submit `dbPrivateKey`")

        # ensure we can transition
        if dbAcmeOrder_renewal_of.status_text != "valid":
            raise errors.InvalidRequest(
                "`dbAcmeOrder_renewal_of.status_text` must be 'valid'"
            )

        # re-use these related objects
        if dbPrivateKey == dbAcmeOrder_renewal_of.certificate_request.private_key:
            dbCertificateRequest = dbAcmeOrder_renewal_of.certificate_request
        dbUniqueFQDNSet = dbAcmeOrder_renewal_of.unique_fqdn_set
        domain_names = dbAcmeOrder_renewal_of.domains_as_list

        # set this
        certificate_request_source_id = (
            model_utils.CertificateRequestSource.ACME_AUTOMATED_ORDER_RENEW
        )

    elif dbCertificateRequest:
        # kwargs validation
        if not dbAcmeAccountKey:
            raise ValueError(
                "Must submit `dbAcmeAccountKey` with `dbCertificateRequest`"
            )
        if dbPrivateKey:
            raise ValueError("do not pass `dbPrivateKey` with `dbCertificateRequest`")

        # re-use these related objects
        dbUniqueFQDNSet = dbCertificateRequest.unique_fqdn_set
        domain_names = dbCertificateRequest.domains_as_list

    elif dbQueueRenewal__of:
        # kwargs validation

        # TODO - dbQueueRenewal__of
        raise ValueError("#TODO")

    elif dbServerCertificate__renewal_of:
        # kwargs validation
        if not dbAcmeAccountKey:
            raise ValueError(
                "Must submit `dbAcmeAccountKey` with `dbAcmeOrder_renewal_of`"
            )
        if not dbPrivateKey:
            raise ValueError("Must submit `dbPrivateKey`")

        # re-use these related objects
        if dbPrivateKey == dbServerCertificate__renewal_of.private_key:
            dbCertificateRequest = dbServerCertificate__renewal_of.certificate_request
        else:
            certificate_request_source_id = (
                model_utils.CertificateRequestSource.ACME_AUTOMATED_CERT_RENEW
            )
        dbUniqueFQDNSet = dbServerCertificate__renewal_of.unique_fqdn_set
        domain_names = dbServerCertificate__renewal_of.domains_as_list

    elif dbUniqueFQDNSet:
        # kwargs validation
        if not dbAcmeAccountKey:
            raise ValueError("Must submit `dbAcmeAccountKey` with `dbUniqueFQDNSet`")
        if not dbPrivateKey:
            raise ValueError("Must submit `dbPrivateKey`")
        certificate_request_source_id = (
            model_utils.CertificateRequestSource.ACME_AUTOMATED_NEW
        )

    # ensure the private key is usable!
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

    tmpfiles = []
    dbAcmeOrder = None
    dbServerCertificate = None
    try:
        # pull the pem out of the account_key
        account_key_pem = dbAcmeAccountKey.key_pem

        # we need to use tmpfiles on the disk
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)
        account_key_path = tmpfile_account.name

        # register the account / ensure that it is registered
        # the authenticatedUser will have an `acmeLogger`
        authenticatedUser = do__AcmeAccountKey_AcmeV2_authenticate(
            ctx, dbAcmeAccountKey, account_key_path=account_key_path,
        )

        # create the order on the ACME server
        (acmeOrderRfcObject, dbAcmeOrderEventLogged) = authenticatedUser.acme_order_new(
            ctx,
            domain_names=domain_names,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            transaction_commit=True,
        )

        try:
            resource_url = acmeOrderRfcObject.response_headers["location"]
        except:
            resource_url = None

        # enroll the Acme Order into our database
        dbAcmeOrder = lib.db.create.create__AcmeOrder(
            ctx,
            acme_order_response=acmeOrderRfcObject.rfc_object,
            resource_url=resource_url,
            dbAcmeAccountKey=dbAcmeAccountKey,
            dbAcmeOrder_retry_of=dbAcmeOrder_retry_of,
            dbAcmeOrder_renewal_of=dbAcmeOrder_renewal_of,
            dbCertificateRequest=dbCertificateRequest,
            dbEventLogged=dbAcmeOrderEventLogged,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            transaction_commit=True,
        )

        # register the order into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        # handle the order towards finalized?
        _todo_finalize_order = _AcmeV2_AcmeOrder_process(
            ctx, authenticatedUser, dbAcmeOrder, acmeOrderRfcObject
        )
        if not _todo_finalize_order:
            return (dbAcmeOrder, False)

        (dbAcmeOrder, result) = _do__AcmeOrder__AcmeV2__core_finalize(
            ctx,
            authenticatedUser=authenticatedUser,
            dbAcmeOrder=dbAcmeOrder,
            dbPrivateKey=dbPrivateKey,
            dbCertificateRequest=dbCertificateRequest,
            certificate_request_source_id=certificate_request_source_id,
            dbQueueRenewal__of=dbQueueRenewal__of,
            dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
            domain_names=domain_names,
            acmeOrderRfcObject=acmeOrderRfcObject,
            update_AcmeOrder_status=update_AcmeOrder_status,
        )

        return (dbAcmeOrder, result)

    except Exception as exc:
        raise

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


def do__AcmeOrder__AcmeV2__automated(
    ctx,
    domain_names,
    dbAcmeAccountKey=None,
    dbPrivateKey=None,
    dbServerCertificate__renewal_of=None,
    dbQueueRenewal__of=None,
    single_process=None,
):
    """
    Automates a Certificate deployment from LetsEncrypt

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain_names: (required) An iteratble list of domain names
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param dbQueueRenewal__of: (optional) A :class:`model.objects.QueueRenewal` object
    :param dbServerCertificate__renewal_of: (optional) A :class:`model.objects.ServerCertificate` object
    :param single_process: (optional) Should this be attempted in a single, long, process?

    :returns: A :class:`model.objects.AcmeOrder` object
    """
    # bookkeeping
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("AcmeOrder_New_Automated"),
    )
    return _do__AcmeOrder__AcmeV2__core(
        ctx,
        domain_names=domain_names,
        certificate_request_source_id=model_utils.CertificateRequestSource.ACME_AUTOMATED_NEW,
        single_process=single_process,
        dbAcmeAccountKey=dbAcmeAccountKey,
        dbPrivateKey=dbPrivateKey,
        dbQueueRenewal__of=dbQueueRenewal__of,
        dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
    )


def do__AcmeOrder_AcmeV2__retry(
    ctx, dbAcmeOrder=None, single_process=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry
    :param single_process: (optional) Should this be attempted in a single, long, process?
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    # bookkeeping
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("AcmeOrder_New_Retry"),
    )
    return _do__AcmeOrder__AcmeV2__core(
        ctx, dbAcmeOrder_retry_of=dbAcmeOrder, single_process=single_process,
    )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
