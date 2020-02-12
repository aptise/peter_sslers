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
from ... import lib  # Todo: only here for `lib.db`
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


def disable_Domain(
    ctx,
    dbDomain,
    dbOperationsEvent=None,
    event_status="domain__mark__inactive",
    action="deactivated",
):
    """
    Disables a domain

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbDomain: (required) A :class:`model.objects.Domain` object
    :param dbOperationsEvent: (required) A :class:`model.objects.OperationsObjectEvent` object

    :param event_status: (optional) A string event status conforming to :class:`model_utils.OperationsObjectEventStatus`
    :param action: (optional) A string action. default = "deactivated"
    """
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["domain.id"] = dbDomain.id
    event_payload_dict["action"] = action
    dbDomain.is_active = False
    ctx.dbSession.flush(objects=[dbDomain])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            event_status
        ),
        dbDomain=dbDomain,
    )
    return True


def enable_Domain(
    ctx,
    dbDomain,
    dbOperationsEvent=None,
    event_status="domain__mark__active",
    action="activated",
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbDomain: (required) A :class:`model.objects.Domain` object
    :param dbOperationsEvent: (required) A :class:`model.objects.OperationsObjectEvent` object

    :param event_status: (optional) A string event status conforming to :class:`model_utils.OperationsObjectEventStatus`
    :param action: (optional) A string action. default = "activated"
    """
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["domain.id"] = dbDomain.id
    event_payload_dict["action"] = action
    dbDomain.is_active = True
    ctx.dbSession.flush(objects=[dbDomain])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            event_status
        ),
        dbDomain=dbDomain,
    )
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def ca_certificate_probe(ctx):
    """
    Probes the LetsEncrypt Certificate Authority for new certificates

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    """

    # create a bookkeeping object
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("ca_certificate__probe")
    )

    certs = letsencrypt_info.probe_letsencrypt_certificates()
    certs_discovered = []
    certs_modified = []
    for c in certs:
        _is_created = False
        dbCACertificate = lib.db.get.get__CACertificate__by_pem_text(ctx, c["cert_pem"])
        if not dbCACertificate:
            (
                dbCACertificate,
                _is_created,
            ) = lib.db.getcreate.getcreate__CACertificate__by_pem_text(
                ctx, c["cert_pem"], ca_chain_name=c["name"]
            )
            if _is_created:
                certs_discovered.append(dbCACertificate)
        if "is_ca_certificate" in c:
            if dbCACertificate.is_ca_certificate != c["is_ca_certificate"]:
                dbCACertificate.is_ca_certificate = c["is_ca_certificate"]
                if dbCACertificate not in certs_discovered:
                    certs_modified.append(dbCACertificate)
        else:
            attrs = (
                "le_authority_name",
                "is_authority_certificate",
                "is_cross_signed_authority_certificate",
            )
            for _k in attrs:
                if getattr(dbCACertificate, _k) is None:
                    setattr(dbCACertificate, _k, c[_k])
                    if dbCACertificate not in certs_discovered:
                        certs_modified.append(dbCACertificate)

    # bookkeeping update
    event_payload_dict["is_certificates_discovered"] = (
        True if certs_discovered else False
    )
    event_payload_dict["is_certificates_updated"] = True if certs_modified else False
    event_payload_dict["ids_discovered"] = [c.id for c in certs_discovered]
    event_payload_dict["ids_modified"] = [c.id for c in certs_modified]

    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return dbOperationsEvent


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


def _AcmeV2_handle_order(
    ctx, authenticatedUser, dbAcmeOrder, acmeOrderObject, is_retry=None
):
    """
    Consolidated AcmeOrder routine

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param authenticatedUser: (required) a :class:`lib.acme_v2.AuthenticatedUser` instance
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object
    :param acmeOrderObject: (required) a :class:`lib.acme_v2.AcmeOrder` instance
    :param is_retry: (optional) If this is a retry, we may behave differently

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
    _order_status = acmeOrderObject.rfc_object["status"]
    if _order_status == "pending" or (is_retry and _order_status == "invalid"):
        # if we are retrying an order, we can try to handle it
        _handled = authenticatedUser.acme_handle_order_authorizations(
            ctx,
            acmeOrder=acmeOrderObject,
            dbAcmeOrder=dbAcmeOrder,
            handle_authorization_payload=handle_authorization_payload,
            handle_challenge_setup=handle_challenge_setup,
            handle_challenge_cleanup=handle_challenge_cleanup,
            transaction_commit=True,
            is_retry=is_retry,
        )
        if not _handled:
            raise ValueError("Order Authorizations failed")
        _todo_finalize_order = True
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
        (
            authorization_response,
            dbAcmeEventLog_authorization_fetch,
        ) = authenticatedUser.acme_authorization_load(
            ctx, dbAcmeAuthorization=dbAcmeAuthorization, transaction_commit=True,
        )

        # todo: update the other fields and challenges from this authorization

        # update the AcmeAuthorization if it's not the same on the database
        _server_status = authorization_response["status"]
        if _server_status != dbAcmeAuthorization.status_text:
            update_AcmeAuthorization_status(
                ctx, dbAcmeAuthorization, _server_status, transaction_commit=True
            )
            return True
        return None

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
        (
            challenge_response,
            dbAcmeEventLog_challenge_fetch,
        ) = authenticatedUser.acme_challenge_load(
            ctx, dbAcmeChallenge=dbAcmeChallenge, transaction_commit=True,
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
        (acmeOrderObject, dbAcmeOrderEventLogged) = authenticatedUser.acme_order_load(
            ctx, dbAcmeOrder=dbAcmeOrder, transaction_commit=True,
        )

        # TODO: raise an exception if we don't have an acmeOrder
        # TODO: update the authorizations/challenges from the order

        # update the AcmeOrder if it's not the same on the database
        _server_status = acmeOrderObject.rfc_object["status"]
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


def _do__AcmeOrder__AcmeV2__core(
    ctx,
    domain_names=None,
    dbAcmeAccountKey=None,
    dbPrivateKey=None,
    dbServerCertificate__renewal_of=None,
    dbQueueRenewal__of=None,
    dbAcmeOrder_retry_of=None,
    dbAcmeOrder_renewal_of=None,
):
    """

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain_names: (required) An iteratble list of domain names
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param dbServerCertificate__renewal_of: (optional) A :class:`model.objects.ServerCertificate` object
    :param dbQueueRenewal__of: (optional) A :class:`model.objects.QueueRenewal` object

    :param dbAcmeOrder_retry_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbAcmeOrder_renewal_of: (optional) A :class:`model.objects.AcmeOrder` object

    :returns: A :class:`model.objects.AcmeOrder` object
    """
    dbCertificateRequest = None  # scoping
    if not any((dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of)):
        if not dbAcmeAccountKey:
            raise ValueError("Must submit `dbAcmeAccountKey`")
        if not dbPrivateKey:
            raise ValueError("Must submit `dbPrivateKey`")
        if all((dbServerCertificate__renewal_of, domain_names)):
            raise ValueError("do not pass `domain_names` with `dbServerCertificate`")
        if dbServerCertificate__renewal_of:
            domain_names = dbServerCertificate__renewal_of.domains_as_list
    else:
        if all((dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of)):
            raise ValueError("renew OR retry; not both")
        if domain_names:
            raise ValueError(
                "do not pass `domain_names` with (`dbAcmeOrder_retry_of` or `dbAcmeOrder_renewal_of`)"
            )
        if dbServerCertificate__renewal_of:
            raise ValueError(
                "do not pass `dbServerCertificate__renewal_of` with (`dbAcmeOrder_retry_of` or `dbAcmeOrder_renewal_of`)"
            )
        if dbAcmeOrder_retry_of:
            # ensure we can transition
            if dbAcmeOrder_retry_of.status_text != "invalid":
                raise errors.InvalidRequest(
                    "`dbAcmeOrder_retry_of.status_text` must be 'invalid'"
                )
            if dbAcmeAccountKey:
                raise ValueError(
                    "Must NOT submit `dbAcmeAccountKey` with `dbAcmeOrder_retry_of`"
                )
            # for a `retry`, recycle the `AcmeAccountKey` and `PrivateKey`
            dbAcmeAccountKey = dbAcmeOrder_retry_of.acme_account_key
            dbPrivateKey = dbAcmeOrder_retry_of.certificate_request.private_key
            domain_names = dbAcmeOrder_retry_of.domains_as_list
            dbCertificateRequest = dbAcmeOrder_retry_of.certificate_request
        elif dbAcmeOrder_renewal_of:
            # ensure we can transition
            if dbAcmeOrder_renewal_of.status_text != "valid":
                raise errors.InvalidRequest(
                    "`dbAcmeOrder_renewal_of.status_text` must be 'valid'"
                )
            domain_names = dbAcmeOrder_renewal_of.domains_as_list
            # for a `renewal`, specify the `AcmeAccountKey` and `PrivateKey`
            if not dbAcmeAccountKey:
                raise ValueError(
                    "Must submit `dbAcmeAccountKey` with `dbAcmeOrder_renewal_of`"
                )
            if not dbPrivateKey:
                raise ValueError("Must submit `dbPrivateKey`")
            dbCertificateRequest = None  # we should make a new CSR for renewals

    if not dbPrivateKey.is_key_usable:
        raise errors.InvalidRequest(
            "The `dbPrivateKey` is not usable. It was deactivated or compromised.`"
        )

    # ensure domains names!
    if not domain_names:
        raise ValueError(
            "`domain_names` must be provided unless this is a renewal or retry"
        )

    # we should have cleaned this up before submitting, but just be safe!
    domain_names = [i.lower() for i in [d.strip() for d in domain_names] if i]
    domain_names = set(domain_names)
    if not domain_names:
        raise ValueError("no domain names!")
    # we need a list
    domain_names = list(domain_names)

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "certificate_request__do__automated"
        ),
    )

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

        private_key_pem = dbPrivateKey.key_pem

        # we need to use tmpfiles on the disk
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
                certificate_request_source_id=model_utils.CertificateRequestSource.ACME_AUTOMATED,
                dbPrivateKey=dbPrivateKey,
                dbServerCertificate__issued=None,
                dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
                domain_names=domain_names,
            )
            ctx.pyramid_transaction_commit()

        # pull domains from csr
        csr_domains = cert_utils.parse_csr_domains(
            csr_path=tmpfile_csr.name, submitted_domain_names=domain_names
        )
        if set(csr_domains) != set(domain_names):
            raise ValueError("Did not make a valid set")

        # register the account / ensure that it is registered
        # the authenticatedUser will have an `acmeLogger`
        authenticatedUser = do__AcmeAccountKey_AcmeV2_authenticate(
            ctx, dbAcmeAccountKey, account_key_path=account_key_path,
        )

        # create the order on the ACME server
        (acmeOrderObject, dbAcmeOrderEventLogged) = authenticatedUser.acme_order_new(
            ctx,
            csr_domains=csr_domains,
            dbCertificateRequest=dbCertificateRequest,
            transaction_commit=True,
        )
        # enroll the Acme Order into our database
        dbAcmeOrder = lib.db.create.create__AcmeOrder(
            ctx,
            dbAcmeAccountKey=dbAcmeAccountKey,
            dbCertificateRequest=dbCertificateRequest,
            dbEventLogged=dbAcmeOrderEventLogged,
            acmeOrderRfcObject=acmeOrderObject.rfc_object,
            acmeOrderResponseHeaders=acmeOrderObject.response_headers,
            dbAcmeOrder_retry_of=dbAcmeOrder_retry_of,
            dbAcmeOrder_renewal_of=dbAcmeOrder_renewal_of,
            transaction_commit=True,
        )
        # register the order into the logging utility
        authenticatedUser.acmeLogger.register_dbAcmeOrder(dbAcmeOrder)

        # handle the order towards finalized?
        _todo_finalize_order = _AcmeV2_handle_order(
            ctx, authenticatedUser, dbAcmeOrder, acmeOrderObject
        )
        if _todo_finalize_order:
            # sign and download
            fullchain_pem = authenticatedUser.acme_finalize_order(
                ctx,
                acmeOrder=acmeOrderObject,
                dbAcmeOrder=dbAcmeOrder,
                update_order_status=update_AcmeOrder_status,
                csr_path=tmpfile_csr.name,
                transaction_commit=True,
            )
        else:
            pdb.set_trace()

        # ######################################################################
        # ######################################################################

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
        return dbAcmeOrder

    except Exception as exc:
        if dbCertificateRequest:
            dbCertificateRequest.is_active = False
            dbCertificateRequest.is_error = True
            ctx.dbSession.flush(objects=[dbCertificateRequest])
            ctx.pyramid_transaction_commit()
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
):
    """
    Automates a Certificate deployment from LetsEncrypt

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain_names: (required) An iteratble list of domain names
    :param dbAcmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param dbServerCertificate__renewal_of: (optional) A :class:`model.objects.ServerCertificate` object
    :param dbQueueRenewal__of: (optional) A :class:`model.objects.QueueRenewal` object

    :returns: A :class:`model.objects.AcmeOrder` object
    """
    return _do__AcmeOrder__AcmeV2__core(
        ctx,
        domain_names=domain_names,
        dbAcmeAccountKey=dbAcmeAccountKey,
        dbPrivateKey=dbPrivateKey,
        dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
        dbQueueRenewal__of=dbQueueRenewal__of,
    )


def do__AcmeOrder_AcmeV2__retry(
    ctx, dbAcmeOrder=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeOrder: (required) A :class:`model.objects.AcmeOrder` object to retry
    """
    if not dbAcmeOrder:
        raise ValueError("Must submit `dbAcmeOrder`")
    return _do__AcmeOrder__AcmeV2__core(ctx, dbAcmeOrder_retry_of=dbAcmeOrder,)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_expired(ctx):
    """
    deactivates expired certificates automatically

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    """
    # create an event first
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["count_deactivated"] = 0
    operationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("certificate__deactivate_expired"),
        event_payload_dict,
    )

    # update the recents, this will automatically create a subevent
    subevent = operations_update_recents(ctx)

    # okay, go!

    # deactivate expired certificates
    expired_certs = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(
            model_objects.ServerCertificate.is_active.is_(True),
            model_objects.ServerCertificate.timestamp_expires < ctx.timestamp,
        )
        .all()
    )
    for c in expired_certs:
        c.is_active = False
        ctx.dbSession.flush(objects=[c])
        events.Certificate_expired(ctx, c)

    # update the event
    if len(expired_certs):
        event_payload_dict["count_deactivated"] = len(expired_certs)
        event_payload_dict["server_certificate.ids"] = [c.id for c in expired_certs]
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_duplicates(ctx, ran_operations_update_recents=None):
    """
    this is kind of weird.
    because we have multiple domains, it is hard to figure out which certs we should use
    the simplest approach is this:

    1. cache the most recent certs via `operations_update_recents`
    2. find domains that have multiple active certs
    3. don't turn off any certs that are a latest_single or latest_multi

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param ran_operations_update_recents: (optional) Default = `None`
    """
    raise ValueError("Don't run this. It's not needed anymore")
    raise errors.OperationsContextError("Not Compliant")

    if ran_operations_update_recents is not True:
        raise ValueError("MUST run `operations_update_recents` first")

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["count_deactivated"] = 0
    operationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("deactivate_duplicate"),
        event_payload_dict,
    )

    _q_ids__latest_single = (
        ctx.dbSession.query(model_objects.Domain.server_certificate_id__latest_single)
        .distinct()
        .filter(
            model_objects.Domain.server_certificate_id__latest_single != None  # noqa
        )
        .subquery()
    )
    _q_ids__latest_multi = (
        ctx.dbSession.query(model_objects.Domain.server_certificate_id__latest_multi)
        .distinct()
        .filter(
            model_objects.Domain.server_certificate_id__latest_single != None  # noqa
        )
        .subquery()
    )

    # now grab the domains with many certs...
    q_inner = (
        ctx.dbSession.query(
            model_objects.UniqueFQDNSet2Domain.domain_id,
            sqlalchemy.func.count(model_objects.UniqueFQDNSet2Domain.domain_id).label(
                "counted"
            ),
        )
        .join(
            model_objects.ServerCertificate,
            model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id
            == model_objects.ServerCertificate.unique_fqdn_set_id,
        )
        .filter(model_objects.ServerCertificate.is_active.is_(True))
        .group_by(model_objects.UniqueFQDNSet2Domain.domain_id)
    )
    q_inner = q_inner.subquery()
    q_domains = ctx.dbSession.query(q_inner).filter(q_inner.c.counted >= 2)
    result = q_domains.all()
    domain_ids_with_multiple_active_certs = [i.domain_id for i in result]

    if False:
        _turned_off = []
        for _domain_id in domain_ids_with_multiple_active_certs:
            domain_certs = (
                ctx.dbSession.query(model_objects.ServerCertificate)
                .join(
                    model_objects.UniqueFQDNSet2Domain,
                    model_objects.ServerCertificate.unique_fqdn_set_id
                    == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
                )
                .filter(
                    model_objects.ServerCertificate.is_active.is_(True),
                    model_objects.UniqueFQDNSet2Domain.domain_id == _domain_id,
                    model_objects.ServerCertificate.id.notin_(_q_ids__latest_single),
                    model_objects.ServerCertificate.id.notin_(_q_ids__latest_multi),
                )
                .order_by(model_objects.ServerCertificate.timestamp_expires.desc())
                .all()
            )
            if len(domain_certs) > 1:
                for cert in domain_certs[1:]:
                    cert.is_active = False
                    _turned_off.append(cert)
                    events.Certificate_deactivated(ctx, cert)

    # update the event
    if len(_turned_off):
        event_payload_dict["count_deactivated"] = len(_turned_off)
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_update_recents(ctx):
    """
    updates all the objects to their most-recent relations

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    """
    # first the single
    # _t_domain = model_objects.Domain.__table__.alias('domain')

    _q_sub = (
        ctx.dbSession.query(model_objects.ServerCertificate.id)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.ServerCertificate.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.ServerCertificate.is_active.is_(True),
            model_objects.ServerCertificate.is_single_domain_cert.is_(True),
            model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
        )
        .order_by(model_objects.ServerCertificate.timestamp_expires.desc())
        .limit(1)
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )

    ctx.dbSession.execute(
        model_objects.Domain.__table__.update().values(
            server_certificate_id__latest_single=_q_sub
        )
    )

    # then the multiple
    # _t_domain = model_objects.Domain.__table__.alias('domain')
    _q_sub = (
        ctx.dbSession.query(model_objects.ServerCertificate.id)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.ServerCertificate.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.ServerCertificate.is_active.is_(True),
            model_objects.ServerCertificate.is_single_domain_cert.is_(False),
            model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
        )
        .order_by(model_objects.ServerCertificate.timestamp_expires.desc())
        .limit(1)
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.Domain.__table__.update().values(
            server_certificate_id__latest_multi=_q_sub
        )
    )

    # update the count of active certs
    ServerCertificate1 = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    ServerCertificate2 = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    _q_sub = (
        ctx.dbSession.query(sqlalchemy.func.count(model_objects.Domain.id))
        .outerjoin(
            ServerCertificate1,
            model_objects.Domain.server_certificate_id__latest_single
            == ServerCertificate1.id,
        )
        .outerjoin(
            ServerCertificate2,
            model_objects.Domain.server_certificate_id__latest_multi
            == ServerCertificate2.id,
        )
        .filter(
            sqlalchemy.or_(
                model_objects.CACertificate.id
                == ServerCertificate1.ca_certificate_id__upchain,
                model_objects.CACertificate.id
                == ServerCertificate2.ca_certificate_id__upchain,
            )
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.CACertificate.__table__.update().values(
            count_active_certificates=_q_sub
        )
    )

    # update the count of active PrivateKeys
    ServerCertificate1 = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    ServerCertificate2 = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    _q_sub = (
        ctx.dbSession.query(sqlalchemy.func.count(model_objects.Domain.id))
        .outerjoin(
            ServerCertificate1,
            model_objects.Domain.server_certificate_id__latest_single
            == ServerCertificate1.id,
        )
        .outerjoin(
            ServerCertificate2,
            model_objects.Domain.server_certificate_id__latest_multi
            == ServerCertificate2.id,
        )
        .filter(
            sqlalchemy.or_(
                model_objects.PrivateKey.id == ServerCertificate1.private_key_id,
                model_objects.PrivateKey.id == ServerCertificate2.private_key_id,
            )
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.PrivateKey.__table__.update().values(
            count_active_certificates=_q_sub
        )
    )

    # the following works, but this is currently tracked
    """
        # update the counts on Acme Account Keys
        _q_sub_req = ctx.dbSession.query(sqlalchemy.func.count(model_objects.CertificateRequest.id))\
            .filter(model_objects.CertificateRequest.acme_account_key_id == model_objects.AcmeAccountKey.id,
                    )\
            .subquery().as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
        ctx.dbSession.execute(model_objects.AcmeAccountKey.__table__
                              .update()
                              .values(count_certificate_requests=_q_sub_req,
                                      # count_certificates_issued=_q_sub_iss,
                                      )
                              )
        # update the counts on Private Keys
        _q_sub_req = ctx.dbSession.query(sqlalchemy.func.count(model_objects.CertificateRequest.id))\
            .filter(model_objects.CertificateRequest.private_key_id == model_objects.PrivateKey.id,
                    )\
            .subquery().as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
        _q_sub_iss = ctx.dbSession.query(sqlalchemy.func.count(model_objects.ServerCertificate.id))\
            .filter(model_objects.ServerCertificate.private_key_id == model_objects.PrivateKey.id,
                    )\
            .subquery().as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`

        ctx.dbSession.execute(model_objects.PrivateKey.__table__
                              .update()
                              .values(count_certificate_requests=_q_sub_req,
                                      count_certificates_issued=_q_sub_iss,
                                      )
                              )
    """

    # should we do the timestamps?
    """
    UPDATE acme_account_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM certificate_request
    WHERE certificate_request.acme_account_key_id = acme_account_key.id);

    UPDATE acme_account_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM server_certificate
    WHERE server_certificate.acme_account_key_id = acme_account_key.id);

    UPDATE private_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM certificate_request
    WHERE certificate_request.private_key_id = private_key.id);

    UPDATE private_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM server_certificate
    WHERE server_certificate.private_key_id = private_key.id);
    """

    # bookkeeping, doing this will mark the session as changed!
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("operations__update_recents"),
    )

    # mark the session changed
    # update: we don't need this if we add the bookkeeping object
    # update2: there is an unresolved bug/behavior where including this somehow commits
    log.debug("mark_changed(ctx.dbSession) - is this necessary?")
    mark_changed(ctx.dbSession)

    return dbOperationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__enable(ctx, domain_names):
    """
    this is just a proxy around queue_domains__add

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain_names: (required) a list of domain names
    """

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("api_domains__enable"),
        event_payload_dict,
    )
    results = lib.db.queues.queue_domains__add(ctx, domain_names)
    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__disable(ctx, domain_names):
    """
    disables domains

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain_names: (required) a list of domain names
    """
    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("api_domains__disable"),
        event_payload_dict,
    )

    for domain_name in domain_names:
        _dbDomain = lib.db.get.get__Domain__by_name(
            ctx, domain_name, preload=False, active_only=False
        )
        if _dbDomain:
            if _dbDomain.is_active:
                disable_Domain(
                    ctx,
                    _dbDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="domain__mark__inactive",
                    action="deactivated",
                )
                results[domain_name] = "deactivated"
            else:
                results[domain_name] = "already deactivated"
        elif not _dbDomain:
            _dbQueueDomain = lib.db.get.get__QueueDomain__by_name__single(
                ctx, domain_name
            )
            if _dbQueueDomain:
                lib.db.queues.dequeue_QueuedDomain(
                    ctx,
                    _dbQueueDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="queue_domain__mark__cancelled",
                    action="de-queued",
                )
                results[domain_name] = "de-queued"
            else:
                results[domain_name] = "not active or in queue"

    event_payload_dict["results"] = results
    dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__certificate_if_needed(
    ctx, domain_names, account_key_pem=None, dbPrivateKey=None
):
    """
    Adds domains if needed
    2016.06.29

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain_names: (required) a list of domain names
    :param account_key_pem: (required) the acme-account-key used for new orders
    :param dbPrivateKey: (required) the class:`model.objects.PrivateKey` used to sign requests

    results will be a dict:

        {%DOMAIN_NAME%: {'domain': # active, activated, new, FAIL
                         'certificate':  # active, new, FAIL

    logging codes
        2010: 'api_domains__certificate_if_needed',
        2011: 'api_domains__certificate_if_needed__domain_exists',
        2012: 'api_domains__certificate_if_needed__domain_activate',
        2013: 'api_domains__certificate_if_needed__domain_new',
        2015: 'api_domains__certificate_if_needed__certificate_exists',
        2016: 'api_domains__certificate_if_needed__certificate_new_success',
        2017: 'api_domains__certificate_if_needed__certificate_new_fail',
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "api_domains__certificate_if_needed"
        ),
        event_payload_dict,
    )

    dbAcmeAccountKey = None
    if account_key_pem is not None:
        raise ValueError("acmeAccountProvider_id")
        dbAcmeAccountKey, _is_created = lib.db.getcreate.getcreate__AcmeAccountKey(
            ctx, account_key_pem, acmeAccountProvider_id=None
        )
        if not dbAcmeAccountKey:
            raise errors.DisplayableError("Could not create an AccountKey")

    if account_key_pem is None:
        dbAcmeAccountKey = lib.db.get.get__AcmeAccountKey__default(ctx)
        if not dbAcmeAccountKey:
            raise errors.DisplayableError("Could not grab an AccountKey")

    if dbPrivateKey is None:
        dbPrivateKey = lib.db.get.get__PrivateKey__current_week(ctx)
        if not dbPrivateKey:
            dbPrivateKey = lib.db.create.create__PrivateKey__autogenerated(ctx)
        if not dbPrivateKey:
            raise errors.DisplayableError("Could not grab a PrivateKey")

    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for domain_name in domain_names:
        _result = {
            "domain.status": None,
            "certificate.status": None,
            "domain.id": None,
            "server_certificate.id": None,
        }

        _dbQueueDomain = None

        # go for the domain
        _logger_args = {"event_status_id": None}
        _dbDomain = lib.db.get.get__Domain__by_name(
            ctx, domain_name, preload=False, active_only=False
        )
        if _dbDomain:
            _result["domain.id"] = _dbDomain.id

            if not _dbDomain.is_active:
                _result["domain.status"] = "activated"

                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "api_domains__certificate_if_needed__domain_activate"
                )
                _logger_args["dbDomain"] = _dbDomain

                # set this active
                _dbDomain.is_active = True
                ctx.dbSession.flush(objects=[_dbDomain])

            else:
                _result["domain.status"] = "exists"

                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "api_domains__certificate_if_needed__domain_exists"
                )
                _logger_args["dbDomain"] = _dbDomain

        elif not _dbDomain:

            _dbDomain = lib.db.getcreate.getcreate__Domain__by_domainName(
                ctx, domain_name
            )[
                0
            ]  # (dbDomain, _is_created)
            _result["domain.status"] = "new"
            _result["domain.id"] = _dbDomain.id
            _logger_args[
                "event_status_id"
            ] = model_utils.OperationsObjectEventStatus.from_string(
                "api_domains__certificate_if_needed__domain_new"
            )
            _logger_args["dbDomain"] = _dbDomain

        # log domain event
        _log_object_event(ctx, dbOperationsEvent=dbOperationsEvent, **_logger_args)

        # do commit, just because we may have created a domain, AND THE LOGGGING
        transaction.commit()

        # go for the certificate
        _logger_args = {"event_status_id": None}
        _dbServerCertificate = lib.db.get.get__ServerCertificate__by_DomainId__latest(
            ctx, _dbDomain.id
        )
        if _dbServerCertificate:
            _result["certificate.status"] = "exists"
            _result["server_certificate.id"] = _dbServerCertificate.id
            _logger_args[
                "event_status_id"
            ] = model_utils.OperationsObjectEventStatus.from_string(
                "api_domains__certificate_if_needed__certificate_exists"
            )
            _logger_args["dbServerCertificate"] = _dbServerCertificate
        else:
            try:
                _dbServerCertificate = _do__AcmeOrder__AcmeV2__core(
                    ctx,
                    domain_names,
                    dbAcmeAccountKey=dbAcmeAccountKey,
                    dbPrivateKey=dbPrivateKey,
                )
                _result["certificate.status"] = "new"
                _result["server_certificate.id"] = _dbServerCertificate.id

                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "api_domains__certificate_if_needed__certificate_new_success"
                )
                _logger_args["dbServerCertificate"] = _dbServerCertificate

            except errors.DomainVerificationError as exc:
                _result["certificate.status"] = "fail"
                _result["server_certificate.id"] = None

                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "api_domains__certificate_if_needed__certificate_new_fail"
                )
                _logger_args["dbServerCertificate"] = None

        dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)

        # log domain event
        _log_object_event(ctx, dbOperationsEvent=dbOperationsEvent, **_logger_args)

        # do commit, just because THE LOGGGING
        transaction.commit()

        # remove from queue if it exists
        _dbQueueDomain = lib.db.get.get__QueueDomain__by_name__single(ctx, domain_name)
        if _dbQueueDomain:
            lib.db.queues.dequeue_QueuedDomain(
                ctx,
                _dbQueueDomain,
                dbOperationsEvent=dbOperationsEvent,
                event_status="queue_domain__mark__already_processed",
                action="already_processed",
            )

        # do commit, just because THE LOGGGING
        transaction.commit()

        # note result
        results[domain_name] = _result

    event_payload_dict["results"] = results
    dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def upload__CACertificateBundle__by_pem_text(ctx, bundle_data):
    """
    Uploads a bundle of CACertificates

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param bundle_data: (required) a compliant payload
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("ca_certificate__upload_bundle"),
        event_payload_dict,
    )
    results = {}
    for cert_pem in bundle_data.keys():
        if cert_pem[-4:] != "_pem":
            raise ValueError("key does not end in `_pem`")
        cert_base = cert_pem[:-4]
        cert_pem_text = bundle_data[cert_pem]
        cert_name = None
        le_authority_name = None
        is_authority_certificate = None
        is_cross_signed_authority_certificate = None
        for c in letsencrypt_info.CA_CERTS_DATA:
            if cert_base == c["formfield_base"]:
                cert_name = c["name"]
                if "le_authority_name" in c:
                    le_authority_name = c["le_authority_name"]
                if "is_authority_certificate" in c:
                    is_authority_certificate = c["is_authority_certificate"]
                if "is_cross_signed_authority_certificate" in c:
                    is_cross_signed_authority_certificate = c[
                        "is_cross_signed_authority_certificate"
                    ]
                break

        (
            dbCACertificate,
            is_created,
        ) = lib.db.getcreate.getcreate__CACertificate__by_pem_text(
            ctx,
            cert_pem_text,
            ca_chain_name=cert_name,
            le_authority_name=None,
            is_authority_certificate=None,
            is_cross_signed_authority_certificate=None,
        )
        if not is_created:
            if dbCACertificate.name in ("unknown", "manual upload") and cert_name:
                dbCACertificate.name = cert_name
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.le_authority_name = le_authority_name
            if dbCACertificate.is_authority_certificate is None:
                dbCACertificate.is_authority_certificate = is_authority_certificate
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.is_cross_signed_authority_certificate = (
                    is_cross_signed_authority_certificate
                )

        results[cert_pem] = (dbCACertificate, is_created)

    ids_created = [i[0].id for i in results.values() if i[1]]
    ids_updated = [i[0].id for i in results.values() if not i[1]]
    event_payload_dict["ids_created"] = ids_created
    event_payload_dict["ids_updated"] = ids_updated
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])
    return results
