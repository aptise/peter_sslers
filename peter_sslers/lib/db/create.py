# logging
import logging

log = logging.getLogger(__name__)

# localapp
from .. import cert_utils
from .. import utils
from ...model import utils as model_utils
from ...model import objects as model_objects

from ... import lib  # from . import db?

# local
from .logger import log__OperationsEvent
from .logger import _log_object_event
from .helpers import _certificate_parse_to_record
from ._utils import get_dbSessionLogItem


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__AcmeOrder(
    ctx,
    dbAcmeAccountKey=None,
    dbCertificateRequest=None,
    dbEventLogged=None,
    transaction_commit=None,
):
    """
    Create a new ACME Order
    
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeAccountKey: (required) The :class:`model.objects.AcmeAccountKey` associated with the order
    :param dbCertificateRequest: (required) The :class:`model.objects.CertificateRequest` associated with the order
    :param dbEventLogged: (required) The :class:`model.objects.AcmeEventLog` associated with submitting the order to LetsEncrypt
    :param transaction_commit: (required) Boolean value. required to indicate this persists to the database.
    """
    if not transaction_commit:
        raise ValueError("`create__AcmeOrder` must persist to the database.")

    dbAcmeOrder = model_objects.AcmeOrder()
    dbAcmeOrder.timestamp_created = ctx.timestamp
    dbAcmeOrder.acme_account_key_id = dbAcmeAccountKey.id
    dbAcmeOrder.acme_event_log_id = dbEventLogged.id
    dbAcmeOrder.certificate_request_id = dbCertificateRequest.id
    ctx.dbSession.add(dbAcmeOrder)
    ctx.dbSession.flush(objects=[dbAcmeOrder])

    # then update the event with the order
    dbEventLogged.acme_order_id = dbAcmeOrder.id
    ctx.dbSession.flush(objects=[dbEventLogged])

    # persist this to the db
    if transaction_commit:
        ctx.transaction_manager.commit()
        ctx.transaction_manager.begin()

    return dbAcmeOrder


def create__AcmeAuthorization(*args, **kwargs):
    raise ValueError("use `getcreate__AcmeAuthorization`")


def create__AcmeChallenge(*args, **kwargs):
    raise ValueError(
        "use `getcreate__AcmeAuthorization` for implicit AcmeChallenge creation"
    )


def create__AcmeChallengePoll(ctx, dbAcmeChallenge=None, remote_ip_address=None):
    """
    Create a new AcmeChallengePoll - this is a log
    
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbAcmeChallenge: (required) The challenge which was polled
    :param remote_ip_address: (required) The remote ip address (string)
    """
    dbAcmeChallengePoll = model_objects.AcmeChallengePoll()
    dbAcmeChallengePoll.acme_challenge_id = dbAcmeChallenge.id
    dbAcmeChallengePoll.timestamp_polled = ctx.timestamp
    dbAcmeChallengePoll.remote_ip_address = remote_ip_address
    ctx.dbSession.add(dbAcmeChallengePoll)
    ctx.dbSession.flush(objects=[dbAcmeChallengePoll])
    return dbAcmeChallengePoll


def create__AcmeChallengeUnknownPoll(
    ctx, domain=None, challenge=None, remote_ip_address=None
):
    """
    Create a new AcmeChallengeUnknownPoll - this is an unknown polling
    
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain: (required) domain (string)
    :param challenge: (required) challenge (string)
    :param remote_ip_address: (required) remote_ip_address (string)
    """
    dbSessionLogItem = get_dbSessionLogItem(ctx)
    dbAcmeChallengeUnknownPoll = model_objects.AcmeChallengeUnknownPoll()
    dbAcmeChallengeUnknownPoll.domain = domain
    dbAcmeChallengeUnknownPoll.challenge = challenge
    dbAcmeChallengeUnknownPoll.timestamp_polled = ctx.timestamp
    dbAcmeChallengeUnknownPoll.remote_ip_address = remote_ip_address
    dbSessionLogItem.add(dbAcmeChallengeUnknownPoll)
    dbSessionLogItem.flush(objects=[dbAcmeChallengeUnknownPoll])
    return dbAcmeChallengeUnknownPoll


def create__CertificateRequest(
    ctx,
    csr_pem=None,
    certificate_request_source_id=None,
    dbPrivateKey=None,
    dbServerCertificate__issued=None,
    dbServerCertificate__renewal_of=None,
    domain_names=None,
):
    """
    Create a new Certificate Signing Request (CSR)
    
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param csr_pem: (required) A Certificate Signing Request with PEM formatting
    :param certificate_request_source_id: (required) What is the source of this? 
        Valid options are in `model_utils.CertificateRequestSource`
    :param dbPrivateKey: (required) Private Key used to sign the CSR
    
    invoked by:
        lib.db.actions.do__CertificateRequest__AcmeV2_Automated
            ctx,
            csr_pem,
            certificate_request_source_id=model_utils.CertificateRequestSource.ACME_AUTOMATED,
            dbAcmeAccountKey=dbAcmeAccountKey,
            dbPrivateKey=dbPrivateKey,
            dbServerCertificate__issued=None,
            dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
            domain_names=domain_names,
        lib.db.getcreate__CertificateRequest__by_pem_text
            ctx,
            csr_pem,
            certificate_request_source_id=certificate_request_source_id,
            dbAcmeAccountKey=dbAcmeAccountKey,
            dbPrivateKey=dbPrivateKey,
            dbServerCertificate__issued=dbServerCertificate__issued,
            dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
    """
    if certificate_request_source_id not in (
        model_utils.CertificateRequestSource.ACME_AUTOMATED,
    ):
        raise ValueError("Unsupported `certificate_request_source_id`")

    _event_type_id = None
    if (
        certificate_request_source_id
        == model_utils.CertificateRequestSource.ACME_AUTOMATED
    ):
        _event_type_id = model_utils.OperationsEventType.from_string(
            "certificate_request__new__automated"
        )
    else:
        # this is probably the ".REPORTING" which is used for historical stuff
        raise ValueError("unsupported `certificate_request_source_id`")

    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(ctx, _event_type_id)

    if dbPrivateKey is None:
        raise ValueError("Must submit `dbPrivateKey` for creation")

    if csr_pem is None:
        raise ValueError("Must submit a valid `csr_pem`")
    csr_pem = cert_utils.cleanup_pem_text(csr_pem)

    # scoping
    csr_domain_names = None
    csr_pem_md5 = None
    csr_pem_modulus_md5 = None

    _tmpfile = None
    try:
        # store the csr_text in a tmpfile
        _tmpfile = cert_utils.new_pem_tempfile(csr_pem)

        # validate
        cert_utils.validate_csr__pem_filepath(_tmpfile.name)

        _csr_domain_names = cert_utils.parse_csr_domains(
            csr_path=_tmpfile.name, submitted_domain_names=domain_names
        )
        csr_domain_names = utils.domains_from_list(_csr_domain_names)
        if len(csr_domain_names) != len(_csr_domain_names):
            raise ValueError(
                "One or more of the domain names in the CSR are not allowed (%s)"
                % _csr_domain_names
            )
        if not csr_domain_names:
            raise ValueError(
                "Must submit `csr_pem` that contains `domain_names` (found None)"
            )
        if set(csr_domain_names) != set(domain_names):
            raise ValueError(
                "received different values for `domain_names` than exist in the CSR"
            )

        # calculate the md5
        csr_pem_md5 = utils.md5_text(csr_pem)
        # grab the modulus
        csr_pem_modulus_md5 = cert_utils.modulus_md5_csr__pem_filepath(_tmpfile.name)
    finally:
        _tmpfile.close()

    # ensure the domains are registered into our system
    dbDomainObjects = {
        _domain_name: lib.db.getcreate.getcreate__Domain__by_domainName(
            ctx, _domain_name
        )[0]
        for _domain_name in domain_names
    }
    # we'll use this tuple in a bit...
    # getcreate__Domain__by_domainName returns a tuple of (domainObject, is_created)
    (
        dbUniqueFqdnSet,
        is_created_fqdn,
    ) = lib.db.getcreate.getcreate__UniqueFQDNSet__by_domainObjects(
        ctx, dbDomainObjects.values()
    )

    # build the cert
    dbCertificateRequest = model_objects.CertificateRequest()
    dbCertificateRequest.is_active = True
    dbCertificateRequest.timestamp_created = ctx.timestamp
    dbCertificateRequest.certificate_request_source_id = certificate_request_source_id
    dbCertificateRequest.csr_pem = csr_pem
    dbCertificateRequest.csr_pem_md5 = csr_pem_md5  # computed in initial block
    dbCertificateRequest.csr_pem_modulus_md5 = (
        csr_pem_modulus_md5  # computed in initial block
    )
    dbCertificateRequest.operations_event_id__created = dbOperationsEvent.id
    dbCertificateRequest.private_key_id__signed_by = dbPrivateKey.id
    if dbServerCertificate__renewal_of:
        dbCertificateRequest.server_certificate_id__renewal_of = (
            dbServerCertificate__renewal_of.id
        )
    dbCertificateRequest.unique_fqdn_set_id = dbUniqueFqdnSet.id

    ctx.dbSession.add(dbCertificateRequest)
    ctx.dbSession.flush(objects=[dbCertificateRequest])

    event_payload_dict["certificate_request.id"] = dbCertificateRequest.id
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            "certificate_request__insert"
        ),
        dbCertificateRequest=dbCertificateRequest,
    )

    #
    # increment private key counts
    #
    dbPrivateKey.count_certificate_requests += 1
    if not dbPrivateKey.timestamp_last_certificate_request or (
        dbPrivateKey.timestamp_last_certificate_request < ctx.timestamp
    ):
        dbPrivateKey.timestamp_last_certificate_request = ctx.timestamp
    ctx.dbSession.flush(objects=[dbPrivateKey])

    return dbCertificateRequest


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__ServerCertificate(
    ctx,
    timestamp_signed=None,
    timestamp_expires=None,
    is_active=None,
    cert_pem=None,
    chained_pem=None,
    chain_name=None,
    dbCertificateRequest=None,
    # dbAcmeAccountKey=None,
    dbDomains=None,
    dbServerCertificate__renewal_of=None,
    dbPrivateKey=None,
):
    """
    Create a new ServerCertificate
    
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param dbPrivateKey: (required) The :class:`model.objects.PrivateKey` that signed the certificate

    """
    if not dbPrivateKey:
        raise ValueError(
            "create__ServerCertificate must be provided with `dbPrivateKey`"
        )

    # we need to figure this out; it's the chained_pem
    # ca_certificate_id__upchain
    (
        dbCACertificate,
        _is_created_cert,
    ) = lib.db.getcreate.getcreate__CaCertificate__by_pem_text(
        ctx, chained_pem, chain_name
    )
    ca_certificate_id__upchain = dbCACertificate.id

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("certificate__insert")
    )

    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    try:
        _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

        # validate
        cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

        # pull the domains, so we can get the fqdn
        (
            dbUniqueFqdnSet,
            is_created_fqdn,
        ) = lib.db.getcreate.getcreate__UniqueFQDNSet__by_domainObjects(ctx, dbDomains)

        dbServerCertificate = model_objects.ServerCertificate()
        _certificate_parse_to_record(_tmpfileCert, dbServerCertificate)

        # we don't need these anymore, because we're parsing the cert
        # dbServerCertificate.timestamp_signed = timestamp_signed
        # dbServerCertificate.timestamp_expires = timestamp_signed

        dbServerCertificate.is_active = is_active
        dbServerCertificate.cert_pem = cert_pem
        dbServerCertificate.cert_pem_md5 = utils.md5_text(cert_pem)
        if dbCertificateRequest:
            dbCertificateRequest.is_active = False
            dbServerCertificate.certificate_request_id = dbCertificateRequest.id
        dbServerCertificate.ca_certificate_id__upchain = ca_certificate_id__upchain
        if dbServerCertificate__renewal_of:
            dbServerCertificate.server_certificate_id__renewal_of = (
                dbServerCertificate__renewal_of.id
            )

        # note account/private keys
        dbServerCertificate.acme_account_key_id = dbAcmeAccountKey.id
        dbServerCertificate.private_key_id__signed_by = dbPrivateKey.id

        # note the fqdn
        dbServerCertificate.unique_fqdn_set_id = dbUniqueFqdnSet.id

        # note the event
        dbServerCertificate.operations_event_id__created = dbOperationsEvent.id

        ctx.dbSession.add(dbServerCertificate)
        ctx.dbSession.flush(objects=[dbServerCertificate])

        # increment account/private key counts
        dbAcmeAccountKey.count_certificates_issued += 1
        dbPrivateKey.count_certificates_issued += 1
        if not dbAcmeAccountKey.timestamp_last_certificate_issue or (
            dbAcmeAccountKey.timestamp_last_certificate_issue < timestamp_signed
        ):
            dbAcmeAccountKey.timestamp_last_certificate_issue = timestamp_signed
        if not dbPrivateKey.timestamp_last_certificate_issue or (
            dbPrivateKey.timestamp_last_certificate_issue < timestamp_signed
        ):
            dbPrivateKey.timestamp_last_certificate_issue = timestamp_signed

        event_payload_dict["server_certificate.id"] = dbServerCertificate.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "certificate__insert"
            ),
            dbServerCertificate=dbServerCertificate,
        )

        # final, just to be safe
        ctx.dbSession.flush()

    except Exception as exc:
        raise
    finally:
        _tmpfileCert.close()

    return dbServerCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__PrivateKey__autogenerated(ctx):
    """
    Generates a new :class:`model.objects.PrivateKey` for the datastore

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    """
    key_pem = cert_utils.new_private_key()
    dbPrivateKey, _is_created = lib.db.getcreate.getcreate__PrivateKey__by_pem_text(
        ctx, key_pem, is_autogenerated_key=True
    )
    return dbPrivateKey


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _create__QueueRenewal(ctx, serverCertificate):
    """
    Queues an item for renewal

    This must happen within the context other events

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    if not ctx.dbOperationsEvent:
        raise ValueError("This must happen WITHIN an operations event")

    dbQueueRenewal = model_objects.QueueRenewal()
    dbQueueRenewal.timestamp_entered = ctx.timestamp
    dbQueueRenewal.timestamp_processed = None
    dbQueueRenewal.server_certificate_id = serverCertificate.id
    dbQueueRenewal.unique_fqdn_set_id = serverCertificate.unique_fqdn_set_id
    dbQueueRenewal.operations_event_id__created = ctx.dbOperationsEvent.id
    ctx.dbSession.add(dbQueueRenewal)
    ctx.dbSession.flush(objects=[dbQueueRenewal])

    event_payload = ctx.dbOperationsEvent.event_payload_json
    event_payload["queue_renewal.id"] = dbQueueRenewal.id
    ctx.dbOperationsEvent.set_event_payload(event_payload)
    ctx.dbSession.flush(objects=[ctx.dbOperationsEvent])

    _log_object_event(
        ctx,
        dbOperationsEvent=ctx.dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            "queue_renewal__insert"
        ),
        dbQueueRenewal=dbQueueRenewal,
    )

    return dbQueueRenewal


def _create__QueueRenewal_fqdns(ctx, unique_fqdn_set_id):
    """
    Queues an item for renewal

    This must happen within the context other events

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param unique_fqdn_set_id: (required) The id of a :class:`model.objects.UniqueFqdnSet` object
    """
    if not ctx.dbOperationsEvent:
        raise ValueError("This must happen WITHIN an operations event")

    dbQueueRenewal = model_objects.QueueRenewal()
    dbQueueRenewal.timestamp_entered = ctx.timestamp
    dbQueueRenewal.timestamp_processed = None
    dbQueueRenewal.server_certificate_id = None
    dbQueueRenewal.unique_fqdn_set_id = unique_fqdn_set_id
    dbQueueRenewal.operations_event_id__created = ctx.dbOperationsEvent.id
    ctx.dbSession.add(dbQueueRenewal)
    ctx.dbSession.flush(objects=[dbQueueRenewal])

    event_payload = ctx.dbOperationsEvent.event_payload_json
    event_payload["queue_renewal.id"] = dbQueueRenewal.id
    ctx.dbOperationsEvent.set_event_payload(event_payload)
    ctx.dbSession.flush(objects=[ctx.dbOperationsEvent])

    _log_object_event(
        ctx,
        dbOperationsEvent=ctx.dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            "queue_renewal__insert"
        ),
        dbQueueRenewal=dbQueueRenewal,
    )

    return dbQueueRenewal


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "create__CertificateRequest",
    "create__ServerCertificate",
    "create__PrivateKey__autogenerated",
    "_create__QueueRenewal",
    "_create__QueueRenewal_fqdns",
)
