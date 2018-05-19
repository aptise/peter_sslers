# logging
import logging
log = logging.getLogger(__name__)

# localapp
from ...models import models
from ... import lib  # from . import db?
from .. import cert_utils
from .. import utils

# local
from .logger import log__SslOperationsEvent
from .logger import _log_object_event
from .helpers import _certificate_parse_to_record

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__SslCertificateRequest(
    ctx,
    csr_pem = None,
    certificate_request_type_id = None,
    dbAccountKey = None,
    dbPrivateKey = None,
    dbServerCertificate__issued = None,
    dbServerCertificate__renewal_of = None,
    domain_names = None,
):
    """
    create CSR
    2016.06.04 - dbOperationsEvent compliant
    """
    if certificate_request_type_id not in (
        models.SslCertificateRequestType.ACME_FLOW,
        models.SslCertificateRequestType.ACME_AUTOMATED,
    ):
        raise ValueError("Invalid `certificate_request_type_id`")

    _event_type_id = None
    if certificate_request_type_id == models.SslCertificateRequestType.ACME_FLOW:
        _event_type_id = models.SslOperationsEventType.from_string('certificate_request__new__flow')
    elif certificate_request_type_id == models.SslCertificateRequestType.ACME_AUTOMATED:
        _event_type_id = models.SslOperationsEventType.from_string('certificate_request__new__automated')

    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                _event_type_id,
                                                )

    # if there is a csr_pem; extract the domains
    csr_domain_names = None
    if csr_pem is None:
        if not domain_names:
            raise ValueError("Must submit `csr_pem` that contains `domain_names` or explicitly provide `domain_names` (found neither)")
    if csr_pem is not None:
        _tmpfile = None
        try:
            # store the csr_text in a tmpfile
            _tmpfile = cert_utils.new_pem_tempfile(csr_pem)
            _csr_domain_names = cert_utils.parse_csr_domains(csr_path=_tmpfile.name,
                                                             submitted_domain_names=domain_names,
                                                             )
            csr_domain_names = utils.domains_from_list(_csr_domain_names)
            if len(csr_domain_names) != len(_csr_domain_names):
                raise ValueError("One or more of the domain names in the CSR are not allowed (%s)" % _csr_domain_names)
            if not csr_domain_names:
                raise ValueError("Must submit `csr_pem` that contains `domain_names` (found none)")
        finally:
            _tmpfile.close()

    if certificate_request_type_id == models.SslCertificateRequestType.ACME_FLOW:
        if domain_names is None:
            if csr_pem is None:
                raise ValueError("Must submit `csr_pem` if not submitting `domain_names`")
            domain_names = csr_domain_names
        else:
            if csr_domain_names:
                if set(domain_names) != set(csr_domain_names):
                    raise ValueError("Must submit `csr_pem` that matches submitted `domain_names`")
            else:
                domain_names = utils.domains_from_list(domain_names)

        if not domain_names:
            raise ValueError("We have no domains")

        # getcreate__SslDomain__by_domainName returns a tuple of (domainObject, is_created)
        dbDomainObjects = [lib.db.getcreate.getcreate__SslDomain__by_domainName(ctx, _domain_name)[0]
                           for _domain_name in domain_names]
        (dbUniqueFqdnSet,
         is_created_fqdn
         ) = lib.db.getcreate.getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, dbDomainObjects)

        dbCertificateRequest = models.SslCertificateRequest()
        dbCertificateRequest.is_active = True
        dbCertificateRequest.csr_pem = csr_pem
        dbCertificateRequest.certificate_request_type_id = models.SslCertificateRequestType.ACME_FLOW
        dbCertificateRequest.timestamp_started = ctx.timestamp
        dbCertificateRequest.ssl_unique_fqdn_set_id = dbUniqueFqdnSet.id
        dbCertificateRequest.ssl_operations_event_id__created = dbOperationsEvent.id

        # note account/private keys
        # these were most-likely-NOT provided
        if dbPrivateKey:
            dbCertificateRequest.ssl_private_key_id__signed_by = dbPrivateKey.id
        if dbAccountKey:
            dbCertificateRequest.ssl_acme_account_key_id = dbAccountKey.id

        ctx.dbSession.add(dbCertificateRequest)
        ctx.dbSession.flush(objects=[dbCertificateRequest, ])

        event_payload_dict['ssl_certificate_request.id'] = dbCertificateRequest.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent, ])

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=models.SslOperationsObjectEventStatus.from_string('certificate_request__insert'),
                          dbCertificateRequest=dbCertificateRequest,
                          )

        for dbDomain in dbDomainObjects:
            dbCertificateRequest2D = models.SslCertificateRequest2SslDomain()
            dbCertificateRequest2D.ssl_certificate_request_id = dbCertificateRequest.id
            dbCertificateRequest2D.ssl_domain_id = dbDomain.id
            ctx.dbSession.add(dbCertificateRequest2D)
            ctx.dbSession.flush(objects=[dbCertificateRequest2D, ])

        return dbCertificateRequest, dbDomainObjects

    if dbPrivateKey is None:
        raise ValueError("Must submit `dbPrivateKey` for creation")

    # PARSE FROM THE CSR
    # timestamp_started
    # domains / ssl_unique_fqdn_set_id
    # domain_names = list(domain_names)

    _tmpfile = None
    dbCertificateRequest = None
    dbDomainObjects = None
    try:
        t_now = ctx.timestamp

        csr_pem = cert_utils.cleanup_pem_text(csr_pem)
        csr_pem_md5 = utils.md5_text(csr_pem)

        # store the csr_text in a tmpfile
        _tmpfile = cert_utils.new_pem_tempfile(csr_pem)

        # validate
        cert_utils.validate_csr__pem_filepath(_tmpfile.name)

        # grab the modulus
        csr_pem_modulus_md5 = cert_utils.modulus_md5_csr__pem_filepath(_tmpfile.name)

        # we'll use this tuple in a bit...
        # getcreate__SslDomain__by_domainName returns a tuple of (domainObject, is_created)
        dbDomainObjects = {_domain_name: lib.db.getcreate.getcreate__SslDomain__by_domainName(ctx, _domain_name)[0]
                           for _domain_name in domain_names
                           }
        (dbUniqueFqdnSet,
         is_created_fqdn
         ) = lib.db.getcreate.getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, dbDomainObjects.values())

        # build the cert
        dbCertificateRequest = models.SslCertificateRequest()
        dbCertificateRequest.is_active = True
        dbCertificateRequest.certificate_request_type_id = certificate_request_type_id
        dbCertificateRequest.timestamp_started = t_now
        dbCertificateRequest.csr_pem = csr_pem
        dbCertificateRequest.csr_pem_md5 = utils.md5_text(csr_pem)
        dbCertificateRequest.csr_pem_modulus_md5 = csr_pem_modulus_md5
        dbCertificateRequest.ssl_unique_fqdn_set_id = dbUniqueFqdnSet.id
        dbCertificateRequest.ssl_operations_event_id__created = dbOperationsEvent.id
        # note account/private keys
        dbCertificateRequest.ssl_private_key_id__signed_by = dbPrivateKey.id
        if dbAccountKey:
            dbCertificateRequest.ssl_acme_account_key_id = dbAccountKey.id

        if dbServerCertificate__renewal_of:
            dbCertificateRequest.ssl_server_certificate_id__renewal_of = dbServerCertificate__renewal_of.id

        ctx.dbSession.add(dbCertificateRequest)
        ctx.dbSession.flush(objects=[dbCertificateRequest, ])

        event_payload_dict['ssl_certificate_request.id'] = dbCertificateRequest.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent, ])

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=models.SslOperationsObjectEventStatus.from_string('certificate_request__insert'),
                          dbCertificateRequest=dbCertificateRequest,
                          )

        #
        # increment account/private key counts
        #
        # dbAccountKey is optional
        if dbAccountKey:
            dbAccountKey.count_certificate_requests += 1
            if ((not dbAccountKey.timestamp_last_certificate_request) or (dbAccountKey.timestamp_last_certificate_request < t_now)):
                dbAccountKey.timestamp_last_certificate_request = t_now
        #
        # dbPrivateKey is required
        #
        dbPrivateKey.count_certificate_requests += 1
        if not dbPrivateKey.timestamp_last_certificate_request or (dbPrivateKey.timestamp_last_certificate_request < t_now):
            dbPrivateKey.timestamp_last_certificate_request = t_now
        ctx.dbSession.flush(objects=[dbPrivateKey, ])

        # we'll use this tuple in a bit...
        for _domain_name in dbDomainObjects.keys():
            dbDomain = dbDomainObjects[_domain_name]

            dbCertificateRequest2SslDomain = models.SslCertificateRequest2SslDomain()
            dbCertificateRequest2SslDomain.ssl_certificate_request_id = dbCertificateRequest.id
            dbCertificateRequest2SslDomain.ssl_domain_id = dbDomain.id

            ctx.dbSession.add(dbCertificateRequest2SslDomain)
            ctx.dbSession.flush(objects=[dbCertificateRequest2SslDomain, ])

            # update the hash to be a tuple
            dbDomainObjects[_domain_name] = (dbDomain, dbCertificateRequest2SslDomain)

        # final, just to be safe
        ctx.dbSession.flush()

    finally:
        if _tmpfile:
            _tmpfile.close()

    return dbCertificateRequest, dbDomainObjects


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def create__SslServerCertificate(
    ctx,
    timestamp_signed = None,
    timestamp_expires = None,
    is_active = None,
    cert_pem = None,
    chained_pem = None,
    chain_name = None,
    dbCertificateRequest = None,
    dbAcmeAccountKey = None,
    dbDomains = None,
    dbServerCertificate__renewal_of = None,

    # only one of these 2
    dbPrivateKey = None,
    privkey_pem = None,
):
    if not any((dbPrivateKey, privkey_pem)) or all((dbPrivateKey, privkey_pem)):
        raise ValueError("create__SslServerCertificate must accept ONE OF [`dbPrivateKey`, `privkey_pem`]")
    if privkey_pem:
        raise ValueError("need to figure this out; might not need it")

    # we need to figure this out; it's the chained_pem
    # ssl_ca_certificate_id__upchain
    (dbCACertificate,
     _is_created_cert
     ) = lib.db.getcreate.getcreate__SslCaCertificate__by_pem_text(ctx, chained_pem, chain_name)
    ssl_ca_certificate_id__upchain = dbCACertificate.id

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                models.SslOperationsEventType.from_string('certificate__insert'),
                                                )

    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    try:
        _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

        # validate
        cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

        # pull the domains, so we can get the fqdn
        (dbUniqueFqdnSet,
         is_created_fqdn
         ) = lib.db.getcreate.getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, dbDomains)

        dbServerCertificate = models.SslServerCertificate()
        _certificate_parse_to_record(_tmpfileCert, dbServerCertificate)

        # we don't need these anymore, because we're parsing the cert
        # dbServerCertificate.timestamp_signed = timestamp_signed
        # dbServerCertificate.timestamp_expires = timestamp_signed

        dbServerCertificate.is_active = is_active
        dbServerCertificate.cert_pem = cert_pem
        dbServerCertificate.cert_pem_md5 = utils.md5_text(cert_pem)
        if dbCertificateRequest:
            dbCertificateRequest.is_active = False
            dbServerCertificate.ssl_certificate_request_id = dbCertificateRequest.id
        dbServerCertificate.ssl_ca_certificate_id__upchain = ssl_ca_certificate_id__upchain
        if dbServerCertificate__renewal_of:
            dbServerCertificate.ssl_server_certificate_id__renewal_of = dbServerCertificate__renewal_of.id

        # note account/private keys
        dbServerCertificate.ssl_acme_account_key_id = dbAcmeAccountKey.id
        dbServerCertificate.ssl_private_key_id__signed_by = dbPrivateKey.id

        # note the fqdn
        dbServerCertificate.ssl_unique_fqdn_set_id = dbUniqueFqdnSet.id

        # note the event
        dbServerCertificate.ssl_operations_event_id__created = dbOperationsEvent.id

        ctx.dbSession.add(dbServerCertificate)
        ctx.dbSession.flush(objects=[dbServerCertificate, ])

        # increment account/private key counts
        dbAcmeAccountKey.count_certificates_issued += 1
        dbPrivateKey.count_certificates_issued += 1
        if not dbAcmeAccountKey.timestamp_last_certificate_issue or (dbAcmeAccountKey.timestamp_last_certificate_issue < timestamp_signed):
            dbAcmeAccountKey.timestamp_last_certificate_issue = timestamp_signed
        if not dbPrivateKey.timestamp_last_certificate_issue or (dbPrivateKey.timestamp_last_certificate_issue < timestamp_signed):
            dbPrivateKey.timestamp_last_certificate_issue = timestamp_signed

        event_payload_dict['ssl_server_certificate.id'] = dbServerCertificate.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent, ])

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=models.SslOperationsObjectEventStatus.from_string('certificate__insert'),
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


def create__SslPrivateKey__autogenerated(ctx):
    """
    create wrapping private key generation
    2016.06.04 - dbOperationsEvent compliant
    """
    key_pem = cert_utils.new_private_key()
    dbPrivateKey, _is_created = lib.db.getcreate.getcreate__SslPrivateKey__by_pem_text(
        ctx,
        key_pem,
        is_autogenerated_key=True
    )
    return dbPrivateKey


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _create__SslQueueRenewal(ctx, serverCertificate):
    """
    Queues an item for renewal
    This must happen within the context other events
    2016.06.04 - dbOperationsEvent compliant
    """
    if not ctx.dbOperationsEvent:
        raise ValueError("This must happen WITHIN an operations event")

    dbQueueRenewal = models.SslQueueRenewal()
    dbQueueRenewal.timestamp_entered = ctx.timestamp
    dbQueueRenewal.timestamp_processed = None
    dbQueueRenewal.ssl_server_certificate_id = serverCertificate.id
    dbQueueRenewal.ssl_unique_fqdn_set_id = serverCertificate.ssl_unique_fqdn_set_id
    dbQueueRenewal.ssl_operations_event_id__created = ctx.dbOperationsEvent.id
    ctx.dbSession.add(dbQueueRenewal)
    ctx.dbSession.flush(objects=[dbQueueRenewal, ])

    event_payload = ctx.dbOperationsEvent.event_payload_json
    event_payload['ssl_queue_renewal.id'] = dbQueueRenewal.id
    ctx.dbOperationsEvent.set_event_payload(event_payload)
    ctx.dbSession.flush(objects=[ctx.dbOperationsEvent, ])

    _log_object_event(ctx,
                      dbOperationsEvent=ctx.dbOperationsEvent,
                      event_status_id=models.SslOperationsObjectEventStatus.from_string('queue_renewal__insert'),
                      dbQueueRenewal=dbQueueRenewal,
                      )

    return dbQueueRenewal


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ('create__SslCertificateRequest',
           'create__SslServerCertificate',
           'create__SslPrivateKey__autogenerated',
           '_create__SslQueueRenewal',
           )
