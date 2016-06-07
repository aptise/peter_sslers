# stdlib
import datetime
import logging
import pdb
import tempfile

# pypi
import sqlalchemy
import transaction
from zope.sqlalchemy import mark_changed

# localapp
from ...models import *
from .. import acme
from .. import cert_utils
from .. import letsencrypt_info
from .. import errors
from .. import events
from .. import utils

# setup logging
log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

from .get import *


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslLetsEncryptAccountKey__by_pem_text(ctx, key_pem):
    """
    Gets or Creates AccountKeys for LetsEncrypts' ACME server
    2016.06.04 - dbOperationsEvent compliant
    """
    key_pem = cert_utils.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    is_created = False
    dbLetsEncryptAccountKey = ctx.dbSession.query(SslLetsEncryptAccountKey)\
        .filter(SslLetsEncryptAccountKey.key_pem_md5 == key_pem_md5,
                SslLetsEncryptAccountKey.key_pem == key_pem,
                )\
        .first()
    if not dbLetsEncryptAccountKey:
        try:
            _tmpfile = cert_utils.new_pem_tempfile(key_pem)

            # validate
            cert_utils.validate_key__pem_filepath(_tmpfile.name)

            # grab the modulus
            key_pem_modulus_md5 = cert_utils.modulus_md5_key__pem_filepath(_tmpfile.name)
        except:
            raise
        finally:
            _tmpfile.close()

        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    SslOperationsEventType.from_string('letsencrypt_account_key__insert'),
                                                    )

        dbLetsEncryptAccountKey = SslLetsEncryptAccountKey()
        dbLetsEncryptAccountKey.timestamp_first_seen = ctx.timestamp
        dbLetsEncryptAccountKey.key_pem = key_pem
        dbLetsEncryptAccountKey.key_pem_md5 = key_pem_md5
        dbLetsEncryptAccountKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbLetsEncryptAccountKey.ssl_operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbLetsEncryptAccountKey)
        ctx.dbSession.flush()
        is_created = True

        event_payload_dict['ssl_letsencrypt_account_key.id'] = dbLetsEncryptAccountKey.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=SslOperationsObjectEventStatus.from_string('letsencrypt_account_key__insert'),
                          dbLetsEncryptAccountKey=dbLetsEncryptAccountKey,
                          )
        ctx.dbSession.flush()

    return dbLetsEncryptAccountKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslCaCertificate__by_pem_text(
    ctx,
    cert_pem,
    chain_name,
    le_authority_name = None,
    is_authority_certificate = None,
    is_cross_signed_authority_certificate = None,
):
    """
    Gets or Creates CaCertificates
    2016.06.04 - dbOperationsEvent compliant
    """
    dbCACertificate = get__SslCaCertificate__by_pem_text(ctx, cert_pem)
    is_created = False
    if not dbCACertificate:
        cert_pem = cert_utils.cleanup_pem_text(cert_pem)
        cert_pem_md5 = utils.md5_text(cert_pem)
        try:
            _tmpfile = cert_utils.new_pem_tempfile(cert_pem)

            # validate
            cert_utils.validate_cert__pem_filepath(_tmpfile.name)

            # grab the modulus
            cert_pem_modulus_md5 = cert_utils.modulus_md5_cert__pem_filepath(_tmpfile.name)

            # bookkeeping
            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                        SslOperationsEventType.from_string('ca_certificate__insert'),
                                                        )

            dbCACertificate = SslCaCertificate()
            dbCACertificate.name = chain_name or 'unknown'

            dbCACertificate.le_authority_name = le_authority_name
            dbCACertificate.is_ca_certificate = True
            dbCACertificate.is_authority_certificate = is_authority_certificate
            dbCACertificate.is_cross_signed_authority_certificate = is_cross_signed_authority_certificate
            dbCACertificate.id_cross_signed_of = None
            dbCACertificate.timestamp_first_seen = ctx.timestamp
            dbCACertificate.cert_pem = cert_pem
            dbCACertificate.cert_pem_md5 = cert_pem_md5
            dbCACertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

            dbCACertificate.timestamp_signed = cert_utils.parse_startdate_cert__pem_filepath(_tmpfile.name)
            dbCACertificate.timestamp_expires = cert_utils.parse_enddate_cert__pem_filepath(_tmpfile.name)
            dbCACertificate.cert_subject = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-subject')
            dbCACertificate.cert_subject_hash = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-subject_hash')
            dbCACertificate.cert_issuer = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-issuer')
            dbCACertificate.cert_issuer_hash = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-issuer_hash')
            dbCACertificate.ssl_operations_event_id__created = dbOperationsEvent.id

            ctx.dbSession.add(dbCACertificate)
            ctx.dbSession.flush()
            is_created = True

            event_payload_dict['ssl_ca_certificate.id'] = dbCACertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush()

            _log_object_event(ctx,
                              dbOperationsEvent=dbOperationsEvent,
                              event_status_id=SslOperationsObjectEventStatus.from_string('ca_certificate__insert'),
                              dbCACertificate=dbCACertificate,
                              )
            ctx.dbSession.flush()

        except:
            raise
        finally:
            _tmpfile.close()

    return dbCACertificate, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslCertificateRequest__by_pem_text(
    ctx,
    csr_pem,
    certificate_request_type_id = None,
    dbAccountKey = None,
    dbPrivateKey = None,
    dbServerCertificate__issued = None,
    dbServerCertificate__renewal_of = None,
):
    """
    getcreate for a CSR
    log__SslOperationsEvent takes place in `create__SslCertificateRequest`
    2016.06.04 - dbOperationsEvent compliant
    """
    dbCertificateRequest = get__SslCertificateRequest__by_pem_text(ctx, csr_pem)
    is_created = False
    if not dbCertificateRequest:
        dbCertificateRequest, dbDomainObjects = create__SslCertificateRequest(
            ctx,
            csr_pem,
            certificate_request_type_id = certificate_request_type_id,
            dbAccountKey = dbAccountKey,
            dbPrivateKey = dbPrivateKey,
            dbServerCertificate__issued = dbServerCertificate__issued,
            dbServerCertificate__renewal_of = dbServerCertificate__renewal_of,
        )
        is_created = True

    return dbCertificateRequest, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def getcreate__SslDomain__by_domainName(
    ctx,
    domain_name,
    is_from_queue_domain=None,
):
    """
    getcreate wrapping a domain
    2016.06.04 - dbOperationsEvent compliant
    """
    is_created = False
    dbDomain = get__SslDomain__by_name(ctx, domain_name, preload=False)
    if not dbDomain:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    SslOperationsEventType.from_string('domain__insert'),
                                                    )
        dbDomain = SslDomain()
        dbDomain.domain_name = domain_name
        dbDomain.timestamp_first_seen = ctx.timestamp
        dbDomain.is_from_queue_domain = is_from_queue_domain
        dbDomain.ssl_operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbDomain)
        ctx.dbSession.flush()
        is_created = True

        event_payload_dict['ssl_domain.id'] = dbDomain.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=SslOperationsObjectEventStatus.from_string('domain__insert'),
                          dbDomain=dbDomain,
                          )
        ctx.dbSession.flush()

    return dbDomain, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslPrivateKey__by_pem_text(
    ctx,
    key_pem,
    is_autogenerated_key=None,
):
    """
    getcreate wrapping private keys
    2016.06.04 - dbOperationsEvent compliant
    """
    key_pem = cert_utils.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    is_created = False
    dbPrivateKey = ctx.dbSession.query(SslPrivateKey)\
        .filter(SslPrivateKey.key_pem_md5 == key_pem_md5,
                SslPrivateKey.key_pem == key_pem,
                )\
        .first()
    if not dbPrivateKey:
        try:
            _tmpfile = cert_utils.new_pem_tempfile(key_pem)

            # validate
            cert_utils.validate_key__pem_filepath(_tmpfile.name)

            # grab the modulus
            key_pem_modulus_md5 = cert_utils.modulus_md5_key__pem_filepath(_tmpfile.name)
        except:
            raise
        finally:
            _tmpfile.close()

        event_payload_dict = utils.new_event_payload_dict()
        _event_type_id = SslOperationsEventType.from_string('private_key__insert')
        if is_autogenerated_key:
            _event_type_id = SslOperationsEventType.from_string('private_key__insert_autogenerated')
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    _event_type_id,
                                                    )

        dbPrivateKey = SslPrivateKey()
        dbPrivateKey.timestamp_first_seen = ctx.timestamp
        dbPrivateKey.key_pem = key_pem
        dbPrivateKey.key_pem_md5 = key_pem_md5
        dbPrivateKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbPrivateKey.is_autogenerated_key = is_autogenerated_key
        dbPrivateKey.ssl_operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbPrivateKey)
        ctx.dbSession.flush()
        is_created = True

        event_payload_dict['ssl_private_key.id'] = dbPrivateKey.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=SslOperationsObjectEventStatus.from_string('private_key__insert'),
                          dbPrivateKey=dbPrivateKey,
                          )
        ctx.dbSession.flush()

    return dbPrivateKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslServerCertificate__by_pem_text(
    ctx,
    cert_pem,
    dbCACertificate=None,
    dbAccountKey=None,
    dbPrivateKey=None,
    dbServerCertificate__renewal_of=None,
):
    """
    getcreate wrapping issued certs
    2016.06.04 - dbOperationsEvent compliant
    """
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    is_created = False
    dbServerCertificate = ctx.dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.cert_pem_md5 == cert_pem_md5,
                SslServerCertificate.cert_pem == cert_pem,
                )\
        .first()
    if dbServerCertificate:
        if dbPrivateKey and (dbServerCertificate.ssl_private_key_id__signed_by != dbPrivateKey.id):
            if dbServerCertificate.ssl_private_key_id__signed_by:
                raise ValueError("Integrity Error. Competing PrivateKey (!?)")
            elif dbServerCertificate.ssl_private_key_id__signed_by is None:
                dbServerCertificate.ssl_private_key_id__signed_by = dbPrivateKey.id
                dbPrivateKey.count_certificates_issued += 1
                if not dbPrivateKey.timestamp_last_certificate_issue or (dbPrivateKey.timestamp_last_certificate_issue < dbServerCertificate.timestamp_signed):
                    dbPrivateKey.timestamp_last_certificate_issue = dbServerCertificate.timestamp_signed
                ctx.dbSession.flush()
        if dbAccountKey and (dbServerCertificate.ssl_letsencrypt_account_key_id != dbAccountKey.id):
            if dbServerCertificate.ssl_letsencrypt_account_key_id:
                raise ValueError("Integrity Error. Competing AccountKey (!?)")
            elif dbServerCertificate.ssl_letsencrypt_account_key_id is None:
                dbServerCertificate.ssl_letsencrypt_account_key_id = dbAccountKey.id
                dbAccountKey.count_certificates_issued += 1
                if not dbAccountKey.timestamp_last_certificate_issue or (dbAccountKey.timestamp_last_certificate_issue < dbServerCertificate.timestamp_signed):
                    dbAccountKey.timestamp_last_certificate_issue = dbAccountKey.timestamp_signed
                ctx.dbSession.flush()
    elif not dbServerCertificate:
        _tmpfileCert = None
        try:
            _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

            # validate
            cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

            # bookkeeping
            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                        SslOperationsEventType.from_string('certificate__insert'),
                                                        )

            dbServerCertificate = SslServerCertificate()
            _certificate_parse_to_record(_tmpfileCert, dbServerCertificate)

            dbServerCertificate.is_active = True
            dbServerCertificate.cert_pem = cert_pem
            dbServerCertificate.cert_pem_md5 = cert_pem_md5

            if dbServerCertificate__renewal_of:
                dbServerCertificate.ssl_server_certificate_id__renewal_of = dbServerCertificate__renewal_of.id

            # this is the LetsEncrypt key
            if dbCACertificate is None:
                raise ValueError('dbCACertificate is None')
            # we should make sure it issued the certificate:
            if dbServerCertificate.cert_issuer_hash != dbCACertificate.cert_subject_hash:
                raise ValueError('dbCACertificate did not sign the certificate')
            dbServerCertificate.ssl_ca_certificate_id__upchain = dbCACertificate.id

            # this is the private key
            # we should make sure it signed the certificate
            # the md5 check isn't exact, BUT ITS CLOSE
            if dbPrivateKey is None:
                raise ValueError('dbPrivateKey is None')
            if dbServerCertificate.cert_pem_modulus_md5 != dbPrivateKey.key_pem_modulus_md5:
                raise ValueError('dbPrivateKey did not sign the certificate')
            dbServerCertificate.ssl_private_key_id__signed_by = dbPrivateKey.id
            dbPrivateKey.count_certificates_issued += 1
            if not dbPrivateKey.timestamp_last_certificate_issue or (dbPrivateKey.timestamp_last_certificate_issue < dbServerCertificate.timestamp_signed):
                dbPrivateKey.timestamp_last_certificate_issue = dbServerCertificate.timestamp_signed

            # did we submit an account key?
            if dbAccountKey:
                dbServerCertificate.ssl_letsencrypt_account_key_id = dbAccountKey.id
                dbAccountKey.count_certificates_issued += 1
                if not dbAccountKey.timestamp_last_certificate_issue or (dbAccountKey.timestamp_last_certificate_issue < dbAccountKey.timestamp_signed):
                    dbAccountKey.timestamp_last_certificate_issue = dbServerCertificate.timestamp_signed

            _subject_domain, _san_domains = cert_utils.parse_cert_domains__segmented(cert_path=_tmpfileCert.name)
            certificate_domain_names = _san_domains
            if _subject_domain is not None and _subject_domain not in certificate_domain_names:
                certificate_domain_names.insert(0, _subject_domain)
            if not certificate_domain_names:
                raise ValueError("could not find any domain names in the certificate")
            # getcreate__SslDomain__by_domainName returns a tuple of (domainObject, is_created)
            dbDomainObjects = [getcreate__SslDomain__by_domainName(ctx, _domain_name)[0]
                               for _domain_name in certificate_domain_names]
            dbUniqueFqdnSet, is_created_fqdn = getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, dbDomainObjects)
            dbServerCertificate.ssl_unique_fqdn_set_id = dbUniqueFqdnSet.id

            if len(certificate_domain_names) == 1:
                dbServerCertificate.is_single_domain_cert = True
            elif len(certificate_domain_names) > 1:
                dbServerCertificate.is_single_domain_cert = False

            dbServerCertificate.ssl_operations_event_id__created = dbOperationsEvent.id
            ctx.dbSession.add(dbServerCertificate)
            ctx.dbSession.flush()
            is_created = True

            event_payload_dict['ssl_server_certificate.id'] = dbServerCertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush()

            _log_object_event(ctx,
                              dbOperationsEvent=dbOperationsEvent,
                              event_status_id=SslOperationsObjectEventStatus.from_string('certificate__insert'),
                              dbServerCertificate=dbServerCertificate,
                              )
            ctx.dbSession.flush()

        except:
            raise
        finally:
            if _tmpfileCert:
                _tmpfileCert.close()

    return dbServerCertificate, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslUniqueFQDNSet__by_domainObjects(
    ctx,
    domainObjects,
):
    """
    getcreate wrapping unique fqdn
    2016.06.04 - dbOperationsEvent compliant
    """
    is_created = False

    domain_ids = [dbDomain.id for dbDomain in domainObjects]
    domain_ids.sort()
    domain_ids_string = ','.join([str(id) for id in domain_ids])

    dbUniqueFQDNSet = ctx.dbSession.query(SslUniqueFQDNSet)\
        .filter(SslUniqueFQDNSet.domain_ids_string == domain_ids_string,
                )\
        .first()

    if not dbUniqueFQDNSet:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    SslOperationsEventType.from_string('unqiue_fqdn__insert'),
                                                    )

        dbUniqueFQDNSet = SslUniqueFQDNSet()
        dbUniqueFQDNSet.domain_ids_string = domain_ids_string
        dbUniqueFQDNSet.timestamp_first_seen = ctx.timestamp
        dbUniqueFQDNSet.ssl_operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbUniqueFQDNSet)
        ctx.dbSession.flush()

        for dbDomain in domainObjects:
            dbAssoc = SslUniqueFQDNSet2SslDomain()
            dbAssoc.ssl_unique_fqdn_set_id = dbUniqueFQDNSet.id
            dbAssoc.ssl_domain_id = dbDomain.id
            ctx.dbSession.add(dbAssoc)
            ctx.dbSession.flush()
        is_created = True

        event_payload_dict['ssl_unique_fqdn_set.id'] = dbUniqueFQDNSet.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=SslOperationsObjectEventStatus.from_string('unqiue_fqdn__insert'),
                          dbUniqueFQDNSet=dbUniqueFQDNSet,
                          )
        ctx.dbSession.flush()

    return dbUniqueFQDNSet, is_created


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
        SslCertificateRequestType.ACME_FLOW,
        SslCertificateRequestType.ACME_AUTOMATED,
    ):
        raise ValueError("Invalid `certificate_request_type_id`")

    _event_type_id = None
    if certificate_request_type_id == SslCertificateRequestType.ACME_FLOW:
        _event_type_id = SslOperationsEventType.from_string('certificate_request__new__flow')
    elif certificate_request_type_id == SslCertificateRequestType.ACME_AUTOMATED:
        _event_type_id = SslOperationsEventType.from_string('certificate_request__new__automated')

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

    if certificate_request_type_id == SslCertificateRequestType.ACME_FLOW:
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
        dbDomainObjects = [getcreate__SslDomain__by_domainName(ctx, _domain_name)[0]
                           for _domain_name in domain_names]
        dbUniqueFqdnSet, is_created_fqdn = getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, dbDomainObjects)

        dbCertificateRequest = SslCertificateRequest()
        dbCertificateRequest.is_active = True
        dbCertificateRequest.csr_pem = csr_pem
        dbCertificateRequest.certificate_request_type_id = SslCertificateRequestType.ACME_FLOW
        dbCertificateRequest.timestamp_started = ctx.timestamp
        dbCertificateRequest.ssl_unique_fqdn_set_id = dbUniqueFqdnSet.id
        dbCertificateRequest.ssl_operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbCertificateRequest)
        ctx.dbSession.flush()

        event_payload_dict['ssl_certificate_request.id'] = dbCertificateRequest.id
        dbOperationsEvent.set_event_payload(event_payload_dict)

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=SslOperationsObjectEventStatus.from_string('certificate_request__insert'),
                          dbCertificateRequest=dbCertificateRequest,
                          )
        ctx.dbSession.flush()

        for dbDomain in dbDomainObjects:
            dbCertificateRequest2D = SslCertificateRequest2SslDomain()
            dbCertificateRequest2D.ssl_certificate_request_id = dbCertificateRequest.id
            dbCertificateRequest2D.ssl_domain_id = dbDomain.id
            ctx.dbSession.add(dbCertificateRequest2D)
            ctx.dbSession.flush()

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
        dbDomainObjects = {_domain_name: getcreate__SslDomain__by_domainName(ctx, _domain_name)[0]
                           for _domain_name in domain_names
                           }
        dbUniqueFqdnSet, is_created_fqdn = getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, dbDomainObjects.values())

        # build the cert
        dbCertificateRequest = SslCertificateRequest()
        dbCertificateRequest.is_active = True
        dbCertificateRequest.certificate_request_type_id = certificate_request_type_id
        dbCertificateRequest.timestamp_started = t_now
        dbCertificateRequest.csr_pem = csr_pem
        dbCertificateRequest.csr_pem_md5 = utils.md5_text(csr_pem)
        dbCertificateRequest.csr_pem_modulus_md5 = csr_pem_modulus_md5
        dbCertificateRequest.ssl_unique_fqdn_set_id = dbUniqueFqdnSet.id
        dbCertificateRequest.ssl_operations_event_id__created = dbOperationsEvent.id

        # note account/private keys
        if dbAccountKey:
            dbCertificateRequest.ssl_letsencrypt_account_key_id = dbAccountKey.id
        dbCertificateRequest.ssl_private_key_id__signed_by = dbPrivateKey.id
        if dbServerCertificate__renewal_of:
            dbCertificateRequest.ssl_server_certificate_id__renewal_of = dbServerCertificate__renewal_of.id

        ctx.dbSession.add(dbCertificateRequest)
        ctx.dbSession.flush()

        event_payload_dict['ssl_certificate_request.id'] = dbCertificateRequest.id
        dbOperationsEvent.set_event_payload(event_payload_dict)

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=SslOperationsObjectEventStatus.from_string('certificate_request__insert'),
                          dbCertificateRequest=dbCertificateRequest,
                          )
        ctx.dbSession.flush()

        #
        # increment account/private key counts
        #
        # dbAccountKey is optional
        if dbAccountKey:
            dbAccountKey.count_certificate_requests += 1
            if (
                not dbAccountKey.timestamp_last_certificate_request
                or
                (dbAccountKey.timestamp_last_certificate_request < t_now)
            ):
                dbAccountKey.timestamp_last_certificate_request = t_now
        #
        # dbPrivateKey is required
        #
        dbPrivateKey.count_certificate_requests += 1
        if not dbPrivateKey.timestamp_last_certificate_request or (dbPrivateKey.timestamp_last_certificate_request < t_now):
            dbPrivateKey.timestamp_last_certificate_request = t_now

        ctx.dbSession.flush()

        # we'll use this tuple in a bit...
        for _domain_name in dbDomainObjects.keys():
            dbDomain = dbDomainObjects[_domain_name]

            dbCertificateRequest2SslDomain = SslCertificateRequest2SslDomain()
            dbCertificateRequest2SslDomain.ssl_certificate_request_id = dbCertificateRequest.id
            dbCertificateRequest2SslDomain.ssl_domain_id = dbDomain.id

            ctx.dbSession.add(dbCertificateRequest2SslDomain)
            ctx.dbSession.flush()

            # update the hash to be a tuple
            dbDomainObjects[_domain_name] = (dbDomain, dbCertificateRequest2SslDomain)

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
    dbLetsEncryptAccountKey = None,
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
    dbCACertificate, _is_created_cert = getcreate__SslCaCertificate__by_pem_text(ctx, chained_pem, chain_name)
    ssl_ca_certificate_id__upchain = dbCACertificate.id

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                SslOperationsEventType.from_string('certificate__insert'),
                                                )

    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    try:
        _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

        # validate
        cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

        # pull the domains, so we can get the fqdn
        dbUniqueFqdnSet, is_created_fqdn = getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, dbDomains)

        dbServerCertificate = SslServerCertificate()
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
        dbServerCertificate.ssl_letsencrypt_account_key_id = dbLetsEncryptAccountKey.id
        dbServerCertificate.ssl_private_key_id__signed_by = dbPrivateKey.id

        # note the fqdn
        dbServerCertificate.ssl_unique_fqdn_set_id = dbUniqueFqdnSet.id

        # note the event
        dbServerCertificate.ssl_operations_event_id__created = dbOperationsEvent.id

        ctx.dbSession.add(dbServerCertificate)
        ctx.dbSession.flush()

        # increment account/private key counts
        dbLetsEncryptAccountKey.count_certificates_issued += 1
        dbPrivateKey.count_certificates_issued += 1
        if not dbLetsEncryptAccountKey.timestamp_last_certificate_issue or (dbLetsEncryptAccountKey.timestamp_last_certificate_issue < timestamp_signed):
            dbLetsEncryptAccountKey.timestamp_last_certificate_issue = timestamp_signed
        if not dbPrivateKey.timestamp_last_certificate_issue or (dbPrivateKey.timestamp_last_certificate_issue < timestamp_signed):
            dbPrivateKey.timestamp_last_certificate_issue = timestamp_signed

        event_payload_dict['ssl_server_certificate.id'] = dbServerCertificate.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()

        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=SslOperationsObjectEventStatus.from_string('certificate__insert'),
                          dbServerCertificate=dbServerCertificate,
                          )
        ctx.dbSession.flush()

    except:
        raise
    finally:
        _tmpfileCert.close()

    return dbServerCertificate


def log__SslOperationsEvent(
    ctx,
    event_type_id,
    event_payload_dict = None,
    operationsEvent_child_of=None,
    timestamp_event=None,
):
    """
    creates a SslOperationsEvent instance
    if needed, registers it into the ctx
    """
    # defaults
    # timestamp overwrite?
    timestamp_event = timestamp_event or ctx.timestamp
    # if we didn't pass in an explicit operationsEvent_child_of, use the global
    operationsEvent_child_of = operationsEvent_child_of or ctx.dbOperationsEvent

    if event_payload_dict is None:
        event_payload_dict = utils.new_event_payload_dict()

    # bookkeeping
    dbOperationsEvent = SslOperationsEvent()
    dbOperationsEvent.ssl_operations_event_type_id = event_type_id
    dbOperationsEvent.timestamp_event = timestamp_event
    dbOperationsEvent.set_event_payload(event_payload_dict)
    if operationsEvent_child_of:
        dbOperationsEvent.ssl_operations_event_id__child_of = operationsEvent_child_of.id
    ctx.dbSession.add(dbOperationsEvent)
    ctx.dbSession.flush()

    # shortcut!
    # if there isn't a global dbOperationsEvent, set it!
    if not ctx.dbOperationsEvent:
        ctx.dbOperationsEvent = dbOperationsEvent

    return dbOperationsEvent


def _log_object_event(
    ctx,
    dbOperationsEvent=None,
    event_status_id=None,
    dbLetsEncryptAccountKey=None,
    dbCACertificate=None,
    dbDomain=None,
    dbPrivateKey=None,
    dbServerCertificate=None,
    dbUniqueFQDNSet=None,
    dbCertificateRequest=None,
    dbQueueRenewal=None,
    dbQueueDomain=None,
):
    """additional logging for domains"""
    dbOperationsDomainEvent = SslOperationsObjectEvent()
    dbOperationsDomainEvent.ssl_operations_event_id = dbOperationsEvent.id
    dbOperationsDomainEvent.ssl_operations_object_event_status_id = event_status_id

    if dbLetsEncryptAccountKey:
        dbOperationsDomainEvent.ssl_letsencrypt_account_key_id = dbLetsEncryptAccountKey.id
    elif dbCACertificate:
        dbOperationsDomainEvent.ssl_ca_certificate_id = dbCACertificate.id
    elif dbDomain:
        dbOperationsDomainEvent.ssl_domain_id = dbDomain.id
    elif dbPrivateKey:
        dbOperationsDomainEvent.ssl_private_key_id = dbPrivateKey.id
    elif dbServerCertificate:
        dbOperationsDomainEvent.ssl_server_certificate_id = dbServerCertificate.id
    elif dbUniqueFQDNSet:
        dbOperationsDomainEvent.ssl_unique_fqdn_set_id = dbUniqueFQDNSet.id
    elif dbCertificateRequest:
        dbOperationsDomainEvent.ssl_certificate_request_id = dbCertificateRequest.id
    elif dbQueueRenewal:
        dbOperationsDomainEvent.ssl_queue_renewal_id = dbQueueRenewal.id
    elif dbQueueDomain:
        dbOperationsDomainEvent.ssl_queue_domain_id = dbQueueDomain.id

    ctx.dbSession.add(dbOperationsDomainEvent)
    ctx.dbSession.flush()

    return dbOperationsDomainEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__SslPrivateKey__autogenerated(ctx):
    """
    create wrapping private key generation
    2016.06.04 - dbOperationsEvent compliant
    """
    key_pem = cert_utils.new_private_key()
    dbPrivateKey, _is_created = getcreate__SslPrivateKey__by_pem_text(
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

    dbQueueRenewal = SslQueueRenewal()
    dbQueueRenewal.timestamp_entered = ctx.timestamp
    dbQueueRenewal.timestamp_processed = None
    dbQueueRenewal.ssl_server_certificate_id = serverCertificate.id
    dbQueueRenewal.ssl_unique_fqdn_set_id = serverCertificate.ssl_unique_fqdn_set_id
    dbQueueRenewal.ssl_operations_event_id__child_of = ctx.dbOperationsEvent.id
    ctx.dbSession.add(dbQueueRenewal)
    ctx.dbSession.flush()

    event_payload = ctx.dbOperationsEvent.event_payload_json
    event_payload['ssl_queue_renewal.id'] = dbQueueRenewal.id
    ctx.dbOperationsEvent.set_event_payload(event_payload)

    _log_object_event(ctx,
                      dbOperationsEvent=ctx.dbOperationsEvent,
                      event_status_id=SslOperationsObjectEventStatus.from_string('queue_renewal__insert'),
                      dbQueueRenewal=dbQueueRenewal,
                      )
    ctx.dbSession.flush()

    return dbQueueRenewal


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _certificate_parse_to_record(_tmpfileCert, dbCertificate):
    """
    helper utility
    """
    # grab the modulus
    cert_pem_modulus_md5 = cert_utils.modulus_md5_cert__pem_filepath(_tmpfileCert.name)
    dbCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

    dbCertificate.timestamp_signed = cert_utils.parse_startdate_cert__pem_filepath(_tmpfileCert.name)
    dbCertificate.timestamp_expires = cert_utils.parse_enddate_cert__pem_filepath(_tmpfileCert.name)
    dbCertificate.cert_subject = cert_utils.cert_single_op__pem_filepath(_tmpfileCert.name, '-subject')
    dbCertificate.cert_subject_hash = cert_utils.cert_single_op__pem_filepath(_tmpfileCert.name, '-subject_hash')
    dbCertificate.cert_issuer = cert_utils.cert_single_op__pem_filepath(_tmpfileCert.name, '-issuer')
    dbCertificate.cert_issuer_hash = cert_utils.cert_single_op__pem_filepath(_tmpfileCert.name, '-issuer_hash')

    return dbCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def ca_certificate_probe(ctx):
    """
    Probes the LetsEncrypt Certificate Authority for new certificates
    2016.06.04 - dbOperationsEvent compliant
    """

    # create a bookkeeping object
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                SslOperationsEventType.from_string('ca_certificate__probe'),
                                                )

    certs = letsencrypt_info.probe_letsencrypt_certificates()
    certs_discovered = []
    certs_modified = []
    for c in certs:
        _is_created = False
        dbCACertificate = get__SslCaCertificate__by_pem_text(ctx, c['cert_pem'])
        if not dbCACertificate:
            dbCACertificate, _is_created = getcreate__SslCaCertificate__by_pem_text(ctx, c['cert_pem'], c['name'])
            if _is_created:
                certs_discovered.append(dbCACertificate)
        if 'is_ca_certificate' in c:
            if dbCACertificate.is_ca_certificate != c['is_ca_certificate']:
                dbCACertificate.is_ca_certificate = c['is_ca_certificate']
                if dbCACertificate not in certs_discovered:
                    certs_modified.append(dbCACertificate)
        else:
            attrs = ('le_authority_name',
                     'is_authority_certificate',
                     'is_cross_signed_authority_certificate',
                     )
            for _k in attrs:
                if getattr(dbCACertificate, _k) is None:
                    setattr(dbCACertificate, _k, c[_k])
                    if dbCACertificate not in certs_discovered:
                        certs_modified.append(dbCACertificate)

    # bookkeeping update
    event_payload_dict['is_certificates_discovered'] = True if certs_discovered else False
    event_payload_dict['is_certificates_updated'] = True if certs_modified else False
    event_payload_dict['ids_discovered'] = [c.id for c in certs_discovered]
    event_payload_dict['ids_modified'] = [c.id for c in certs_modified]

    dbOperationsEvent.set_event_payload(event_payload_dict)
    return dbOperationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__SslLetsEncryptAccountKey_authenticate(ctx, dbLetsEncryptAccountKey, account_key_path=None):
    """
    Authenticates the AccountKey against the LetsEncrypt ACME servers
    2016.06.04 - dbOperationsEvent compliant
    """
    _tmpfile = None
    try:
        if account_key_path is None:
            _tmpfile = cert_utils.new_pem_tempfile(dbLetsEncryptAccountKey.key_pem)
            account_key_path = _tmpfile.name

        # parse account key to get public key
        header, thumbprint = acme.account_key__header_thumbprint(account_key_path=account_key_path, )

        acme.acme_register_account(header,
                                   account_key_path=account_key_path)

        # this would raise if we couldn't authenticate

        dbLetsEncryptAccountKey.timestamp_last_authenticated = ctx.timestamp
        ctx.dbSession.flush()

        # log this
        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict['ssl_letsencrypt_account_key.id'] = dbLetsEncryptAccountKey.id
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    SslOperationsEventType.from_string('letsencrypt_account_key__authenticate'),
                                                    event_payload_dict,
                                                    )
        return True

    finally:
        if _tmpfile:
            _tmpfile.close()


def do__CertificateRequest__AcmeAutomated(
    ctx,
    domain_names,

    dbAccountKey=None,
    account_key_pem=None,

    dbPrivateKey=None,
    private_key_pem=None,

    dbServerCertificate__renewal_of=None,
):
    """
    2016.06.04 - dbOperationsEvent compliant

    #for a single domain
    openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr

    #for multiple domains (use this one if you want both www.yoursite.com and yoursite.com)
    openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) > domain.csr

    # homebrew?
    /usr/local/opt/openssl/bin/openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /usr/local/etc/openssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com")) > domain_multi.csr</code>

    # scratch
    openssl req -new -sha256 -key /var/folders/4o/4oYQL09OGcSwJ2-Uj2T+dE+++TI/-Tmp-/tmp9mT8V6 -subj "/" -reqexts SAN -config < /var/folders/4o/4oYQL09OGcSwJ2-Uj2T+dE+++TI/-Tmp-/tmpK9tsl9 >STDOUT
    (cat /System/Library/OpenSSL/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com"))
    cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")
    cat  /usr/local/etc/openssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")
    cat /System/Library/OpenSSL/openssl.cnf printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com"
    /usr/local/opt/openssl/bin/openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <

    """
    if not any((dbAccountKey, account_key_pem)) or all((dbAccountKey, account_key_pem)):
        raise ValueError("Submit one and only one of: `dbAccountKey`, `account_key_pem`")

    if not any((dbPrivateKey, private_key_pem)) or all((dbPrivateKey, private_key_pem)):
        raise ValueError("Submit one and only one of: `dbPrivateKey`, `private_key_pem`")

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                SslOperationsEventType.from_string('certificate_request__do__automated'),
                                                )

    tmpfiles = []
    dbCertificateRequest = None
    dbServerCertificate = None
    try:

        # we should have cleaned this up before, but just be safe
        domain_names = [i.lower() for i in [d.strip() for d in domain_names] if i]
        domain_names = set(domain_names)
        if not domain_names:
            raise ValueError("no domain names!")
        # we need a list
        domain_names = list(domain_names)

        if dbAccountKey is None:
            account_key_pem = cert_utils.cleanup_pem_text(account_key_pem)
            dbAccountKey, _is_created = getcreate__SslLetsEncryptAccountKey__by_pem_text(ctx, account_key_pem)
        else:
            account_key_pem = dbAccountKey.key_pem
        # we need to use tmpfiles on the disk
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)

        if dbPrivateKey is None:
            private_key_pem = cert_utils.cleanup_pem_text(private_key_pem)
            dbPrivateKey, _is_created = getcreate__SslPrivateKey__by_pem_text(ctx, private_key_pem)
        else:
            private_key_pem = dbPrivateKey.key_pem
        # we need to use tmpfiles on the disk
        tmpfile_pkey = cert_utils.new_pem_tempfile(private_key_pem)
        tmpfiles.append(tmpfile_pkey)

        # make the CSR
        csr_pem = cert_utils.new_csr_for_domain_names(domain_names,
                                                      private_key_path=tmpfile_pkey.name,
                                                      tmpfiles_tracker=tmpfiles
                                                      )
        tmpfile_csr = cert_utils.new_pem_tempfile(csr_pem)
        tmpfiles.append(tmpfile_csr)

        # these MUST commit
        with transaction.manager as tx:
            dbCertificateRequest, dbDomainObjects = create__SslCertificateRequest(
                ctx,
                csr_pem,
                certificate_request_type_id = SslCertificateRequestType.ACME_AUTOMATED,
                dbAccountKey = dbAccountKey,
                dbPrivateKey = dbPrivateKey,
                dbServerCertificate__issued = None,
                dbServerCertificate__renewal_of = dbServerCertificate__renewal_of,
                domain_names = domain_names,
            )

        def process_keyauth_challenge(domain, token, keyauthorization):
            log.info("-process_keyauth_challenge %s", domain)
            with transaction.manager as tx:
                (dbDomain, dbCertificateRequest2D) = dbDomainObjects[domain]
                dbCertificateRequest2D.challenge_key = token
                dbCertificateRequest2D.challenge_text = keyauthorization
                ctx.dbSession.flush()

        def process_keyauth_cleanup(domain, token, keyauthorization):
            log.info("-process_keyauth_cleanup %s", domain)

        # ######################################################################
        # THIS BLOCK IS FROM acme-tiny

        # pull domains from csr
        csr_domains = cert_utils.parse_csr_domains(csr_path=tmpfile_csr.name,
                                                   submitted_domain_names=domain_names,
                                                   )
        if set(csr_domains) != set(domain_names):
            raise ValueError("Did not make a valid set")

        # parse account key to get public key
        header, thumbprint = acme.account_key__header_thumbprint(account_key_path=tmpfile_account.name, )

        # register the account / ensure that it is registered
        if not dbAccountKey.timestamp_last_authenticated:
            do__SslLetsEncryptAccountKey_authenticate(ctx,
                                                      dbAccountKey,
                                                      account_key_path=tmpfile_account.name,
                                                      )

        # verify each domain
        acme.acme_verify_domains(csr_domains=csr_domains,
                                 account_key_path=tmpfile_account.name,
                                 handle_keyauth_challenge=process_keyauth_challenge,
                                 handle_keyauth_cleanup=process_keyauth_cleanup,
                                 thumbprint=thumbprint,
                                 header=header,
                                 )

        # sign it
        (cert_pem,
         chained_pem,
         chain_url,
         datetime_signed,
         datetime_expires,
         ) = acme.acme_sign_certificate(csr_path=tmpfile_csr.name,
                                        account_key_path=tmpfile_account.name,
                                        header=header,
                                        )
        #
        # end acme-tiny
        # ######################################################################

        # these MUST commit
        with transaction.manager as tx:
            dbServerCertificate = create__SslServerCertificate(
                ctx,
                timestamp_signed = datetime_signed,
                timestamp_expires = datetime_expires,
                is_active = True,
                cert_pem = cert_pem,
                chained_pem = chained_pem,
                chain_name = chain_url,
                dbCertificateRequest = dbCertificateRequest,
                dbLetsEncryptAccountKey = dbAccountKey,
                dbPrivateKey = dbPrivateKey,
                dbDomains = [v[0] for v in dbDomainObjects.values()],
                dbServerCertificate__renewal_of = dbServerCertificate__renewal_of,
            )

        return dbServerCertificate

    except:
        if dbCertificateRequest:
            dbCertificateRequest.is_active = False
            dbCertificateRequest.is_error = True
            transaction.manager.commit()
        raise

    finally:

        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_expired(ctx):
    """
    deactivates expired certificates automatically
    2016.06.04 - dbOperationsEvent compliant
    """
    # create an event first
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict['count_deactivated'] = 0
    operationsEvent = log__SslOperationsEvent(ctx,
                                              SslOperationsEventType.from_string('certificate__deactivate_expired'),
                                              event_payload_dict,
                                              )

    # update the recents, this will automatically create a subevent
    subevent = operations_update_recents(ctx)

    # okay, go!

    # deactivate expired certificates
    expired_certs = ctx.dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.is_active is True,  # noqa
                SslServerCertificate.timestamp_expires < ctx.timestamp,
                )\
        .all()
    for c in expired_certs:
        c.is_active = False
        ctx.dbSession.flush()
        events.Certificate_expired(ctx, c)

    # update the event
    if len(expired_certs):
        event_payload_dict['count_deactivated'] = len(expired_certs)
        event_payload_dict['ssl_server_certificate.ids'] = [c.id for c in expired_certs]
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()
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
    """
    raise ValueError("Don't run this. It's not needed anymore")
    raise errors.OperationsContextError("Not Compliant")

    if ran_operations_update_recents is not True:
        raise ValueError("MUST run `operations_update_recents` first")

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict['count_deactivated'] = 0
    operationsEvent = log__SslOperationsEvent(ctx,
                                              SslOperationsEventType.from_string('deactivate_duplicate'),
                                              event_payload_dict,
                                              )

    _q_ids__latest_single = ctx.dbSession.query(SslDomain.ssl_server_certificate_id__latest_single)\
        .distinct()\
        .filter(SslDomain.ssl_server_certificate_id__latest_single != None,  # noqa
                )\
        .subquery()
    _q_ids__latest_multi = ctx.dbSession.query(SslDomain.ssl_server_certificate_id__latest_multi)\
        .distinct()\
        .filter(SslDomain.ssl_server_certificate_id__latest_single != None,  # noqa
                )\
        .subquery()

    # now grab the domains with many certs...
    q_inner = ctx.dbSession.query(SslUniqueFQDNSet2SslDomain.ssl_domain_id,
                              sqlalchemy.func.count(SslUniqueFQDNSet2SslDomain.ssl_domain_id).label('counted'),
                              )\
        .join(SslServerCertificate,
              SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id == SslServerCertificate.ssl_unique_fqdn_set_id
              )\
        .filter(SslServerCertificate.is_active == True,  # noqa
                )\
        .group_by(SslUniqueFQDNSet2SslDomain.ssl_domain_id)
    q_inner = q_inner.subquery()
    q_domains = ctx.dbSession.query(q_inner)\
        .filter(q_inner.c.counted >= 2)
    result = q_domains.all()
    domain_ids_with_multiple_active_certs = [i.ssl_domain_id for i in result]

    if False:
        _turned_off = []
        for _domain_id in domain_ids_with_multiple_active_certs:
            domain_certs = ctx.dbSession.query(SslServerCertificate)\
                .join(SslUniqueFQDNSet2SslDomain,
                      SslServerCertificate.ssl_unique_fqdn_set_id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
                      )\
                .filter(SslServerCertificate.is_active == True,  # noqa
                        SslUniqueFQDNSet2SslDomain.ssl_domain_id == _domain_id,
                        SslServerCertificate.id.notin_(_q_ids__latest_single),
                        SslServerCertificate.id.notin_(_q_ids__latest_multi),
                        )\
                .order_by(SslServerCertificate.timestamp_expires.desc())\
                .all()
            if len(domain_certs) > 1:
                for cert in domain_certs[1:]:
                    cert.is_active = False
                    _turned_off.append(cert)
                    events.Certificate_deactivated(ctx, c)

    # update the event
    if len(_turned_off):
        event_payload_dict['count_deactivated'] = len(_turned_off)
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()
    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_update_recents(ctx):
    """
    updates all the objects to their most-recent relations
    2016.06.04 - dbOperationsEvent compliant
    """
    # first the single
    # _t_domain = SslDomain.__table__.alias('domain')
    _q_sub = ctx.dbSession.query(SslServerCertificate.id)\
        .join(SslUniqueFQDNSet2SslDomain,
              SslServerCertificate.ssl_unique_fqdn_set_id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id
        )\
        .filter(SslServerCertificate.is_active == True,  # noqa
                SslServerCertificate.is_single_domain_cert == True,  # noqa
                SslUniqueFQDNSet2SslDomain.ssl_domain_id == SslDomain.id,
                )\
        .order_by(SslServerCertificate.timestamp_expires.desc())\
        .limit(1)\
        .subquery()\
        .as_scalar()
    ctx.dbSession.execute(SslDomain.__table__
                          .update()
                          .values(ssl_server_certificate_id__latest_single=_q_sub)
                          )

    # then the multiple
    # _t_domain = SslDomain.__table__.alias('domain')
    _q_sub = ctx.dbSession.query(SslServerCertificate.id)\
        .join(SslUniqueFQDNSet2SslDomain,
              SslServerCertificate.ssl_unique_fqdn_set_id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id
        )\
        .filter(SslServerCertificate.is_active == True,  # noqa
                SslServerCertificate.is_single_domain_cert == False,  # noqa
                SslUniqueFQDNSet2SslDomain.ssl_domain_id == SslDomain.id,
                )\
        .order_by(SslServerCertificate.timestamp_expires.desc())\
        .limit(1)\
        .subquery()\
        .as_scalar()
    ctx.dbSession.execute(SslDomain.__table__
                          .update()
                          .values(ssl_server_certificate_id__latest_multi=_q_sub)
                          )

    # update the count of active certs
    SslServerCertificate1 = sqlalchemy.orm.aliased(SslServerCertificate)
    SslServerCertificate2 = sqlalchemy.orm.aliased(SslServerCertificate)
    _q_sub = ctx.dbSession.query(sqlalchemy.func.count(SslDomain.id))\
        .outerjoin(SslServerCertificate1,
                   SslDomain.ssl_server_certificate_id__latest_single == SslServerCertificate1.id
                   )\
        .outerjoin(SslServerCertificate2,
                   SslDomain.ssl_server_certificate_id__latest_multi == SslServerCertificate2.id
                   )\
        .filter(sqlalchemy.or_(SslCaCertificate.id == SslServerCertificate1.ssl_ca_certificate_id__upchain,
                               SslCaCertificate.id == SslServerCertificate2.ssl_ca_certificate_id__upchain,
                               ),
                )\
        .subquery()\
        .as_scalar()
    ctx.dbSession.execute(SslCaCertificate.__table__
                          .update()
                          .values(count_active_certificates=_q_sub)
                          )

    # update the count of active PrivateKeys
    SslServerCertificate1 = sqlalchemy.orm.aliased(SslServerCertificate)
    SslServerCertificate2 = sqlalchemy.orm.aliased(SslServerCertificate)
    _q_sub = ctx.dbSession.query(sqlalchemy.func.count(SslDomain.id))\
        .outerjoin(SslServerCertificate1,
                   SslDomain.ssl_server_certificate_id__latest_single == SslServerCertificate1.id
                   )\
        .outerjoin(SslServerCertificate2,
                   SslDomain.ssl_server_certificate_id__latest_multi == SslServerCertificate2.id
                   )\
        .filter(sqlalchemy.or_(SslPrivateKey.id == SslServerCertificate1.ssl_private_key_id__signed_by,
                               SslPrivateKey.id == SslServerCertificate2.ssl_private_key_id__signed_by,
                               ),
                )\
        .subquery()\
        .as_scalar()
    ctx.dbSession.execute(SslPrivateKey.__table__
                          .update()
                          .values(count_active_certificates=_q_sub)
                          )

    # the following works, but this is currently tracked
    if False:
        # update the counts on Account Keys
        _q_sub_req = ctx.dbSession.query(sqlalchemy.func.count(SslCertificateRequest.id))\
            .filter(SslCertificateRequest.ssl_letsencrypt_account_key_id == SslLetsEncryptAccountKey.id,
                    )\
            .subquery()\
            .as_scalar()
        ctx.dbSession.execute(SslLetsEncryptAccountKey.__table__
                              .update()
                              .values(count_certificate_requests=_q_sub_req,
                                      # count_certificates_issued=_q_sub_iss,
                                      )
                              )
        # update the counts on Private Keys
        _q_sub_req = ctx.dbSession.query(sqlalchemy.func.count(SslCertificateRequest.id))\
            .filter(SslCertificateRequest.ssl_private_key_id__signed_by == SslPrivateKey.id,
                    )\
            .subquery()\
            .as_scalar()
        _q_sub_iss = ctx.dbSession.query(sqlalchemy.func.count(SslServerCertificate.id))\
            .filter(SslServerCertificate.ssl_private_key_id__signed_by == SslPrivateKey.id,
                    )\
            .subquery()\
            .as_scalar()

        ctx.dbSession.execute(SslPrivateKey.__table__
                              .update()
                              .values(count_certificate_requests=_q_sub_req,
                                      count_certificates_issued=_q_sub_iss,
                                      )
                              )

    # should we do the timestamps?
    """
    UPDATE ssl_letsencrypt_account_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM ssl_certificate_request
    WHERE ssl_certificate_request.ssl_letsencrypt_account_key_id = ssl_letsencrypt_account_key.id);

    UPDATE ssl_letsencrypt_account_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM ssl_server_certificate
    WHERE ssl_server_certificate.ssl_letsencrypt_account_key_id = ssl_letsencrypt_account_key.id);

    UPDATE ssl_private_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM ssl_certificate_request
    WHERE ssl_certificate_request.ssl_private_key_id__signed_by = ssl_private_key.id);

    UPDATE ssl_private_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM ssl_server_certificate
    WHERE ssl_server_certificate.ssl_private_key_id__signed_by = ssl_private_key.id);
    """

    # mark the session changed, but we need to mark the session not scoped session.  ugh.
    # update: we don't need this if we add the bookkeeping object, but let's just keep this to be safe
    mark_changed(ctx.dbSession)

    # bookkeeping
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                SslOperationsEventType.from_string('operations__update_recents'),
                                                )
    return dbOperationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__enable(ctx, domain_names):
    """this is just a proxy around queue_domains__add"""
    results = queue_domains__add(ctx, domain_names,
                                 alternate_event_type_id=SslOperationsEventType.from_string('api_domains__enable'),
                                 )
    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__disable(ctx, domain_names):
    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    for domain_name in domain_names:
        _exists = get__SslDomain__by_name(ctx, domain_name, preload=False)
        if _exists:
            results[domain_name] = 'deactivated'
        elif not _exists:
            _exists_queue = get__SslQueueDomain__by_name(ctx, domain_name)
            if _exists_queue:
                results[domain_name] = 'de-queued'
            else:
                results[domain_name] = 'no active or in queue'

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_domains__add(ctx, domain_names, alternate_event_type_id=None):
    """
    Adds domains to the queue if needed
    2016.06.04 - dbOperationsEvent compliant
    
    `alternate_event_type_id` can be specified if this should be logged differently
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                alternate_event_type_id or SslOperationsEventType.from_string('queue_domain__add'),
                                                event_payload_dict,
                                                )

    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for domain_name in domain_names:
        _exists = get__SslDomain__by_name(ctx, domain_name, preload=False)
        if _exists:
            # log request
            _log_object_event(ctx,
                              dbOperationsEvent=dbOperationsEvent,
                              event_status_id=SslOperationsObjectEventStatus.from_string('queue_domain__add__already_exists'),
                              dbDomain=_exists,
                              )
            # note result
            results[domain_name] = 'exists'

        elif not _exists:
            _existing_queue = get__SslQueueDomain__by_name(ctx, domain_name)
            if _existing_queue:
                # log request
                _log_object_event(ctx,
                                  dbOperationsEvent=dbOperationsEvent,
                                  event_status_id=SslOperationsObjectEventStatus.from_string('queue_domain__add__already_queued'),
                                  dbQueueDomain=_existing_queue,
                                  )
                # note result
                results[domain_name] = 'already_queued'

            elif not _existing_queue:
                dbQueueDomain = SslQueueDomain()
                dbQueueDomain.domain_name = domain_name
                dbQueueDomain.timestamp_entered = _timestamp
                dbQueueDomain.ssl_operations_event_id__created = dbOperationsEvent.id
                ctx.dbSession.add(dbQueueDomain)
                ctx.dbSession.flush()

                # log request
                _log_object_event(ctx,
                                  dbOperationsEvent=dbOperationsEvent,
                                  event_status_id=SslOperationsObjectEventStatus.from_string('queue_domain__add__success'),
                                  dbQueueDomain=dbQueueDomain,
                                  )

                # note result
                results[domain_name] = 'queued'
    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_domains__process(
    ctx,
    dbAccountKey=None,
    dbPrivateKey=None,
):
    raise errors.OperationsContextError("Not Compliant")

    try:
        items_paged = get__SslQueueDomain__paginated(
            ctx,
            show_processed=False,
            limit=100,
            offset=0
        )
        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict['batch_size'] = len(items_paged)
        event_payload_dict['status'] = 'attempt'
        event_payload_dict['queue_domain_ids'] = ','.join([str(d.id) for d in items_paged])
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    SslOperationsEventType.from_string('queue_domain__process'),
                                                    event_payload_dict,
                                                    )

        _timestamp = ctx.timestamp
        for qDomain in items_paged:
            _log_object_event(ctx,
                              dbOperationsEvent=dbOperationsEvent,
                              event_status_id=SslOperationsEventType.from_string('queue_domain__process'),
                              dbQueueDomain=qDomain,
                              )

        # commit this so we have the attempt recorded.
        transaction.commit()

        # exit out
        if not items_paged:
            raise errors.DisplayableError("No items in queue")

        # cache the timestamp
        timestamp_transaction = datetime.datetime.now()

        # generate domains
        domainObjects = []
        for qDomain in items_paged:
            domainObject, _is_created = getcreate__SslDomain__by_domainName(
                ctx,
                qDomain.domain_name,
                is_from_queue_domain=True,
            )
            domainObjects.append(domainObject)
            qDomain.ssl_domain_id = domainObject.id
            ctx.dbSession.flush()

        # create a dbUniqueFqdnSet for this.
        # TODO - should we delete this if we fail? or keep for the CSR record
        #      - rationale is that on another pass, we would have a different fqdn set
        dbUniqueFqdnSet, is_created = getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, domainObjects)

        # update the event
        event_payload_dict['ssl_unique_fqdn_set_id'] = dbUniqueFqdnSet.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()
        transaction.commit()

        if dbAccountKey is None:
            dbAccountKey = get__SslLetsEncryptAccountKey__default(dbSession)
            if not dbAccountKey:
                raise ValueError("Could not grab an AccountKey")

        if dbPrivateKey is None:
            dbPrivateKey = get__SslPrivateKey__current_week(dbSession)
            if not dbPrivateKey:
                dbPrivateKey = create__SslPrivateKey__autogenerated(ctx)
            if not dbPrivateKey:
                raise ValueError("Could not grab a PrivateKey")

        # do commit, just because we may have created a private key
        transaction.commit()

        dbServerCertificate = None
        try:
            domain_names = [d.domain_name for d in domainObjects]
            dbServerCertificate = do__CertificateRequest__AcmeAutomated(
                ctx,
                domain_names,
                dbAccountKey=dbAccountKey,
                dbPrivateKey=dbPrivateKey,
            )
            for qdomain in items_paged:
                # this may have committed
                qdomain.timestamp_processed = timestamp_transaction
            ctx.dbSession.flush()

            event_payload_dict['status'] = 'success'
            event_payload_dict['certificate.id'] = dbServerCertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush()

        except errors.DomainVerificationError, e:
            event_payload_dict['status'] = 'error - DomainVerificationError'
            event_payload_dict['error'] = e.message
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush()

            _timestamp = ctx.timestamp
            for qd in items_paged:
                _log_object_event(ctx,
                                  dbOperationsEvent=dbOperationsEvent,
                                  event_status_id=SslOperationsEventType.from_string('queue_domain__process__fail'),
                                  dbQueueDomain=qd,
                                  )
            raise

        _timestamp = ctx.timestamp
        for qd in items_paged:
            _log_object_event(ctx,
                              dbOperationsEvent=dbOperationsEvent,
                              event_status_id=SslOperationsEventType.from_string('queue_domain__process__success'),
                              dbQueueDomain=qd,
                              )

        return True

    except:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_renewals__process(
    ctx,
    fqdns_ids_only = None,
):
    try:
        event_type = SslOperationsEventType.from_string('queue_renewals__process')
        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict['status'] = 'attempt'
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    event_type,
                                                    event_payload_dict,
                                                    )

        _expiring_days = 28
        _until = ctx.timestamp + datetime.timedelta(days=_expiring_days)
        _core_query = ctx.dbSession.query(SslServerCertificate)\
            .filter(SslServerCertificate.is_active.op('IS')(True),
                    SslServerCertificate.timestamp_expires <= _until
                    )
        if fqdns_ids_only:
            _core_query = _core_query\
                .filter(SslServerCertificate.ssl_unique_fqdn_set_id.in_(fqdns_ids_only),
                        )
        _core_query = _core_query\
            .join(SslQueueRenewal,
                  SslServerCertificate.ssl_unique_fqdn_set_id == SslQueueRenewal.ssl_unique_fqdn_set_id,
                  )\
            .filter(SslQueueRenewal.timestamp_processed.op('IS')(None),
                    )
        results = _core_query.all()
        for cert in results:
            renewal = _create__SslQueueRenewal(
                ctx,
                cert,
            )
        event_payload_dict['queued_certificate_ids'] = ','.join([str(c.id) for c in results])
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush()

        raise ValueError("what to log?")
        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          event_status_id=SslOperationsObjectEventStatus.from_string('queue_renewal__process'),
                          dbQueueRewnwal=dbQueue,
                          )
        ctx.dbSession.flush()

        return True

    except:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def upload__SslCaCertificateBundle__by_pem_text(ctx, bundle_data):
    """
    Uploads a bundle of CaCertificates
    2016.06.04 - dbOperationsEvent compliant
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                SslOperationsEventType.from_string('ca_certificate__upload_bundle'),
                                                event_payload_dict
                                                )
    results = {}
    for cert_pem in bundle_data.keys():
        if cert_pem[-4:] != '_pem':
            raise ValueError("key does not end in `_pem`")
        cert_base = cert_pem[:-4]
        cert_pem_text = bundle_data[cert_pem]
        cert_name = None
        le_authority_name = None
        is_authority_certificate = None
        is_cross_signed_authority_certificate = None
        for c in letsencrypt_info.CA_CERTS_DATA:
            if cert_base == c['formfield_base']:
                cert_name = c['name']
                if 'le_authority_name' in c:
                    le_authority_name = c['le_authority_name']
                if 'is_authority_certificate' in c:
                    is_authority_certificate = c['is_authority_certificate']
                if 'is_cross_signed_authority_certificate' in c:
                    is_cross_signed_authority_certificate = c['is_cross_signed_authority_certificate']
                break

        dbCACertificate, is_created = getcreate__SslCaCertificate__by_pem_text(
            ctx,
            cert_pem_text,
            cert_name,
            le_authority_name = None,
            is_authority_certificate = None,
            is_cross_signed_authority_certificate = None,
        )
        if not is_created:
            if dbCACertificate.name in ('unknown', 'manual upload') and cert_name:
                dbCACertificate.name = cert_name
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.le_authority_name = le_authority_name
            if dbCACertificate.is_authority_certificate is None:
                dbCACertificate.is_authority_certificate = is_authority_certificate
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.is_cross_signed_authority_certificate = is_cross_signed_authority_certificate

        results[cert_pem] = (dbCACertificate, is_created)

    ids_created = [i[0].id for i in results.values() if i[1]]
    ids_updated = [i[0].id for i in results.values() if not i[1]]
    event_payload_dict['ids_created'] = ids_created
    event_payload_dict['ids_updated'] = ids_updated
    dbOperationsEvent.set_event_payload(event_payload_dict)
    return results
