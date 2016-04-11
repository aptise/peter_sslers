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


def getcreate__SslLetsEncryptAccountKey__by_pem_text(dbSession, key_pem):
    key_pem = cert_utils.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    is_created = False
    dbKey = dbSession.query(SslLetsEncryptAccountKey)\
        .filter(SslLetsEncryptAccountKey.key_pem_md5 == key_pem_md5,
                SslLetsEncryptAccountKey.key_pem == key_pem,
                )\
        .first()
    if not dbKey:
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
        dbKey = SslLetsEncryptAccountKey()
        dbKey.timestamp_first_seen = datetime.datetime.utcnow()
        dbKey.key_pem = key_pem
        dbKey.key_pem_md5 = key_pem_md5
        dbKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbSession.add(dbKey)
        dbSession.flush()
        is_created = True
    return dbKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslCaCertificate__by_pem_text(
    dbSession,
    cert_pem,
    chain_name,
    le_authority_name = None,
    is_authority_certificate = None,
    is_cross_signed_authority_certificate = None,
):
    dbCACertificate = get__SslCaCertificate__by_pem_text(dbSession, cert_pem)
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

            dbCACertificate = SslCaCertificate()
            dbCACertificate.name = chain_name or 'unknown'

            dbCACertificate.le_authority_name = le_authority_name
            dbCACertificate.is_ca_certificate = True
            dbCACertificate.is_authority_certificate = is_authority_certificate
            dbCACertificate.is_cross_signed_authority_certificate = is_cross_signed_authority_certificate
            dbCACertificate.id_cross_signed_of = None
            dbCACertificate.timestamp_first_seen = datetime.datetime.utcnow()
            dbCACertificate.cert_pem = cert_pem
            dbCACertificate.cert_pem_md5 = cert_pem_md5
            dbCACertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

            dbCACertificate.timestamp_signed = cert_utils.parse_startdate_cert__pem_filepath(_tmpfile.name)
            dbCACertificate.timestamp_expires = cert_utils.parse_enddate_cert__pem_filepath(_tmpfile.name)
            dbCACertificate.cert_subject = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-subject')
            dbCACertificate.cert_subject_hash = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-subject_hash')
            dbCACertificate.cert_issuer = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-issuer')
            dbCACertificate.cert_issuer_hash = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-issuer_hash')

            dbSession.add(dbCACertificate)
            dbSession.flush()
            is_created = True
        except:
            raise
        finally:
            _tmpfile.close()

    return dbCACertificate, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslCertificateRequest__by_pem_text(
    dbSession,
    csr_pem,
    certificate_request_type_id = None,
    dbAccountKey = None,
    dbPrivateKey = None,
    dbSslCertificate_issued = None,
    dbSslCertificate__renewal_of = None,
):
    dbSslCertificateRequest = get__SslCertificateRequest__by_pem_text(dbSession, csr_pem)
    is_created = False
    if not dbSslCertificateRequest:
        dbSslCertificateRequest = create__SslCertificateRequest(
            dbSession,
            csr_pem,
            certificate_request_type_id = certificate_request_type_id,
            dbAccountKey = dbAccountKey,
            dbPrivateKey = dbPrivateKey,
            dbSslCertificate_issued = dbSslCertificate_issued,
            dbSslCertificate__renewal_of = dbSslCertificate__renewal_of,
        )
        is_created = True

    return dbSslCertificateRequest, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def getcreate__SslDomain__by_domainName(
    dbSession,
    domain_name,
    is_from_domain_queue=None,
):
    is_created = False
    dbDomain = get__SslDomain__by_name(dbSession, domain_name, preload=False)
    if not dbDomain:
        dbDomain = SslDomain()
        dbDomain.domain_name = domain_name
        dbDomain.timestamp_first_seen = datetime.datetime.utcnow()
        dbDomain.is_from_domain_queue = is_from_domain_queue
        dbSession.add(dbDomain)
        dbSession.flush()
        is_created = True
    return dbDomain, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslPrivateKey__by_pem_text(dbSession, key_pem, is_autogenerated_key=None):
    key_pem = cert_utils.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    is_created = False
    dbKey = dbSession.query(SslPrivateKey)\
        .filter(SslPrivateKey.key_pem_md5 == key_pem_md5,
                SslPrivateKey.key_pem == key_pem,
                )\
        .first()
    if not dbKey:
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

        dbKey = SslPrivateKey()
        dbKey.timestamp_first_seen = datetime.datetime.utcnow()
        dbKey.key_pem = key_pem
        dbKey.key_pem_md5 = key_pem_md5
        dbKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbKey.is_autogenerated_key = is_autogenerated_key
        dbSession.add(dbKey)
        dbSession.flush()
        is_created = True
    return dbKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslServerCertificate__by_pem_text(
    dbSession,
    cert_pem,
    dbCACertificate=None,
    dbAccountKey=None,
    dbPrivateKey=None,
    ssl_server_certificate_id__renewal_of=None,
):
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    is_created = False
    dbCertificate = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.cert_pem_md5 == cert_pem_md5,
                SslServerCertificate.cert_pem == cert_pem,
                )\
        .first()
    if dbCertificate:
        if dbPrivateKey and (dbCertificate.ssl_private_key_id__signed_by != dbPrivateKey.id):
            if dbCertificate.ssl_private_key_id__signed_by:
                raise ValueError("Integrity Error. Competing PrivateKey (!?)")
            elif dbCertificate.ssl_private_key_id__signed_by is None:
                dbCertificate.ssl_private_key_id__signed_by = dbPrivateKey.id
                dbPrivateKey.count_certificates_issued += 1
                if not dbPrivateKey.timestamp_last_certificate_issue or (dbPrivateKey.timestamp_last_certificate_issue < dbCertificate.timestamp_signed):
                    dbPrivateKey.timestamp_last_certificate_issue = dbCertificate.timestamp_signed
                dbSession.flush()
        if dbAccountKey and (dbCertificate.ssl_letsencrypt_account_key_id != dbAccountKey.id):
            if dbCertificate.ssl_letsencrypt_account_key_id:
                raise ValueError("Integrity Error. Competing AccountKey (!?)")
            elif dbCertificate.ssl_letsencrypt_account_key_id is None:
                dbCertificate.ssl_letsencrypt_account_key_id = dbAccountKey.id
                dbAccountKey.count_certificates_issued += 1
                if not dbAccountKey.timestamp_last_certificate_issue or (dbAccountKey.timestamp_last_certificate_issue < dbCertificate.timestamp_signed):
                    dbAccountKey.timestamp_last_certificate_issue = dbAccountKey.timestamp_signed
                dbSession.flush()
    elif not dbCertificate:
        _tmpfileCert = None
        try:
            _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

            # validate
            cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

            dbCertificate = SslServerCertificate()
            _certificate_parse_to_record(_tmpfileCert, dbCertificate)

            dbCertificate.is_active = True
            dbCertificate.cert_pem = cert_pem
            dbCertificate.cert_pem_md5 = cert_pem_md5

            dbCertificate.ssl_server_certificate_id__renewal_of = ssl_server_certificate_id__renewal_of

            # this is the LetsEncrypt key
            if dbCACertificate is None:
                raise ValueError('dbCACertificate is None')
            # we should make sure it issued the certificate:
            if dbCertificate.cert_issuer_hash != dbCACertificate.cert_subject_hash:
                raise ValueError('dbCACertificate did not sign the certificate')
            dbCertificate.ssl_ca_certificate_id__upchain = dbCACertificate.id

            # this is the private key
            # we should make sure it signed the certificate
            # the md5 check isn't exact, BUT ITS CLOSE
            if dbPrivateKey is None:
                raise ValueError('dbPrivateKey is None')
            if dbCertificate.cert_pem_modulus_md5 != dbPrivateKey.key_pem_modulus_md5:
                raise ValueError('dbPrivateKey did not sign the certificate')
            dbCertificate.ssl_private_key_id__signed_by = dbPrivateKey.id
            dbPrivateKey.count_certificates_issued += 1
            if not dbPrivateKey.timestamp_last_certificate_issue or (dbPrivateKey.timestamp_last_certificate_issue < dbCertificate.timestamp_signed):
                dbPrivateKey.timestamp_last_certificate_issue = dbCertificate.timestamp_signed

            # did we submit an account key?
            if dbAccountKey:
                dbCertificate.ssl_letsencrypt_account_key_id = dbAccountKey.id
                dbAccountKey.count_certificates_issued += 1
                if not dbAccountKey.timestamp_last_certificate_issue or (dbAccountKey.timestamp_last_certificate_issue < dbAccountKey.timestamp_signed):
                    dbAccountKey.timestamp_last_certificate_issue = dbCertificate.timestamp_signed

            _subject_domain, _san_domains = cert_utils.parse_cert_domains__segmented(cert_path=_tmpfileCert.name)
            certificate_domain_names = _san_domains
            if _subject_domain is not None and _subject_domain not in certificate_domain_names:
                certificate_domain_names.insert(0, _subject_domain)
            if not certificate_domain_names:
                raise ValueError("could not find any domain names in the certificate")
            # getcreate__SslDomain__by_domainName returns a tuple of (domainObject, is_created)
            dbDomainObjects = [getcreate__SslDomain__by_domainName(dbSession, _domain_name)[0]
                               for _domain_name in certificate_domain_names]
            dbFqdnSet, is_created_fqdn = getcreate__SslUniqueFQDNSet__by_domainObjects(dbSession, dbDomainObjects)
            dbCertificate.ssl_unique_fqdn_set_id = dbFqdnSet.id

            if len(certificate_domain_names) == 1:
                dbCertificate.is_single_domain_cert = True
            elif len(certificate_domain_names) > 1:
                dbCertificate.is_single_domain_cert = False

            dbSession.add(dbCertificate)
            dbSession.flush()
            is_created = True

        except:
            raise
        finally:
            if _tmpfileCert:
                _tmpfileCert.close()

    return dbCertificate, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslUniqueFQDNSet__by_domainObjects(
    dbSession,
    domainObjects,
):
    is_created = False

    domain_ids = [dbDomain.id for dbDomain in domainObjects]
    domain_ids.sort()
    domain_ids_string = ','.join([str(id) for id in domain_ids])

    dbFQDNSet = dbSession.query(SslUniqueFQDNSet)\
        .filter(SslUniqueFQDNSet.domain_ids_string == domain_ids_string,
                )\
        .first()

    if not dbFQDNSet:
        dbFQDNSet = SslUniqueFQDNSet()
        dbFQDNSet.domain_ids_string = domain_ids_string
        dbFQDNSet.timestamp_first_seen = datetime.datetime.utcnow()
        dbSession.add(dbFQDNSet)
        dbSession.flush()

        for dbDomain in domainObjects:
            dbAssoc = SslUniqueFQDNSet2SslDomain()
            dbAssoc.ssl_unique_fqdn_set_id = dbFQDNSet.id
            dbAssoc.ssl_domain_id = dbDomain.id
            dbSession.add(dbAssoc)
            dbSession.flush()
        is_created = True

    return dbFQDNSet, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def create__SslCertificateRequest(
    dbSession,
    csr_pem = None,
    certificate_request_type_id = None,
    dbAccountKey = None,
    dbPrivateKey = None,
    dbSslCertificate_issued = None,
    dbSslCertificate__renewal_of = None,
    domain_names = None,
):
    if certificate_request_type_id not in (
        SslCertificateRequestType.ACME_FLOW,
        SslCertificateRequestType.ACME_AUTOMATED,
    ):
        raise ValueError("Invalid `certificate_request_type_id`")

    # if there is a csr_pem; extract the domains
    csr_domain_names = None
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
        dbDomainObjects = [getcreate__SslDomain__by_domainName(dbSession, _domain_name)[0]
                           for _domain_name in domain_names]
        dbFqdnSet, is_created_fqdn = getcreate__SslUniqueFQDNSet__by_domainObjects(dbSession, dbDomainObjects)

        dbSslCertificateRequest = SslCertificateRequest()
        dbSslCertificateRequest.is_active = True
        dbSslCertificateRequest.csr_pem = csr_pem
        dbSslCertificateRequest.certificate_request_type_id = SslCertificateRequestType.ACME_FLOW
        dbSslCertificateRequest.timestamp_started = datetime.datetime.utcnow()
        dbSslCertificateRequest.ssl_unique_fqdn_set_id = dbFqdnSet.id
        dbSession.add(dbSslCertificateRequest)
        dbSession.flush()

        for dbDomain in dbDomainObjects:
            dbSslCertificateRequest2D = SslCertificateRequest2SslDomain()
            dbSslCertificateRequest2D.ssl_certificate_request_id = dbSslCertificateRequest.id
            dbSslCertificateRequest2D.ssl_domain_id = dbDomain.id
            dbSession.add(dbSslCertificateRequest2D)
            dbSession.flush()

        return dbSslCertificateRequest

    if dbPrivateKey is None:
        raise ValueError("Must submit `dbPrivateKey` for creation")

    # PARSE FROM THE CSR
    # timestamp_started
    # domains / ssl_unique_fqdn_set_id
    # domain_names = list(domain_names)

    _tmpfile = None
    dbSslCertificateRequest = None
    dbDomainObjects = None
    try:
        t_now = datetime.datetime.utcnow()

        csr_pem = cert_utils.cleanup_pem_text(csr_pem)
        csr_pem_md5 = utils.md5_text(csr_pem)

        # store the csr_text in a tmpfile
        _tmpfile = cert_utils.new_pem_tempfile(csr_pem)

        # validate
        cert_utils.validate_csr__pem_filepath(_tmpfile.name)

        # grab the modulus
        csr_pem_modulus_md5 = cert_utils.modulus_md5_csr__pem_filepath(tmpfile_csr.name)

        # we'll use this tuple in a bit...
        # getcreate__SslDomain__by_domainName returns a tuple of (domainObject, is_created)
        dbDomainObjects = {_domain_name: getcreate__SslDomain__by_domainName(dbSession, _domain_name)[0]
                           for _domain_name in domain_names
                           }
        dbFqdnSet, is_created_fqdn = getcreate__SslUniqueFQDNSet__by_domainObjects(dbSession, dbDomainObjects.values())

        # build the cert
        dbSslCertificateRequest = SslCertificateRequest()
        dbSslCertificateRequest.is_active = True
        dbSslCertificateRequest.certificate_request_type_id = certificate_request_type_id
        dbSslCertificateRequest.timestamp_started = t_now
        dbSslCertificateRequest.csr_pem = csr_text
        dbSslCertificateRequest.csr_pem_md5 = utils.md5_text(csr_text)
        dbSslCertificateRequest.csr_pem_modulus_md5 = csr_pem_modulus_md5
        dbSslCertificateRequest.ssl_unique_fqdn_set_id = dbFqdnSet.id

        # note account/private keys
        if dbAccountKey:
            dbSslCertificateRequest.ssl_letsencrypt_account_key_id = dbAccountKey.id
        dbSslCertificateRequest.ssl_private_key_id__signed_by = dbPrivateKey.id
        dbSslCertificateRequest.ssl_server_certificate_id__renewal_of = ssl_server_certificate_id__renewal_of

        dbSession.add(dbSslCertificateRequest)
        dbSession.flush()

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

        dbSession.flush()

        # we'll use this tuple in a bit...
        for _domain_name in dbDomainObjects.keys():
            dbDomain = dbDomainObjects[_domain_name]

            dbSslCertificateRequest2SslDomain = SslCertificateRequest2SslDomain()
            dbSslCertificateRequest2SslDomain.ssl_certificate_request_id = dbSslCertificateRequest.id
            dbSslCertificateRequest2SslDomain.ssl_domain_id = dbDomain.id

            dbSession.add(dbSslCertificateRequest2SslDomain)
            dbSession.flush()

            # update the hash to be a tuple
            dbDomainObjects[_domain_name] = (dbDomain, dbSslCertificateRequest2SslDomain)

        dbSession.flush()

    finally:
        if _tmpfile:
            _tmpfile.close()

    return dbSslCertificateRequest, dbDomainObjects


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def create__SslServerCertificate(
    dbSession,
    timestamp_signed = None,
    timestamp_expires = None,
    is_active = None,
    cert_pem = None,
    chained_pem = None,
    chain_name = None,
    dbSslCertificateRequest = None,
    dbSslLetsEncryptAccountKey = None,
    dbSslDomains = None,
    ssl_server_certificate_id__renewal_of = None,

    # only one of these 2
    dbSslPrivateKey = None,
    privkey_pem = None,
):
    if not any((dbSslPrivateKey, privkey_pem)) or all((dbSslPrivateKey, privkey_pem)):
        raise ValueError("create__SslServerCertificate must accept ONE OF [`dbSslPrivateKey`, `privkey_pem`]")
    if privkey_pem:
        raise ValueError("need to figure this out; might not need it")

    # we need to figure this out; it's the chained_pem
    # ssl_ca_certificate_id__upchain
    dbCACertificate, _is_created_cert = getcreate__SslCaCertificate__by_pem_text(dbSession, chained_pem, chain_name)
    ssl_ca_certificate_id__upchain = dbCACertificate.id

    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    try:
        _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

        # validate
        cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

        # pull the domains, so we can get the fqdn
        dbFqdnSet, is_created_fqdn = getcreate__SslUniqueFQDNSet__by_domainObjects(dbSession, dbSslDomains)

        dbSslServerCertificate = SslServerCertificate()
        _certificate_parse_to_record(_tmpfileCert, dbSslServerCertificate)

        # we don't need these anymore, because we're parsing the cert
        # dbSslServerCertificate.timestamp_signed = timestamp_signed
        # dbSslServerCertificate.timestamp_expires = timestamp_signed

        dbSslServerCertificate.is_active = is_active
        dbSslServerCertificate.cert_pem = cert_pem
        dbSslServerCertificate.cert_pem_md5 = utils.md5_text(cert_pem)
        if dbSslCertificateRequest:
            dbSslCertificateRequest.is_active = False
            dbSslServerCertificate.ssl_certificate_request_id = dbSslCertificateRequest.id
        dbSslServerCertificate.ssl_ca_certificate_id__upchain = ssl_ca_certificate_id__upchain
        dbSslServerCertificate.ssl_server_certificate_id__renewal_of = ssl_server_certificate_id__renewal_of

        # note account/private keys
        dbSslServerCertificate.ssl_letsencrypt_account_key_id = dbSslLetsEncryptAccountKey.id
        dbSslServerCertificate.ssl_private_key_id__signed_by = dbSslPrivateKey.id

        # note the fqdn
        dbSslServerCertificate.ssl_unique_fqdn_set_id = dbFqdnSet.id

        dbSession.add(dbSslServerCertificate)
        dbSession.flush()

        # increment account/private key counts
        dbSslLetsEncryptAccountKey.count_certificates_issued += 1
        dbSslPrivateKey.count_certificates_issued += 1
        if not dbSslLetsEncryptAccountKey.timestamp_last_certificate_issue or (dbSslLetsEncryptAccountKey.timestamp_last_certificate_issue < timestamp_signed):
            dbSslLetsEncryptAccountKey.timestamp_last_certificate_issue = timestamp_signed
        if not dbSslPrivateKey.timestamp_last_certificate_issue or (dbSslPrivateKey.timestamp_last_certificate_issue < timestamp_signed):
            dbSslPrivateKey.timestamp_last_certificate_issue = timestamp_signed

        dbSession.flush()

    except:
        raise
    finally:
        _tmpfileCert.close()

    return dbSslServerCertificate


def create__SslOperationsEvent(
    dbSession,
    event_type_id,
    event_payload_dict,
    ssl_operations_event_id__child_of=None,
):
    # bookkeeping
    dbEvent = SslOperationsEvent()
    dbEvent.ssl_operations_event_type_id = event_type_id
    dbEvent.timestamp_operation = datetime.datetime.utcnow()
    dbEvent.set_event_payload(event_payload_dict)
    dbEvent.ssl_operations_event_id__child_of = ssl_operations_event_id__child_of
    dbSession.add(dbEvent)
    dbSession.flush()
    return dbEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__SslPrivateKey__new(dbSession, is_autogenerated_key=None):
    key_pem = cert_utils.new_private_key()
    dbPrivateKey, _is_created = getcreate__SslPrivateKey__by_pem_text(
        dbSession,
        key_pem,
        is_autogenerated_key=is_autogenerated_key
    )
    return dbPrivateKey


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__SslQueueRenewal(dbSession, serverCertificate, ssl_operations_event_id__child_of=None):
    # bookkeeping
    dbQueue = SslQueueRenewal()
    dbQueue.timestamp_entered = datetime.datetime.utcnow()
    dbQueue.timestamp_processed = None
    dbQueue.ssl_server_certificate_id = serverCertificate.id
    dbQueue.ssl_unique_fqdn_set_id = serverCertificate.ssl_unique_fqdn_set_id
    dbQueue.ssl_operations_event_id__child_of = ssl_operations_event_id__child_of
    dbSession.add(dbQueue)
    dbSession.flush()
    return dbQueue


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _certificate_parse_to_record(_tmpfileCert, dbCertificate):

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


def ca_certificate_probe(dbSession):
    certs = letsencrypt_info.probe_letsencrypt_certificates()
    certs_discovered = []
    certs_modified = []
    for c in certs:
        _is_created = False
        dbCACertificate = get__SslCaCertificate__by_pem_text(dbSession, c['cert_pem'])
        if not dbCACertificate:
            dbCACertificate, _is_created = getcreate__SslCaCertificate__by_pem_text(dbSession, c['cert_pem'], c['name'])
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
    # bookkeeping
    dbEvent = create__SslOperationsEvent(dbSession,
                                         SslOperationsEventType.ca_certificate_probe,
                                         {'is_certificates_discovered': True if certs_discovered else False,
                                          'is_certificates_updated': True if certs_modified else False,
                                          'v': 1,
                                          }
                                         )

    return dbEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__SslLetsEncryptAccountKey_authenticate(dbSession, dbSslLetsEncryptAccountKey, account_key_path=None):
    _tmpfile = None
    try:
        if account_key_path is None:
            _tmpfile = cert_utils.new_pem_tempfile(dbSslLetsEncryptAccountKey.key_pem)
            account_key_path = _tmpfile.name

        # parse account key to get public key
        header, thumbprint = acme.account_key__header_thumbprint(account_key_path=account_key_path, )

        acme.acme_register_account(header,
                                   account_key_path=account_key_path)

        # this would raise if we couldn't authenticate

        dbSslLetsEncryptAccountKey.timestamp_last_authenticated = datetime.datetime.utcnow()
        dbSession.flush()

        return True

    finally:
        if _tmpfile:
            _tmpfile.close()


def do__CertificateRequest__ACME_AUTOMATED(
    dbSession,
    domain_names,

    dbAccountKey=None,
    account_key_pem=None,

    dbPrivateKey=None,
    private_key_pem=None,

    ssl_server_certificate_id__renewal_of=None,
):
    """

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

    tmpfiles = []
    dbSslCertificateRequest = None
    dbSslServerCertificate = None
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
            dbAccountKey, _is_created = getcreate__SslLetsEncryptAccountKey__by_pem_text(dbSession, account_key_pem)
        else:
            account_key_pem = dbAccountKey.key_pem
        # we need to use tmpfiles on the disk
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)

        if dbPrivateKey is None:
            private_key_pem = cert_utils.cleanup_pem_text(private_key_pem)
            dbPrivateKey, _is_created = getcreate__SslPrivateKey__by_pem_text(dbSession, private_key_pem)
        else:
            private_key_pem = dbPrivateKey.key_pem
        # we need to use tmpfiles on the disk
        tmpfile_pkey = cert_utils.new_pem_tempfile(private_key_pem)
        tmpfiles.append(tmpfile_pkey)

        # make the CSR
        csr_text = cert_utils.new_csr_for_domain_names(domain_names, tmpfile_pkey.name, tmpfiles)

        # these MUST commit
        with transaction.manager as tx:
            dbSslCertificateRequest = create__SslCertificateRequest(
                dbSession,
                csr_pem,
                certificate_request_type_id = SslCertificateRequestType.ACME_AUTOMATED,
                dbAccountKey = None,
                dbPrivateKey = None,
                dbSslCertificate_issued = None,
                dbSslCertificate__renewal_of = None,
            )

        def process_keyauth_challenge(domain, token, keyauthorization):
            log.info("-process_keyauth_challenge %s", domain)
            with transaction.manager as tx:
                (dbDomain, dbSslCertificateRequest2D) = dbDomainObjects[domain]
                dbSslCertificateRequest2D.challenge_key = token
                dbSslCertificateRequest2D.challenge_text = keyauthorization
                dbSession.flush()

        def process_keyauth_cleanup(domain, token, keyauthorization):
            log.info("-process_keyauth_cleanup %s", domain)

        # ######################################################################
        # THIS BLOCK IS FROM acme-tiny

        # parse account key to get public key
        header, thumbprint = acme.account_key__header_thumbprint(account_key_path=tmpfile_account.name, )

        # pull domains from csr
        csr_domains = cert_utils.parse_csr_domains(csr_path=tmpfile_csr.name,
                                                   submitted_domain_names=domain_names,
                                                   )

        # register the account / ensure that it is registered
        if not dbAccountKey.timestamp_last_authenticated:
            do__SslLetsEncryptAccountKey_authenticate(dbSession,
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
            dbSslServerCertificate = create__SslServerCertificate(
                dbSession,
                timestamp_signed = datetime_signed,
                timestamp_expires = datetime_expires,
                is_active = True,
                cert_pem = cert_pem,
                chained_pem = chained_pem,
                chain_name = chain_url,
                dbSslCertificateRequest = dbSslCertificateRequest,
                dbSslLetsEncryptAccountKey = dbAccountKey,
                dbSslPrivateKey = dbPrivateKey,
                dbSslDomains = [v[0] for v in dbDomainObjects.values()],
                ssl_server_certificate_id__renewal_of = ssl_server_certificate_id__renewal_of,
            )

        return dbSslServerCertificate

    except:
        if dbSslCertificateRequest:
            dbSslCertificateRequest.is_active = False
            dbSslCertificateRequest.is_error = True
            transaction.manager.commit()
        raise

    finally:

        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_expired(dbSession):

    # create an event first
    event_payload_dict = {'count_deactivated': 0,
                          'v': 1,
                          }
    operationsEvent = create__SslOperationsEvent(dbSession,
                                                 SslOperationsEventType.deactivate_expired,
                                                 event_payload_dict
                                                 )

    # deactivate expired certificates
    expired_certs = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.is_active is True,  # noqa
                SslServerCertificate.timestamp_expires < datetime.datetime.utcnow(),
                )\
        .all()
    for c in expired_certs:
        c.is_active = False
        dbSession.flush()
        events.Certificate_expired(dbSession, c, operationsEvent=operationsEvent)

    # update the event
    if len(expired_certs):
        event_payload['count_deactivated'] = len(expired_certs)
        operationsEvent.set_event_payload(event_payload_dict)
        dbSession.flush()
    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_duplicates(dbSession, ran_operations_update_recents=None):
    """
    this is kind of weird.
    because we have multiple domains, it is hard to figure out which certs we should use
    the simplest approach is this:

    1. cache the most recent certs via `operations_update_recents`
    2. find domains that have multiple active certs
    3. don't turn off any certs that are a latest_single or latest_multi
    """
    raise ValueError("Don't run this. It's not needed anymore")
    if ran_operations_update_recents is not True:
        raise ValueError("MUST run `operations_update_recents` first")

    # bookkeeping
    event_payload_dict = {'count_deactivated': 0,
                          'v': 1,
                          }
    operationsEvent = create__SslOperationsEvent(
        dbSession,
        SslOperationsEventType.deactivate_duplicate,
        event_payload_dict,
    )

    _q_ids__latest_single = dbSession.query(SslDomain.ssl_server_certificate_id__latest_single)\
        .distinct()\
        .filter(SslDomain.ssl_server_certificate_id__latest_single != None,  # noqa
                )\
        .subquery()
    _q_ids__latest_multi = dbSession.query(SslDomain.ssl_server_certificate_id__latest_multi)\
        .distinct()\
        .filter(SslDomain.ssl_server_certificate_id__latest_single != None,  # noqa
                )\
        .subquery()

    # now grab the domains with many certs...
    q_inner = dbSession.query(SslUniqueFQDNSet2SslDomain.ssl_domain_id,
                              sqlalchemy.func.count(SslUniqueFQDNSet2SslDomain.ssl_domain_id).label('counted'),
                              )\
        .join(SslServerCertificate,
              SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id == SslServerCertificate.ssl_unique_fqdn_set_id
              )\
        .filter(SslServerCertificate.is_active == True,  # noqa
                )\
        .group_by(SslUniqueFQDNSet2SslDomain.ssl_domain_id)
    q_inner = q_inner.subquery()
    q_domains = dbSession.query(q_inner)\
        .filter(q_inner.c.counted >= 2)
    result = q_domains.all()
    domain_ids_with_multiple_active_certs = [i.ssl_domain_id for i in result]

    if False:
        _turned_off = []
        for _domain_id in domain_ids_with_multiple_active_certs:
            domain_certs = dbSession.query(SslServerCertificate)\
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
                    events.Certificate_deactivated(dbSession, c, operationsEvent=operationsEvent)

    # update the event
    if len(_turned_off):
        event_payload['count_deactivated'] = len(_turned_off)
        operationsEvent.set_event_payload(event_payload_dict)
        dbSession.flush()
    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_update_recents(dbSession):

    # first the single
    # _t_domain = SslDomain.__table__.alias('domain')
    _q_sub = dbSession.query(SslServerCertificate.id)\
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
    dbSession.execute(SslDomain.__table__
                      .update()
                      .values(ssl_server_certificate_id__latest_single=_q_sub)
                      )

    # then the multiple
    # _t_domain = SslDomain.__table__.alias('domain')
    _q_sub = dbSession.query(SslServerCertificate.id)\
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
    dbSession.execute(SslDomain.__table__
                      .update()
                      .values(ssl_server_certificate_id__latest_multi=_q_sub)
                      )

    # update the count of active certs
    SslServerCertificate1 = sqlalchemy.orm.aliased(SslServerCertificate)
    SslServerCertificate2 = sqlalchemy.orm.aliased(SslServerCertificate)
    _q_sub = dbSession.query(sqlalchemy.func.count(SslDomain.id))\
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
    dbSession.execute(SslCaCertificate.__table__
                      .update()
                      .values(count_active_certificates=_q_sub)
                      )

    # update the count of active PrivateKeys
    SslServerCertificate1 = sqlalchemy.orm.aliased(SslServerCertificate)
    SslServerCertificate2 = sqlalchemy.orm.aliased(SslServerCertificate)
    _q_sub = dbSession.query(sqlalchemy.func.count(SslDomain.id))\
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
    dbSession.execute(SslPrivateKey.__table__
                      .update()
                      .values(count_active_certificates=_q_sub)
                      )

    # the following works, but this is currently tracked
    if False:
        # update the counts on Account Keys
        _q_sub_req = dbSession.query(sqlalchemy.func.count(SslCertificateRequest.id))\
            .filter(SslCertificateRequest.ssl_letsencrypt_account_key_id == SslLetsEncryptAccountKey.id,
                    )\
            .subquery()\
            .as_scalar()
        dbSession.execute(SslLetsEncryptAccountKey.__table__
                          .update()
                          .values(count_certificate_requests=_q_sub_req,
                                  # count_certificates_issued=_q_sub_iss,
                                  )
                          )
        # update the counts on Private Keys
        _q_sub_req = dbSession.query(sqlalchemy.func.count(SslCertificateRequest.id))\
            .filter(SslCertificateRequest.ssl_private_key_id__signed_by == SslPrivateKey.id,
                    )\
            .subquery()\
            .as_scalar()
        _q_sub_iss = dbSession.query(sqlalchemy.func.count(SslServerCertificate.id))\
            .filter(SslServerCertificate.ssl_private_key_id__signed_by == SslPrivateKey.id,
                    )\
            .subquery()\
            .as_scalar()

        dbSession.execute(SslPrivateKey.__table__
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
    # we don't need this if we add the bookkeeping object, but let's just keep this to be safe
    mark_changed(dbSession)

    # bookkeeping
    dbEvent = create__SslOperationsEvent(dbSession,
                                         SslOperationsEventType.update_recents,
                                         {'v': 1,
                                          }
                                         )
    return dbEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_domains__add(dbSession, domain_names):
    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    for domain_name in domain_names:
        _exists = get__SslDomain__by_name(dbSession, domain_name, preload=False)
        if _exists:
            results[domain_name] = 'exists'
        elif not _exists:
            _exists_queue = get__SslQueueDomain__by_name(dbSession, domain_name)
            if _exists_queue:
                results[domain_name] = 'already_queued'
            elif not _exists_queue:
                dbQueue = SslQueueDomain()
                dbQueue.domain_name = domain_name
                dbQueue.timestamp_entered = datetime.datetime.utcnow()
                dbSession.add(dbQueue)
                dbSession.flush()
                results[domain_name] = 'queued'
    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_domains__process(
    dbSession,
    dbAccountKey=None,
    dbPrivateKey=None,
):
    try:
        items_paged = get__SslQueueDomain__paginated(
            dbSession,
            show_processed=False,
            limit=100,
            offset=0
        )
        event_payload = {'batch_size': len(items_paged),
                         'status': 'attempt',
                         'queue_domain_ids': ','.join([str(d.id) for d in items_paged]),
                         'v': 1,
                         }
        operationsEvent = create__SslOperationsEvent(dbSession,
                                                     SslOperationsEventType.batch_queued_domains,
                                                     event_payload,
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
        for qdomain in items_paged:
            domainObject, _is_created = getcreate__SslDomain__by_domainName(
                dbSession,
                qdomain.domain_name,
                is_from_domain_queue=True
            )
            domainObjects.append(domainObject)
            qdomain.ssl_domain_id = domainObject.id
            dbSession.flush()

        # create a dbFQDNset for this.
        # TODO - should we delete this if we fail? or keep for the CSR record
        #      - rationale is that on another pass, we would have a different fqdn set
        dbFQDNset, is_created = getcreate__SslUniqueFQDNSet__by_domainObjects(dbSession, domainObjects)

        # update the event
        event_payload['ssl_unique_fqdn_set_id'] = dbFQDNset.id
        operationsEvent.set_event_payload(event_payload)
        dbSession.flush()
        transaction.commit()

        if dbAccountKey is None:
            dbAccountKey = get__SslLetsEncryptAccountKey__default(dbSession)
            if not dbAccountKey:
                raise ValueError("Could not grab a AccountKey")

        if dbPrivateKey is None:
            dbPrivateKey = get__SslPrivateKey__current_week(dbSession)
            if not dbPrivateKey:
                dbPrivateKey = create__SslPrivateKey__new(dbSession, is_autogenerated_key=True)
            if not dbPrivateKey:
                raise ValueError("Could not grab a PrivateKey")

        # do commit, just because we may have created a private key
        transaction.commit()

        dbSslServerCertificate = None
        try:
            domain_names = [d.domain_name for d in domainObjects]
            dbSslServerCertificate = do__CertificateRequest__ACME_AUTOMATED(
                dbSession,
                domain_names,
                dbAccountKey=dbAccountKey,
                dbPrivateKey=dbPrivateKey,
            )
            for qdomain in items_paged:
                # this may have committed
                qdomain.timestamp_processed = timestamp_transaction
            dbSession.flush()

            event_payload['status'] = 'success'
            event_payload['certificate.id'] = dbSslServerCertificate.id
            operationsEvent.set_event_payload(event_payload)
            dbSession.flush()

        except errors.DomainVerificationError, e:
            event_payload['status'] = 'error - DomainVerificationError'
            event_payload['error'] = e.message
            operationsEvent.set_event_payload(event_payload)
            dbSession.flush()
            raise

        return True

    except:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_renewals__process(
    dbSession,
    ssl_operations_event_id__child_of = None,
    fqdns_ids_only = None
):
    try:
        event_type = SslOperationsEventType.queue_renewals
        event_payload = {'status': 'attempt',
                         'v': 1,
                         }
        operationsEvent = create__SslOperationsEvent(dbSession,
                                                     event_type,
                                                     event_payload,
                                                     ssl_operations_event_id__child_of = ssl_operations_event_id__child_of,
                                                     )

        _expiring_days = 28
        _until = datetime.datetime.utcnow() + datetime.timedelta(days=_expiring_days)
        _core_query = dbSession.query(SslServerCertificate)\
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
            renewal = create__SslQueueRenewal(
                dbSession,
                cert,
                ssl_operations_event_id__child_of = ssl_operations_event_id__child_of or operationsEvent.id
            )
        event_payload['queued_certificate_ids'] = ','.join([str(c.id) for c in results])
        operationsEvent.set_event_payload(event_payload)
        dbSession.flush()
        return True

    except:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def upload__SslCaCertificateBundle__by_pem_text(dbSession, bundle_data):
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
            dbSession,
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

    return results




