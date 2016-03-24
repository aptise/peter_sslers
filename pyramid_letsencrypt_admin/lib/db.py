# stdlib
import datetime
import json
import logging
import pdb
import tempfile

# pypi
import sqlalchemy
import transaction

# localapp
from ..models import *
from . import acme
from . import errors
from . import utils

# setup logging
log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# ==============================================================================


def get__LetsencryptCertificateRequest_2_ManagedDomain__challenged(dbSession, challenge, domain_name):
    active_request = dbSession.query(LetsencryptCertificateRequest_2_ManagedDomain)\
        .join(LetsencryptManagedDomain,
              LetsencryptCertificateRequest_2_ManagedDomain.letsencrypt_managed_domain_id == LetsencryptManagedDomain.id
              )\
        .join(LetsencryptCertificateRequest,
              LetsencryptCertificateRequest_2_ManagedDomain.letsencrypt_certificate_request_id == LetsencryptCertificateRequest.id
              )\
        .filter(LetsencryptCertificateRequest_2_ManagedDomain.challenge_key == challenge,
                sa.func.lower(LetsencryptManagedDomain.domain_name) == sa.func.lower(domain_name),
                LetsencryptCertificateRequest.is_active.op('IS')(True),
                )\
        .options(sqlalchemy.orm.contains_eager('certificate_request'),
                 sqlalchemy.orm.contains_eager('domain'),
                 )\
        .first()
    return active_request


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptManagedDomain__count(dbSession):
    counted = dbSession.query(LetsencryptManagedDomain).count()
    return counted


def get__LetsencryptManagedDomain__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptManagedDomains = dbSession.query(LetsencryptManagedDomain)\
        .order_by(sa.func.lower(LetsencryptManagedDomain.domain_name).asc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptManagedDomains


def get__LetsencryptManagedDomain__by_id(dbSession, domain_id):
    dbLetsencryptManagedDomain = dbSession.query(LetsencryptManagedDomain)\
        .filter(LetsencryptManagedDomain.id == domain_id)\
        .options(sqlalchemy.orm.subqueryload('domain_to_certificates').joinedload('certificate'),
                 sqlalchemy.orm.subqueryload('domain_to_certificate_requests').joinedload('certificate_request'),
                 )\
        .first()
    return dbLetsencryptManagedDomain


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptHttpsCertificate__count(dbSession):
    counted = dbSession.query(LetsencryptHttpsCertificate).count()
    return counted


def get__LetsencryptHttpsCertificate__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptHttpsCertificates = dbSession.query(LetsencryptHttpsCertificate)\
        .order_by(LetsencryptHttpsCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptHttpsCertificates


def get__LetsencryptHttpsCertificate__by_id(dbSession, cert_id):
    dbLetsencryptHttpsCertificate = dbSession.query(LetsencryptHttpsCertificate)\
        .filter(LetsencryptHttpsCertificate.id == cert_id)\
        .options(sqlalchemy.orm.subqueryload('certificate_to_domains').joinedload('domain'),
                 )\
        .first()
    return dbLetsencryptHttpsCertificate

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptCertificateRequest__count(dbSession):
    counted = dbSession.query(LetsencryptCertificateRequest).count()
    return counted


def get__LetsencryptCertificateRequest__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptCertificateRequests = dbSession.query(LetsencryptCertificateRequest)\
        .options(sqlalchemy.orm.subqueryload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .order_by(LetsencryptCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptCertificateRequests


def get__LetsencryptCertificateRequest__by_id(dbSession, certificate_request_id):
    dbLetsencryptCertificateRequest = dbSession.query(LetsencryptCertificateRequest)\
        .filter(LetsencryptCertificateRequest.id == certificate_request_id)\
        .options(sqlalchemy.orm.subqueryload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .one()
    return dbLetsencryptCertificateRequest


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptAccountKey__count(dbSession):
    counted = dbSession.query(LetsencryptAccountKey).count()
    return counted


def get__LetsencryptAccountKey__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptAccountKeys = dbSession.query(LetsencryptAccountKey)\
        .order_by(LetsencryptAccountKey.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptAccountKeys


def get__LetsencryptAccountKey__by_id(dbSession, cert_id):
    dbLetsencryptAccountKey = dbSession.query(LetsencryptAccountKey)\
        .filter(LetsencryptAccountKey.id == cert_id)\
        .first()
    return dbLetsencryptAccountKey


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptDomainKey__count(dbSession):
    counted = dbSession.query(LetsencryptDomainKey).count()
    return counted


def get__LetsencryptDomainKey__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptDomainKeys = dbSession.query(LetsencryptDomainKey)\
        .order_by(LetsencryptDomainKey.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptDomainKeys


def get__LetsencryptDomainKey__by_id(dbSession, cert_id):
    dbLetsencryptDomainKey = dbSession.query(LetsencryptDomainKey)\
        .filter(LetsencryptDomainKey.id == cert_id)\
        .first()
    return dbLetsencryptDomainKey


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptCACertificateProbe__count(dbSession):
    counted = dbSession.query(LetsencryptCACertificateProbe).count()
    return counted


def get__LetsencryptCACertificateProbe__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptCACertificateProbes = dbSession.query(LetsencryptCACertificateProbe)\
        .order_by(LetsencryptCACertificateProbe.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptCACertificateProbes


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptCACertificate__count(dbSession):
    counted = dbSession.query(LetsencryptCACertificate).count()
    return counted


def get__LetsencryptCACertificate__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptCACertificates = dbSession.query(LetsencryptCACertificate)\
        .order_by(LetsencryptCACertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptCACertificates


def get__LetsencryptCACertificate__by_id(dbSession, cert_id):
    dbLetsencryptCACertificate = dbSession.query(LetsencryptCACertificate)\
        .filter(LetsencryptCACertificate.id == cert_id)\
        .first()
    return dbLetsencryptCACertificate


def get__LetsencryptHttpsCertificate_by_LetsencryptCACertificateId__count(dbSession, cert_id):
    counted = dbSession.query(LetsencryptHttpsCertificate)\
        .filter(LetsencryptHttpsCertificate.letsencrypt_ca_certificate_id__signed_by == cert_id)\
        .count()
    return counted


def get__LetsencryptHttpsCertificate_by_LetsencryptCACertificateId__paginated(dbSession, cert_id, limit=None, offset=0):
    dbLetsencryptHttpsCertificates = dbSession.query(LetsencryptHttpsCertificate)\
        .filter(LetsencryptHttpsCertificate.letsencrypt_ca_certificate_id__signed_by == cert_id)\
        .order_by(LetsencryptHttpsCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptHttpsCertificates


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__LetsencryptManagedDomain__by_domainName(dbSession, domain_name):
    dbDomain = dbSession.query(LetsencryptManagedDomain)\
        .filter(sa.func.lower(LetsencryptManagedDomain.domain_name) == sa.func.lower(domain_name))\
        .first()
    if not dbDomain:
        dbDomain = LetsencryptManagedDomain()
        dbDomain.domain_name = domain_name
        dbSession.add(dbDomain)
        dbSession.flush()
    return dbDomain


def getcreate__LetsencryptAccountKey__by_pem_text(dbSession, key_pem):
    key_pem = acme.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    is_created = False
    dbKey = dbSession.query(LetsencryptAccountKey)\
        .filter(LetsencryptAccountKey.key_pem_md5 == key_pem_md5,
                LetsencryptAccountKey.key_pem == key_pem,
                )\
        .first()
    if not dbKey:
        try:
            _tmpfile = tempfile.NamedTemporaryFile()
            _tmpfile.write(key_pem)
            _tmpfile.seek(0)

            # validate
            acme.validate_key__pem_filepath(_tmpfile.name)

            # grab the modulus
            key_pem_modulus_md5 = acme.modulus_md5_key__pem_filepath(_tmpfile.name)
        except:
            raise
        finally:
            _tmpfile.close()
        dbKey = LetsencryptAccountKey()
        dbKey.timestamp_first_seen = datetime.datetime.utcnow()
        dbKey.key_pem = key_pem
        dbKey.key_pem_md5 = key_pem_md5
        dbKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbSession.add(dbKey)
        dbSession.flush()
        is_created = True
    return dbKey, is_created


def getcreate__LetsencryptDomainKey__by_pem_text(dbSession, key_pem):
    key_pem = acme.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    is_created = False
    dbKey = dbSession.query(LetsencryptDomainKey)\
        .filter(LetsencryptDomainKey.key_pem_md5 == key_pem_md5,
                LetsencryptDomainKey.key_pem == key_pem,
                )\
        .first()
    if not dbKey:
        try:
            _tmpfile = tempfile.NamedTemporaryFile()
            _tmpfile.write(key_pem)
            _tmpfile.seek(0)

            # validate
            acme.validate_key__pem_filepath(_tmpfile.name)

            # grab the modulus
            key_pem_modulus_md5 = acme.modulus_md5_key__pem_filepath(_tmpfile.name)
        except:
            raise
        finally:
            _tmpfile.close()

        dbKey = LetsencryptDomainKey()
        dbKey.timestamp_first_seen = datetime.datetime.utcnow()
        dbKey.key_pem = key_pem
        dbKey.key_pem_md5 = key_pem_md5
        dbKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbSession.add(dbKey)
        dbSession.flush()
        is_created = True
    return dbKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptCACertificate__by_pem_text(dbSession, cert_pem):
    cert_pem = acme.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    is_created = False
    dbCertificate = dbSession.query(LetsencryptCACertificate)\
        .filter(LetsencryptCACertificate.cert_pem_md5 == cert_pem_md5,
                LetsencryptCACertificate.cert_pem == cert_pem,
                )\
        .first()
    return dbCertificate


def getcreate__LetsencryptCACertificate__by_pem_text(dbSession, cert_pem, chain_name):
    dbCertificate = get__LetsencryptCACertificate__by_pem_text(dbSession, cert_pem)
    is_created = False
    if not dbCertificate:
        cert_pem = acme.cleanup_pem_text(cert_pem)
        cert_pem_md5 = utils.md5_text(cert_pem)
        try:
            _tmpfile = tempfile.NamedTemporaryFile()
            _tmpfile.write(cert_pem)
            _tmpfile.seek(0)

            # validate
            acme.validate_cert__pem_filepath(_tmpfile.name)

            # grab the modulus
            cert_pem_modulus_md5 = acme.modulus_md5_cert__pem_filepath(_tmpfile.name)

            dbCertificate = LetsencryptCACertificate()
            dbCertificate.name = chain_name or 'unknown'

            dbCertificate.le_authority_name = None
            dbCertificate.is_ca_certificate = True
            dbCertificate.is_authority_certificate = False
            dbCertificate.is_cross_signed_authority_certificate = None
            dbCertificate.id_cross_signed_of = None
            dbCertificate.timestamp_first_seen = datetime.datetime.utcnow()
            dbCertificate.cert_pem = cert_pem
            dbCertificate.cert_pem_md5 = cert_pem_md5
            dbCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

            dbCertificate.timestamp_signed = acme.parse_startdate_cert__pem_filepath(_tmpfile.name)
            dbCertificate.timestamp_expires = acme.parse_enddate_cert__pem_filepath(_tmpfile.name)
            dbCertificate.cert_subject = acme.cert_single_op__pem_filepath(_tmpfile.name, '-subject')
            dbCertificate.cert_subject_hash = acme.cert_single_op__pem_filepath(_tmpfile.name, '-subject_hash')
            dbCertificate.cert_issuer = acme.cert_single_op__pem_filepath(_tmpfile.name, '-issuer')
            dbCertificate.cert_issuer_hash = acme.cert_single_op__pem_filepath(_tmpfile.name, '-issuer_hash')

            dbSession.add(dbCertificate)
            dbSession.flush()
            is_created = True
        except:
            raise
        finally:
            _tmpfile.close()

    return dbCertificate, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__CertificateRequest__by_domainNamesList_FLOW(dbSession, domain_names):
    dbLetsencryptCertificateRequest = LetsencryptCertificateRequest()
    dbLetsencryptCertificateRequest.is_active = True
    dbLetsencryptCertificateRequest.certificate_request_type_id = LetsencryptCertificateRequestType.FLOW
    dbLetsencryptCertificateRequest.timestamp_started = datetime.datetime.utcnow()
    dbSession.add(dbLetsencryptCertificateRequest)
    dbSession.flush()

    for _domain_name in domain_names:
        dbDomain = getcreate__LetsencryptManagedDomain__by_domainName(dbSession, _domain_name)

        dbLetsencryptCertificateRequest2D = LetsencryptCertificateRequest_2_ManagedDomain()
        dbLetsencryptCertificateRequest2D.letsencrypt_certificate_request_id = dbLetsencryptCertificateRequest.id
        dbLetsencryptCertificateRequest2D.letsencrypt_managed_domain_id = dbDomain.id

        dbSession.add(dbLetsencryptCertificateRequest2D)
        dbSession.flush()

    dbSession.flush()

    return dbLetsencryptCertificateRequest


def create__CertificateRequest__FULL(
    dbSession,
    domain_names,
    account_key_pem=None,
    domain_key_pem=None,
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

    tmpfiles = []
    dbLetsencryptCertificateRequest = None
    dbLetsencryptHttpsCertificate = None
    try:

        account_key_pem = acme.cleanup_pem_text(account_key_pem)
        domain_key_pem = acme.cleanup_pem_text(domain_key_pem)

        # we should have cleaned this up before, but just be safe
        domain_names = [i.lower() for i in [d.strip() for d in domain_names] if i]
        domain_names = set(domain_names)
        if not domain_names:
            raise ValueError("no domain names!")
        # we need a list
        domain_names = list(domain_names)

        # we need to use tmpfiles on the disk
        tmpfile_account = tempfile.NamedTemporaryFile()
        tmpfile_account.write(account_key_pem)
        tmpfile_account.seek(0)
        tmpfiles.append(tmpfile_account)

        tmpfile_domain = tempfile.NamedTemporaryFile()
        tmpfile_domain.write(domain_key_pem)
        tmpfile_domain.seek(0)
        tmpfiles.append(tmpfile_domain)

        csr_text = acme.new_csr_for_domain_names(domain_names, tmpfile_domain.name, tmpfiles)

        # store the csr_text in a tmpfile
        tmpfile_csr = tempfile.NamedTemporaryFile()
        tmpfile_csr.write(csr_text)
        tmpfile_csr.seek(0)
        tmpfiles.append(tmpfile_csr)

        # validate
        acme.validate_csr__pem_filepath(tmpfile_csr.name)

        # grab the modulus
        csr_pem_modulus_md5 = acme.modulus_md5_csr__pem_filepath(tmpfile_csr.name)

        # these MUST commit
        with transaction.manager as tx:

            # have we seen these certificates before?
            dbAccountKey, _is_created = getcreate__LetsencryptAccountKey__by_pem_text(dbSession, account_key_pem)
            dbDomainKey, _is_created = getcreate__LetsencryptDomainKey__by_pem_text(dbSession, domain_key_pem)

            dbLetsencryptCertificateRequest = LetsencryptCertificateRequest()
            dbLetsencryptCertificateRequest.is_active = True
            dbLetsencryptCertificateRequest.certificate_request_type_id = LetsencryptCertificateRequestType.FULL
            dbLetsencryptCertificateRequest.timestamp_started = datetime.datetime.utcnow()
            dbLetsencryptCertificateRequest.csr_pem = csr_text
            dbLetsencryptCertificateRequest.csr_pem_md5 = utils.md5_text(csr_text)
            dbLetsencryptCertificateRequest.csr_pem_modulus_md5 = csr_pem_modulus_md5
            dbLetsencryptCertificateRequest.letsencrypt_account_key_id = dbAccountKey.id
            dbLetsencryptCertificateRequest.letsencrypt_domain_key_id__signed_by = dbDomainKey.id
            dbSession.add(dbLetsencryptCertificateRequest)
            dbSession.flush()

            # we'll use this tuple in a bit...
            _domain_objects = {}
            for _domain_name in domain_names:
                dbDomain = getcreate__LetsencryptManagedDomain__by_domainName(dbSession, _domain_name)

                dbLetsencryptCertificateRequest2D = LetsencryptCertificateRequest_2_ManagedDomain()
                dbLetsencryptCertificateRequest2D.letsencrypt_certificate_request_id = dbLetsencryptCertificateRequest.id
                dbLetsencryptCertificateRequest2D.letsencrypt_managed_domain_id = dbDomain.id

                dbSession.add(dbLetsencryptCertificateRequest2D)
                dbSession.flush()

                _domain_objects[_domain_name] = (dbDomain, dbLetsencryptCertificateRequest2D)

            dbSession.flush()

        def process_keyauth_challenge(domain, token, keyauthorization):
            log.info("-process_keyauth_challenge %s", domain)
            with transaction.manager as tx:
                (dbDomain, dbLetsencryptCertificateRequest2D) = _domain_objects[domain]
                dbDomain = dbSession.merge(dbDomain, )
                dbLetsencryptCertificateRequest2D = dbSession.merge(dbLetsencryptCertificateRequest2D, )
                dbLetsencryptCertificateRequest2D.challenge_key = token
                dbLetsencryptCertificateRequest2D.challenge_text = keyauthorization
                dbSession.flush()

        def process_keyauth_cleanup(domain, token, keyauthorization):
            log.info("-process_keyauth_cleanup %s", domain)

        # ######################################################################
        # THIS BLOCK IS FROM acme-tiny

        # parse account key to get public key
        header, thumbprint = acme.account_key__header_thumbprint(account_key_path=tmpfile_account.name, )

        # pull domains from csr
        csr_domains = acme.parse_csr_domains(csr_path=tmpfile_csr.name,
                                             submitted_domain_names=domain_names,
                                             )

        # register the account / ensure that it is registered
        acme.acme_register_account(header,
                                   account_key_path=tmpfile_account.name)

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
            if dbDomainKey not in dbSession:
                dbDomainKey = dbSession.merge(dbDomainKey)
            if dbLetsencryptCertificateRequest not in dbSession:
                dbLetsencryptCertificateRequest = dbSession.merge(dbLetsencryptCertificateRequest)
            dbLetsencryptHttpsCertificate = create__LetsencryptHttpsCertificate(
                dbSession,
                timestamp_signed = datetime_signed,
                timestamp_expires = datetime_expires,
                is_active = True,
                cert_pem = cert_pem,
                chained_pem = chained_pem,
                chain_name = chain_url,
                letsencrypt_domain_key_id__signed_by = dbDomainKey.id,
                dbLetsencryptCertificateRequest = dbLetsencryptCertificateRequest,
                domains_list__objects = _domain_objects,
            )

        # merge this back in
        if dbLetsencryptHttpsCertificate:
            if dbLetsencryptHttpsCertificate not in dbSession:
                dbLetsencryptHttpsCertificate = dbSession.merge(dbLetsencryptHttpsCertificate)
        return dbLetsencryptHttpsCertificate

    except:
        if dbLetsencryptCertificateRequest:
            if dbLetsencryptCertificateRequest not in dbSession:
                dbLetsencryptCertificateRequest = dbSession.merge(dbLetsencryptCertificateRequest)
                dbLetsencryptCertificateRequest.is_active = False
                dbLetsencryptCertificateRequest.is_error = True
                transaction.manager.commit()
        raise

    finally:

        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__LetsencryptHttpsCertificate__by_pem_text(
    dbSession,
    cert_pem,
    dbCACertificate=None,
    dbDomainKey=None,
):
    cert_pem = acme.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    is_created = False
    dbCertificate = dbSession.query(LetsencryptHttpsCertificate)\
        .filter(LetsencryptHttpsCertificate.cert_pem_md5 == cert_pem_md5,
                LetsencryptHttpsCertificate.cert_pem == cert_pem,
                )\
        .first()
    if not dbCertificate:
        _tmpfileCert = None
        try:
            _tmpfileCert = tempfile.NamedTemporaryFile()
            _tmpfileCert.write(cert_pem)
            _tmpfileCert.seek(0)

            # validate
            acme.validate_cert__pem_filepath(_tmpfileCert.name)

            # grab the modulus
            cert_pem_modulus_md5 = acme.modulus_md5_cert__pem_filepath(_tmpfileCert.name)
            dbCertificate = LetsencryptHttpsCertificate()

            dbCertificate.timestamp_signed = acme.parse_startdate_cert__pem_filepath(_tmpfileCert.name)
            dbCertificate.timestamp_expires = acme.parse_enddate_cert__pem_filepath(_tmpfileCert.name)
            dbCertificate.cert_subject = acme.cert_single_op__pem_filepath(_tmpfileCert.name, '-subject')
            dbCertificate.cert_subject_hash = acme.cert_single_op__pem_filepath(_tmpfileCert.name, '-subject_hash')
            dbCertificate.cert_issuer = acme.cert_single_op__pem_filepath(_tmpfileCert.name, '-issuer')
            dbCertificate.cert_issuer_hash = acme.cert_single_op__pem_filepath(_tmpfileCert.name, '-issuer_hash')
            dbCertificate.is_active = True

            dbCertificate.cert_pem = cert_pem
            dbCertificate.cert_pem_md5 = cert_pem_md5
            dbCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

            # this is the LetsEncrypt key
            if dbCACertificate is None:
                raise ValueError('dbCACertificate is None')
            # we should make sure it issued the certificate:
            if dbCertificate.cert_issuer_hash != dbCACertificate.cert_subject_hash:
                raise ValueError('dbCACertificate did not sign the certificate')
            dbCertificate.letsencrypt_ca_certificate_id__signed_by = dbCACertificate.id

            # this is the private key
            # we should make sure it signed the certificate
            # the md5 check isn't exact, BUT ITS CLOSE
            if dbDomainKey is None:
                raise ValueError('dbDomainKey is None')
            if dbCertificate.cert_pem_modulus_md5 != dbDomainKey.key_pem_modulus_md5:
                raise ValueError('dbDomainKey did not sign the certificate')
            dbCertificate.letsencrypt_domain_key_id__signed_by = dbDomainKey.id

            certificate_domain_names = acme.parse_cert_domains(cert_path=_tmpfileCert.name)
            certificate_domain_names = list(certificate_domain_names)
            if not certificate_domain_names:
                raise ValueError("could not find any domain names in the certificate")

            dbSession.add(dbCertificate)
            dbSession.flush()
            is_created = True

            for _domain_name in certificate_domain_names:

                dbDomain = getcreate__LetsencryptManagedDomain__by_domainName(dbSession, _domain_name)

                dbLetsencryptHttpsCertificateToDomain = LetsencryptHttpsCertificateToDomain()
                dbLetsencryptHttpsCertificateToDomain.letsencrypt_https_certificate_id = dbCertificate.id
                dbLetsencryptHttpsCertificateToDomain.letsencrypt_managed_domain_id = dbDomain.id
                dbSession.add(dbLetsencryptHttpsCertificateToDomain)
                dbSession.flush()

        except:
            raise
        finally:
            if _tmpfileCert:
                _tmpfileCert.close()

    return dbCertificate, is_created


def create__LetsencryptHttpsCertificate(
    dbSession,
    timestamp_signed = None,
    timestamp_expires = None,
    is_active = None,
    cert_pem = None,
    chained_pem = None,
    chain_name = None,
    dbLetsencryptCertificateRequest = None,
    domains_list__objects = None,

    # only one of these 2
    letsencrypt_domain_key_id__signed_by = None,
    privkey_pem = None,
):
    if not any((letsencrypt_domain_key_id__signed_by, privkey_pem)) or all((letsencrypt_domain_key_id__signed_by, privkey_pem)):
        raise ValueError("create__LetsencryptHttpsCertificate must accept ONE OF [`letsencrypt_domain_key_id__signed_by`, `privkey_pem`]")
    if privkey_pem:
        raise ValueError("need to figure this out")

    # we need to figure this out; it's the chained_pem
    # letsencrypt_ca_certificate_id__signed_by
    dbCACertificate, _is_created_cert = getcreate__LetsencryptCACertificate__by_pem_text(dbSession, chained_pem, chain_name)
    letsencrypt_ca_certificate_id__signed_by = dbCACertificate.id

    cert_pem = acme.cleanup_pem_text(cert_pem)
    try:
        _tmpfileCert = tempfile.NamedTemporaryFile()
        _tmpfileCert.write(cert_pem)
        _tmpfileCert.seek(0)

        # validate
        acme.validate_cert__pem_filepath(_tmpfileCert.name)

        # grab the modulus
        cert_pem_modulus_md5 = acme.modulus_md5_cert__pem_filepath(_tmpfileCert.name)

    except:
        raise
    finally:
        _tmpfileCert.close()

    dbLetsencryptHttpsCertificate = LetsencryptHttpsCertificate()
    dbLetsencryptHttpsCertificate.timestamp_signed = timestamp_signed
    dbLetsencryptHttpsCertificate.timestamp_expires = timestamp_signed
    dbLetsencryptHttpsCertificate.is_active = is_active
    dbLetsencryptHttpsCertificate.cert_pem = cert_pem
    dbLetsencryptHttpsCertificate.cert_pem_md5 = utils.md5_text(cert_pem)
    dbLetsencryptHttpsCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5
    if dbLetsencryptCertificateRequest:
        if dbLetsencryptCertificateRequest not in dbSession:
            dbLetsencryptCertificateRequest = dbSession.merge(dbLetsencryptCertificateRequest)
        dbLetsencryptCertificateRequest.is_active = False
        dbLetsencryptHttpsCertificate.letsencrypt_certificate_request_id = dbLetsencryptCertificateRequest.id
    dbLetsencryptHttpsCertificate.letsencrypt_ca_certificate_id__signed_by = letsencrypt_ca_certificate_id__signed_by
    dbLetsencryptHttpsCertificate.letsencrypt_domain_key_id__signed_by = letsencrypt_domain_key_id__signed_by
    dbSession.add(dbLetsencryptHttpsCertificate)
    dbSession.flush()

    for _domain_name in domains_list__objects.keys():
        # we dont' care about the dbLetsencryptCertificateRequest2D
        (domainObject, dbLetsencryptCertificateRequest2D) = domains_list__objects[_domain_name]
        if domainObject not in dbSession:
            domainObject = dbSession.merge(domainObject)
        dbLetsencryptHttpsCertificateToDomain = LetsencryptHttpsCertificateToDomain()
        dbLetsencryptHttpsCertificateToDomain.letsencrypt_https_certificate_id = dbLetsencryptHttpsCertificate.id
        dbLetsencryptHttpsCertificateToDomain.letsencrypt_managed_domain_id = domainObject.id
        dbSession.add(dbLetsencryptHttpsCertificateToDomain)
        dbSession.flush()

    return dbLetsencryptHttpsCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def ca_certificate_probe(dbSession):
    certs = acme.probe_letsencrypt_certificates()
    certs_discovered = []
    certs_modified = []
    for c in certs:
        _is_created = False
        dbCACertificate = get__LetsencryptCACertificate__by_pem_text(DBSession, c['cert_pem'])
        if not dbCACertificate:
            dbCACertificate, _is_created = getcreate__LetsencryptCACertificate__by_pem_text(DBSession, c['cert_pem'], c['name'])
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
    dbProbe = LetsencryptCACertificateProbe()
    dbProbe.timestamp_operation = datetime.datetime.utcnow()
    dbProbe.is_certificates_discovered = True if certs_discovered else False
    dbProbe.is_certificates_updated = True if certs_modified else False
    DBSession.add(dbProbe)
    DBSession.flush()
    return dbProbe
