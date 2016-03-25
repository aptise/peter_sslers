# stdlib
import datetime
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


def get__LetsencryptCertificateRequest2LetsencryptDomain__challenged(dbSession, challenge, domain_name):
    active_request = dbSession.query(LetsencryptCertificateRequest2LetsencryptDomain)\
        .join(LetsencryptDomain,
              LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id == LetsencryptDomain.id
              )\
        .join(LetsencryptCertificateRequest,
              LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id == LetsencryptCertificateRequest.id
              )\
        .filter(LetsencryptCertificateRequest2LetsencryptDomain.challenge_key == challenge,
                sa.func.lower(LetsencryptDomain.domain_name) == sa.func.lower(domain_name),
                LetsencryptCertificateRequest.is_active.op('IS')(True),
                )\
        .options(sqlalchemy.orm.contains_eager('certificate_request'),
                 sqlalchemy.orm.contains_eager('domain'),
                 )\
        .first()
    return active_request


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptDomain__count(dbSession):
    counted = dbSession.query(LetsencryptDomain).count()
    return counted


def get__LetsencryptDomain__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptDomains = dbSession.query(LetsencryptDomain)\
        .order_by(sa.func.lower(LetsencryptDomain.domain_name).asc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptDomains


def get__LetsencryptDomain__by_id(dbSession, domain_id):
    dbLetsencryptDomain = dbSession.query(LetsencryptDomain)\
        .filter(LetsencryptDomain.id == domain_id)\
        .options(sqlalchemy.orm.subqueryload('domain_to_certificates').joinedload('certificate'),
                 sqlalchemy.orm.subqueryload('domain_to_certificate_requests').joinedload('certificate_request'),
                 )\
        .first()
    return dbLetsencryptDomain


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptServerCertificate__count(dbSession):
    counted = dbSession.query(LetsencryptServerCertificate).count()
    return counted


def get__LetsencryptServerCertificate__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptServerCertificates = dbSession.query(LetsencryptServerCertificate)\
        .order_by(LetsencryptServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptServerCertificates


def get__LetsencryptServerCertificate__by_id(dbSession, cert_id):
    dbLetsencryptServerCertificate = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.id == cert_id)\
        .options(sqlalchemy.orm.subqueryload('certificate_to_domains').joinedload('domain'),
                 )\
        .first()
    return dbLetsencryptServerCertificate

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


def get__LetsencryptCertificateRequest__by_LetsencryptDomain__count(dbSession, domain_id):
    counted = dbSession.query(LetsencryptCertificateRequest)\
        .join(LetsencryptCertificateRequest2LetsencryptDomain,
              LetsencryptCertificateRequest.id == LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id,
              )\
        .filter(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .count()
    return counted


def get__LetsencryptCertificateRequest__by_LetsencryptDomain__paginated(dbSession, domain_id, limit=None, offset=0):
    dbLetsencryptCertificateRequests = dbSession.query(LetsencryptCertificateRequest)\
        .join(LetsencryptCertificateRequest2LetsencryptDomain,
              LetsencryptCertificateRequest.id == LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id,
              )\
        .filter(LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .order_by(LetsencryptCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptCertificateRequests

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


def get__LetsencryptPrivateKey__count(dbSession):
    counted = dbSession.query(LetsencryptPrivateKey).count()
    return counted


def get__LetsencryptPrivateKey__paginated(dbSession, limit=None, offset=0):
    dbLetsencryptPrivateKeys = dbSession.query(LetsencryptPrivateKey)\
        .order_by(LetsencryptPrivateKey.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptPrivateKeys


def get__LetsencryptPrivateKey__by_id(dbSession, cert_id):
    dbLetsencryptPrivateKey = dbSession.query(LetsencryptPrivateKey)\
        .filter(LetsencryptPrivateKey.id == cert_id)\
        .first()
    return dbLetsencryptPrivateKey


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


def get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__count(dbSession, cert_id):
    counted = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_ca_certificate_id__signed_by == cert_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__paginated(dbSession, cert_id, limit=None, offset=0):
    dbLetsencryptServerCertificates = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_ca_certificate_id__signed_by == cert_id)\
        .order_by(LetsencryptServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptServerCertificates


def get__LetsencryptServerCertificate__by_LetsencryptDomain__count(dbSession, domain_id):
    counted = dbSession.query(LetsencryptServerCertificate)\
        .join(LetsencryptServerCertificate2LetsencryptDomain,
              LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id,
              )\
        .filter(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptDomain__paginated(dbSession, domain_id, limit=None, offset=0):
    dbLetsencryptServerCertificates = dbSession.query(LetsencryptServerCertificate)\
        .join(LetsencryptServerCertificate2LetsencryptDomain,
              LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id,
              )\
        .filter(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .order_by(LetsencryptServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbLetsencryptServerCertificates


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__LetsencryptDomain__by_domainName(dbSession, domain_name):
    dbDomain = dbSession.query(LetsencryptDomain)\
        .filter(sa.func.lower(LetsencryptDomain.domain_name) == sa.func.lower(domain_name))\
        .first()
    if not dbDomain:
        dbDomain = LetsencryptDomain()
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


def getcreate__LetsencryptPrivateKey__by_pem_text(dbSession, key_pem):
    key_pem = acme.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    is_created = False
    dbKey = dbSession.query(LetsencryptPrivateKey)\
        .filter(LetsencryptPrivateKey.key_pem_md5 == key_pem_md5,
                LetsencryptPrivateKey.key_pem == key_pem,
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

        dbKey = LetsencryptPrivateKey()
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
        dbDomain = getcreate__LetsencryptDomain__by_domainName(dbSession, _domain_name)

        dbLetsencryptCertificateRequest2D = LetsencryptCertificateRequest2LetsencryptDomain()
        dbLetsencryptCertificateRequest2D.letsencrypt_certificate_request_id = dbLetsencryptCertificateRequest.id
        dbLetsencryptCertificateRequest2D.letsencrypt_domain_id = dbDomain.id

        dbSession.add(dbLetsencryptCertificateRequest2D)
        dbSession.flush()

    dbSession.flush()

    return dbLetsencryptCertificateRequest


def create__CertificateRequest__FULL(
    dbSession,
    domain_names,
    account_key_pem=None,
    private_key_pem=None,
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
    dbLetsencryptServerCertificate = None
    try:

        account_key_pem = acme.cleanup_pem_text(account_key_pem)
        private_key_pem = acme.cleanup_pem_text(private_key_pem)

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
        tmpfile_domain.write(private_key_pem)
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
            dbPrivateKey, _is_created = getcreate__LetsencryptPrivateKey__by_pem_text(dbSession, private_key_pem)

            dbLetsencryptCertificateRequest = LetsencryptCertificateRequest()
            dbLetsencryptCertificateRequest.is_active = True
            dbLetsencryptCertificateRequest.certificate_request_type_id = LetsencryptCertificateRequestType.FULL
            dbLetsencryptCertificateRequest.timestamp_started = datetime.datetime.utcnow()
            dbLetsencryptCertificateRequest.csr_pem = csr_text
            dbLetsencryptCertificateRequest.csr_pem_md5 = utils.md5_text(csr_text)
            dbLetsencryptCertificateRequest.csr_pem_modulus_md5 = csr_pem_modulus_md5
            dbLetsencryptCertificateRequest.letsencrypt_account_key_id = dbAccountKey.id
            dbLetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by = dbPrivateKey.id
            dbSession.add(dbLetsencryptCertificateRequest)
            dbSession.flush()

            # we'll use this tuple in a bit...
            _domain_objects = {}
            for _domain_name in domain_names:
                dbDomain = getcreate__LetsencryptDomain__by_domainName(dbSession, _domain_name)

                dbLetsencryptCertificateRequest2D = LetsencryptCertificateRequest2LetsencryptDomain()
                dbLetsencryptCertificateRequest2D.letsencrypt_certificate_request_id = dbLetsencryptCertificateRequest.id
                dbLetsencryptCertificateRequest2D.letsencrypt_domain_id = dbDomain.id

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
            if dbPrivateKey not in dbSession:
                dbPrivateKey = dbSession.merge(dbPrivateKey)
            if dbLetsencryptCertificateRequest not in dbSession:
                dbLetsencryptCertificateRequest = dbSession.merge(dbLetsencryptCertificateRequest)
            dbLetsencryptServerCertificate = create__LetsencryptServerCertificate(
                dbSession,
                timestamp_signed = datetime_signed,
                timestamp_expires = datetime_expires,
                is_active = True,
                cert_pem = cert_pem,
                chained_pem = chained_pem,
                chain_name = chain_url,
                letsencrypt_private_key_id__signed_by = dbPrivateKey.id,
                dbLetsencryptCertificateRequest = dbLetsencryptCertificateRequest,
                domains_list__objects = _domain_objects,
            )

        # merge this back in
        if dbLetsencryptServerCertificate:
            if dbLetsencryptServerCertificate not in dbSession:
                dbLetsencryptServerCertificate = dbSession.merge(dbLetsencryptServerCertificate)
        return dbLetsencryptServerCertificate

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


def getcreate__LetsencryptServerCertificate__by_pem_text(
    dbSession,
    cert_pem,
    dbCACertificate=None,
    dbPrivateKey=None,
):
    cert_pem = acme.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    is_created = False
    dbCertificate = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.cert_pem_md5 == cert_pem_md5,
                LetsencryptServerCertificate.cert_pem == cert_pem,
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
            dbCertificate = LetsencryptServerCertificate()

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
            if dbPrivateKey is None:
                raise ValueError('dbPrivateKey is None')
            if dbCertificate.cert_pem_modulus_md5 != dbPrivateKey.key_pem_modulus_md5:
                raise ValueError('dbPrivateKey did not sign the certificate')
            dbCertificate.letsencrypt_private_key_id__signed_by = dbPrivateKey.id

            _subject_domain, _san_domains = acme.parse_cert_domains__segmented(cert_path=_tmpfileCert.name)
            certificate_domain_names = _san_domains
            if _subject_domain is not None and _subject_domain not in certificate_domain_names:
                certificate_domain_names.insert(0, _subject_domain)
            if not certificate_domain_names:
                raise ValueError("could not find any domain names in the certificate")
            if len(certificate_domain_names) == 1:
                dbCertificate.is_single_domain_cert = True
            elif len(certificate_domain_names) > 1:
                dbCertificate.is_single_domain_cert = False

            dbSession.add(dbCertificate)
            dbSession.flush()
            is_created = True

            for _domain_name in certificate_domain_names:

                dbDomain = getcreate__LetsencryptDomain__by_domainName(dbSession, _domain_name)

                dbLetsencryptServerCertificate2LetsencryptDomain = LetsencryptServerCertificate2LetsencryptDomain()
                dbLetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id = dbCertificate.id
                dbLetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id = dbDomain.id
                dbSession.add(dbLetsencryptServerCertificate2LetsencryptDomain)
                dbSession.flush()

        except:
            raise
        finally:
            if _tmpfileCert:
                _tmpfileCert.close()

    return dbCertificate, is_created


def create__LetsencryptServerCertificate(
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
    letsencrypt_private_key_id__signed_by = None,
    privkey_pem = None,
):
    if not any((letsencrypt_private_key_id__signed_by, privkey_pem)) or all((letsencrypt_private_key_id__signed_by, privkey_pem)):
        raise ValueError("create__LetsencryptServerCertificate must accept ONE OF [`letsencrypt_private_key_id__signed_by`, `privkey_pem`]")
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

    dbLetsencryptServerCertificate = LetsencryptServerCertificate()
    dbLetsencryptServerCertificate.timestamp_signed = timestamp_signed
    dbLetsencryptServerCertificate.timestamp_expires = timestamp_signed
    dbLetsencryptServerCertificate.is_active = is_active
    dbLetsencryptServerCertificate.cert_pem = cert_pem
    dbLetsencryptServerCertificate.cert_pem_md5 = utils.md5_text(cert_pem)
    dbLetsencryptServerCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5
    if dbLetsencryptCertificateRequest:
        if dbLetsencryptCertificateRequest not in dbSession:
            dbLetsencryptCertificateRequest = dbSession.merge(dbLetsencryptCertificateRequest)
        dbLetsencryptCertificateRequest.is_active = False
        dbLetsencryptServerCertificate.letsencrypt_certificate_request_id = dbLetsencryptCertificateRequest.id
    dbLetsencryptServerCertificate.letsencrypt_ca_certificate_id__signed_by = letsencrypt_ca_certificate_id__signed_by
    dbLetsencryptServerCertificate.letsencrypt_private_key_id__signed_by = letsencrypt_private_key_id__signed_by
    dbSession.add(dbLetsencryptServerCertificate)
    dbSession.flush()

    for _domain_name in domains_list__objects.keys():
        # we dont' care about the dbLetsencryptCertificateRequest2D
        (domainObject, dbLetsencryptCertificateRequest2D) = domains_list__objects[_domain_name]
        if domainObject not in dbSession:
            domainObject = dbSession.merge(domainObject)
        dbLetsencryptServerCertificate2LetsencryptDomain = LetsencryptServerCertificate2LetsencryptDomain()
        dbLetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id = dbLetsencryptServerCertificate.id
        dbLetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id = domainObject.id
        dbSession.add(dbLetsencryptServerCertificate2LetsencryptDomain)
        dbSession.flush()

    return dbLetsencryptServerCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def ca_certificate_probe(dbSession):
    certs = acme.probe_letsencrypt_certificates()
    certs_discovered = []
    certs_modified = []
    for c in certs:
        _is_created = False
        dbCACertificate = get__LetsencryptCACertificate__by_pem_text(dbSession, c['cert_pem'])
        if not dbCACertificate:
            dbCACertificate, _is_created = getcreate__LetsencryptCACertificate__by_pem_text(dbSession, c['cert_pem'], c['name'])
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
    dbSession.add(dbProbe)
    dbSession.flush()
    return dbProbe

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def operations_update_recents(dbSession):
    if False:
        dbSession.execute("""
            UPDATE letsencrypt_domain
            SET letsencrypt_server_certificate_id__latest_single = (
                SELECT id FROM (
                    SELECT cert.id
                          , max(cert.timestamp_expires)
                          , cert2domain.letsencrypt_domain_id
                    FROM letsencrypt_server_certificate cert
                    JOIN letsencrypt_server_certificate_2_letsencrypt_domain cert2domain
                        ON (cert.id = cert2domain.letsencrypt_server_certificate_id)
                    WHERE cert.is_single_domain_cert = :is_single_domain_cert
                          AND 
                          cert.is_active = :is_active
                    GROUP BY cert2domain.letsencrypt_domain_id
                ) q_inner
                WHERE
                letsencrypt_domain.id = q_inner.letsencrypt_domain_id
            );
        """, {'is_single_domain_cert': True, 'is_active': True})
        dbSession.execute("""
            UPDATE letsencrypt_domain
            SET letsencrypt_server_certificate_id__latest_multi = (
                SELECT id FROM (
                    SELECT cert.id
                          , max(cert.timestamp_expires)
                          , cert2domain.letsencrypt_domain_id
                    FROM letsencrypt_server_certificate cert
                    JOIN letsencrypt_server_certificate_2_letsencrypt_domain cert2domain
                        ON (cert.id = cert2domain.letsencrypt_server_certificate_id)
                    WHERE cert.is_single_domain_cert = :is_single_domain_cert
                          AND 
                          cert.is_active = :is_active
                    GROUP BY cert2domain.letsencrypt_domain_id
                ) q_inner
                WHERE
                letsencrypt_domain.id = q_inner.letsencrypt_domain_id
            );
        """, {'is_single_domain_cert': False, 'is_active': True})
    else:
        # first the single
        _t_domain = LetsencryptDomain.__table__.alias('domain')
        _q_sub = dbSession.query(LetsencryptServerCertificate.id)\
            .join(LetsencryptServerCertificate2LetsencryptDomain,
                  LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id
            )\
            .filter(LetsencryptServerCertificate.is_active is True,  # noqa
                    LetsencryptServerCertificate.timestamp_expires < datetime.datetime.utcnow(),
                    LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == _t_domain.c.id,
                    )\
            .order_by(LetsencryptServerCertificate.timestamp_expires.desc())\
            .limit(1)\
            .subquery()\
            .alias()
            # .alias().select()
            
        dbSession.execute(LetsencryptDomain.__table__
                          .update()
                          .values(letsencrypt_server_certificate_id__latest_single=_q_sub)
                          )
    return True
    
    
def operations_deactivate_expired(dbSession):
    # deactivate expired certificates
    expired_certs = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.is_active is True,  # noqa
                LetsencryptServerCertificate.timestamp_expires < datetime.datetime.utcnow(),
                )\
        .all()
    for c in expired_certs:
        c.is_active = False
    dbSession.flush()
    return len(expired_certs)


def operations_deactivate_duplicates(dbSession, ran_operations_update_recents=None):
    """
    this is kind of weird.
    because we have multiple domains, it is hard to figure out which certs we should use
    the simplest approach is this:
    
    1. cache the most recent certs via `operations_update_recents`
    2. find domains that have multiple active certs
    3. don't turn off any certs that are a latest_single or latest_multi
    """
    if ran_operations_update_recents is not True:
        raise ValueError("MUST run `operations_update_recents` first")
    _q_ids__latest_single = dbSession.query(LetsencryptDomain.letsencrypt_server_certificate_id__latest_single)\
        .distinct()\
        .filter(LetsencryptDomain.letsencrypt_server_certificate_id__latest_single != None,  # noqa
                )\
        .subquery()
    _q_ids__latest_multi = dbSession.query(LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi)\
        .distinct()\
        .filter(LetsencryptDomain.letsencrypt_server_certificate_id__latest_single != None,  # noqa
                )\
        .subquery()

    # now grab the domains with many certs...
    q_inner = dbSession.query(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id,
                              sqlalchemy.func.count(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id).label('counted'),
                              )\
        .join(LetsencryptServerCertificate,
              LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id == LetsencryptServerCertificate.id
              )\
        .filter(LetsencryptServerCertificate.is_active == True,  # noqa
                )\
        .group_by(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id)
    q_inner = q_inner.subquery()
    q_domains = dbSession.query(q_inner)\
        .filter(q_inner.c.counted >= 2)
    result = q_domains.all()
    domain_ids_with_multiple_active_certs = [i.letsencrypt_domain_id for i in result]
    
    _turned_off = []
    for _domain_id in domain_ids_with_multiple_active_certs:
        domain_certs = dbSession.query(LetsencryptServerCertificate)\
            .join(LetsencryptServerCertificate2LetsencryptDomain,
                  LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id,
                  )\
            .filter(LetsencryptServerCertificate.is_active == True,  # noqa
                    LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == _domain_id,
                    LetsencryptServerCertificate.id.notin_(_q_ids__latest_single),
                    LetsencryptServerCertificate.id.notin_(_q_ids__latest_multi),
                    )\
            .order_by(LetsencryptServerCertificate.timestamp_expires.desc())\
            .all()
        if len(domain_certs) > 1:
            for cert in domain_certs[1:]:
                cert.is_active = False
                _turned_off.append(cert)
    return len(_turned_off)
