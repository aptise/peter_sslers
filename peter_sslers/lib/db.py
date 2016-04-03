# stdlib
import datetime
import json
import logging
import pdb
import tempfile

# pypi
import sqlalchemy
import transaction
from zope.sqlalchemy import mark_changed

# localapp
from ..models import *
from . import acme
from . import cert_utils
from . import letsencrypt_info
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


def _LetsencryptDomain_inject_exipring_days(q, expiring_days, order=False):
    """helper function for the count/paginated queries"""
    LetsencryptServerCertificateMulti = sqlalchemy.orm.aliased(LetsencryptServerCertificate)
    LetsencryptServerCertificateSingle = sqlalchemy.orm.aliased(LetsencryptServerCertificate)
    _until = datetime.datetime.utcnow() + datetime.timedelta(days=expiring_days)
    q = q.outerjoin(LetsencryptServerCertificateMulti,
                    LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi == LetsencryptServerCertificateMulti.id
                    )\
        .outerjoin(LetsencryptServerCertificateSingle,
                   LetsencryptDomain.letsencrypt_server_certificate_id__latest_single == LetsencryptServerCertificateSingle.id
                   )\
        .filter(sqlalchemy.or_(sqlalchemy.and_(LetsencryptServerCertificateMulti.is_active == True,  # noqa
                                               LetsencryptServerCertificateMulti.timestamp_expires <= _until,
                                               ),
                               sqlalchemy.and_(LetsencryptServerCertificateSingle.is_active == True,  # noqa
                                               LetsencryptServerCertificateSingle.timestamp_expires <= _until,
                                               ),
                               )
                )
    if order:
        q = q.order_by(sqlalchemy.func.min(LetsencryptServerCertificateMulti.timestamp_expires,
                                           LetsencryptServerCertificateSingle.timestamp_expires,
                                           ).asc(),
                       )
    return q


def get__LetsencryptDomain__count(dbSession, expiring_days=None, active_only=False):
    q = dbSession.query(LetsencryptDomain)
    if active_only and not expiring_days:
        q = q.filter(sqlalchemy.or_(LetsencryptDomain.letsencrypt_server_certificate_id__latest_single.op('IS NOT')(None),
                                    LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi.op('IS NOT')(None),
                                    ),
                     )
    if expiring_days:
        q = _LetsencryptDomain_inject_exipring_days(q, expiring_days, order=False)
    counted = q.count()
    return counted


def get__LetsencryptDomain__paginated(dbSession, expiring_days=None, eagerload_web=False, limit=None, offset=0, active_only=False):
    q = dbSession.query(LetsencryptDomain)
    if active_only and not expiring_days:
        q = q.filter(sqlalchemy.or_(LetsencryptDomain.letsencrypt_server_certificate_id__latest_single.op('IS NOT')(None),
                                    LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi.op('IS NOT')(None),
                                    ),
                     )
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload('latest_certificate_single'),
                      sqlalchemy.orm.joinedload('latest_certificate_multi'),
                      )
    if expiring_days:
        q = _LetsencryptDomain_inject_exipring_days(q, expiring_days, order=True)
    else:
        q = q.order_by(sa.func.lower(LetsencryptDomain.domain_name).asc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__LetsencryptDomain__core(q, preload=False, eagerload_web=False):
    q = q.options(sqlalchemy.orm.subqueryload('latest_certificate_single'),
                  sqlalchemy.orm.joinedload('latest_certificate_single.private_key'),
                  sqlalchemy.orm.joinedload('latest_certificate_single.certificate_upchain'),
                  sqlalchemy.orm.joinedload('latest_certificate_single.certificate_to_domains'),
                  sqlalchemy.orm.joinedload('latest_certificate_single.certificate_to_domains.domain'),

                  sqlalchemy.orm.subqueryload('latest_certificate_multi'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.private_key'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.certificate_upchain'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.certificate_to_domains'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.certificate_to_domains.domain'),
                  )
    if eagerload_web:
        # need to join back the domains to show alternate domains.
        q = q.options(sqlalchemy.orm.subqueryload('domain_to_certificate_requests_5').joinedload('certificate_request').joinedload('certificate_request_to_domains').joinedload('domain'),
                      sqlalchemy.orm.subqueryload('domain_to_certificates_5').joinedload('certificate').joinedload('certificate_to_domains').joinedload('domain'),
                      )
    return q


def get__LetsencryptDomain__by_id(dbSession, domain_id, preload=False, eagerload_web=False):
    q = dbSession.query(LetsencryptDomain)\
        .filter(LetsencryptDomain.id == domain_id)
    q = _get__LetsencryptDomain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


def get__LetsencryptDomain__by_name(dbSession, domain_name, preload=False, eagerload_web=False):
    q = dbSession.query(LetsencryptDomain)\
        .filter(LetsencryptDomain.domain_name == domain_name)
    q = _get__LetsencryptDomain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptUniqueFQDNSet__count(dbSession):
    q = dbSession.query(LetsencryptUniqueFQDNSet)
    counted = q.count()
    return counted


def get__LetsencryptUniqueFQDNSet__paginated(dbSession, eagerload_web=False, limit=None, offset=0):
    q = dbSession.query(LetsencryptUniqueFQDNSet)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload('to_domains').joinedload('domain'),
                      )
    else:
        q = q.order_by(LetsencryptUniqueFQDNSet.id.desc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__LetsencryptUniqueFQDNSet__by_id(dbSession, set_id):
    item = dbSession.query(LetsencryptUniqueFQDNSet)\
        .filter(LetsencryptUniqueFQDNSet.id == set_id)\
        .options(sqlalchemy.orm.subqueryload('to_domains').joinedload('domain'),
                 )\
        .first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptServerCertificate__count(dbSession, expiring_days=None):
    q = dbSession.query(LetsencryptServerCertificate)
    if expiring_days:
        _until = datetime.datetime.utcnow() + datetime.timedelta(days=expiring_days)
        q = q.filter(LetsencryptServerCertificate.is_active == True,  # noqa
                     LetsencryptServerCertificate.timestamp_expires <= _until,
                     )
    counted = q.count()
    return counted


def get__LetsencryptServerCertificate__paginated(dbSession, expiring_days=None, eagerload_web=False, limit=None, offset=0):
    q = dbSession.query(LetsencryptServerCertificate)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload('certificate_to_domains').joinedload('domain'),
                      )
    if expiring_days:
        _until = datetime.datetime.utcnow() + datetime.timedelta(days=expiring_days)
        q = q.filter(LetsencryptServerCertificate.is_active == True,  # noqa
                     LetsencryptServerCertificate.timestamp_expires <= _until,
                     )\
            .order_by(LetsencryptServerCertificate.timestamp_expires.asc())
    else:
        q = q.order_by(LetsencryptServerCertificate.id.desc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


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
    items_paged = dbSession.query(LetsencryptCertificateRequest)\
        .options(sqlalchemy.orm.joinedload('signed_certificate'),
                 sqlalchemy.orm.subqueryload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .order_by(LetsencryptCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__LetsencryptCertificateRequest__by_id(dbSession, certificate_request_id):
    dbLetsencryptCertificateRequest = dbSession.query(LetsencryptCertificateRequest)\
        .filter(LetsencryptCertificateRequest.id == certificate_request_id)\
        .options(sqlalchemy.orm.joinedload('signed_certificate'),
                 sqlalchemy.orm.subqueryload('certificate_request_to_domains').joinedload('domain'),
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
    items_paged = dbSession.query(LetsencryptCertificateRequest)\
        .join(LetsencryptCertificateRequest2LetsencryptDomain,
              LetsencryptCertificateRequest.id == LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id,
              )\
        .filter(LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .order_by(LetsencryptCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged

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


def get__LetsencryptAccountKey__by_id(dbSession, key_id, eagerload_web=False):
    q = dbSession.query(LetsencryptAccountKey)\
        .filter(LetsencryptAccountKey.id == key_id)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.subqueryload('certificate_requests_5').joinedload('certificate_request_to_domains').joinedload('domain'),
                      sqlalchemy.orm.subqueryload('issued_certificates_5').joinedload('certificate_to_domains').joinedload('domain'),
                      )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptPrivateKey__count(dbSession):
    counted = dbSession.query(LetsencryptPrivateKey).count()
    return counted


def get__LetsencryptPrivateKey__paginated(dbSession, limit=None, offset=0, active_only=False):
    q = dbSession.query(LetsencryptPrivateKey)
    if active_only:
        q = q.filter(LetsencryptPrivateKey.count_active_certificates >= 1)
    q = q.order_by(LetsencryptPrivateKey.id.desc())\
        .limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__LetsencryptPrivateKey__by_id(dbSession, cert_id, eagerload_web=False):
    q = dbSession.query(LetsencryptPrivateKey)\
        .filter(LetsencryptPrivateKey.id == cert_id)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.subqueryload('certificate_requests_5').joinedload('certificate_request_to_domains').joinedload('domain'),
                      sqlalchemy.orm.subqueryload('signed_certificates_5').joinedload('certificate_to_domains').joinedload('domain'),
                      )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptOperationsEvent__count(dbSession, event_type_ids=None):
    q = dbSession.query(LetsencryptOperationsEvent)
    if event_type_ids is not None:
        q = q.filter(LetsencryptOperationsEvent.letsencrypt_operations_event_type_id.in_(event_type_ids))
    items_count = q.count()
    return items_count


def get__LetsencryptOperationsEvent__paginated(dbSession, event_type_ids=None, limit=None, offset=0):
    q = dbSession.query(LetsencryptOperationsEvent)
    if event_type_ids is not None:
        q = q.filter(LetsencryptOperationsEvent.letsencrypt_operations_event_type_id.in_(event_type_ids))
    items_paged = q.order_by(LetsencryptOperationsEvent.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptOperationsEvent__certificate_probe__count(dbSession):
    counted = dbSession.query(LetsencryptOperationsEvent)\
        .filter(LetsencryptOperationsEvent.letsencrypt_operations_event_type_id == LetsencryptOperationsEventType.ca_certificate_probe,
                )\
        .count()
    return counted


def get__LetsencryptOperationsEvent__certificate_probe__paginated(dbSession, limit=None, offset=0):
    paged_items = dbSession.query(LetsencryptOperationsEvent)\
        .order_by(LetsencryptOperationsEvent.id.desc())\
        .filter(LetsencryptOperationsEvent.letsencrypt_operations_event_type_id == LetsencryptOperationsEventType.ca_certificate_probe,
                )\
        .limit(limit)\
        .offset(offset)\
        .all()
    return paged_items


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptCACertificate__count(dbSession):
    counted = dbSession.query(LetsencryptCACertificate).count()
    return counted


def get__LetsencryptCACertificate__paginated(dbSession, limit=None, offset=0, active_only=False):
    q = dbSession.query(LetsencryptCACertificate)
    if active_only:
        q = q.filter(LetsencryptCACertificate.count_active_certificates >= 1)
    q = q.order_by(LetsencryptCACertificate.id.desc())\
        .limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__LetsencryptCACertificate__by_id(dbSession, cert_id):
    dbLetsencryptCACertificate = dbSession.query(LetsencryptCACertificate)\
        .filter(LetsencryptCACertificate.id == cert_id)\
        .first()
    return dbLetsencryptCACertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptCertificateRequest__by_LetsencryptAccountKeyId__count(dbSession, key_id):
    counted = dbSession.query(LetsencryptCertificateRequest)\
        .filter(LetsencryptCertificateRequest.letsencrypt_account_key_id == key_id)\
        .count()
    return counted


def get__LetsencryptCertificateRequest__by_LetsencryptAccountKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptCertificateRequest)\
        .filter(LetsencryptCertificateRequest.letsencrypt_account_key_id == key_id)\
        .options(sqlalchemy.orm.joinedload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .order_by(LetsencryptCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__LetsencryptCertificateRequest__by_LetsencryptPrivateKeyId__count(dbSession, key_id):
    counted = dbSession.query(LetsencryptCertificateRequest)\
        .filter(LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by == key_id)\
        .count()
    return counted


def get__LetsencryptCertificateRequest__by_LetsencryptPrivateKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptCertificateRequest)\
        .filter(LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by == key_id)\
        .options(sqlalchemy.orm.joinedload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .order_by(LetsencryptCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__count(dbSession, cert_id):
    counted = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_ca_certificate_id__upchain == cert_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__paginated(dbSession, cert_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_ca_certificate_id__upchain == cert_id)\
        .order_by(LetsencryptServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptServerCertificate__by_LetsencryptDomainId__count(dbSession, domain_id):
    counted = dbSession.query(LetsencryptServerCertificate)\
        .join(LetsencryptServerCertificate2LetsencryptDomain,
              LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id,
              )\
        .filter(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptDomainId__paginated(dbSession, domain_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptServerCertificate)\
        .join(LetsencryptServerCertificate2LetsencryptDomain,
              LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id,
              )\
        .filter(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .order_by(LetsencryptServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__LetsencryptServerCertificate__by_LetsencryptAccountKeyId__count(dbSession, key_id):
    counted = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_account_key_id == key_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptAccountKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_account_key_id == key_id)\
        .options(sqlalchemy.orm.joinedload('certificate_to_domains').joinedload('domain'),
                 )\
        .order_by(LetsencryptServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__LetsencryptServerCertificate__by_LetsencryptPrivateKeyId__count(dbSession, key_id):
    counted = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_private_key_id__signed_by == key_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptPrivateKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_private_key_id__signed_by == key_id)\
        .order_by(LetsencryptServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


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
    key_pem = cert_utils.cleanup_pem_text(key_pem)
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
            cert_utils.validate_key__pem_filepath(_tmpfile.name)

            # grab the modulus
            key_pem_modulus_md5 = cert_utils.modulus_md5_key__pem_filepath(_tmpfile.name)
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
    key_pem = cert_utils.cleanup_pem_text(key_pem)
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
            cert_utils.validate_key__pem_filepath(_tmpfile.name)

            # grab the modulus
            key_pem_modulus_md5 = cert_utils.modulus_md5_key__pem_filepath(_tmpfile.name)
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
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    dbCertificate = dbSession.query(LetsencryptCACertificate)\
        .filter(LetsencryptCACertificate.cert_pem_md5 == cert_pem_md5,
                LetsencryptCACertificate.cert_pem == cert_pem,
                )\
        .first()
    return dbCertificate


def getcreate__LetsencryptCACertificate__by_pem_text(
    dbSession,
    cert_pem,
    chain_name,
    le_authority_name = None,
    is_authority_certificate = None,
    is_cross_signed_authority_certificate = None,
):
    dbCertificate = get__LetsencryptCACertificate__by_pem_text(dbSession, cert_pem)
    is_created = False
    if not dbCertificate:
        cert_pem = cert_utils.cleanup_pem_text(cert_pem)
        cert_pem_md5 = utils.md5_text(cert_pem)
        try:
            _tmpfile = tempfile.NamedTemporaryFile()
            _tmpfile.write(cert_pem)
            _tmpfile.seek(0)

            # validate
            cert_utils.validate_cert__pem_filepath(_tmpfile.name)

            # grab the modulus
            cert_pem_modulus_md5 = cert_utils.modulus_md5_cert__pem_filepath(_tmpfile.name)

            dbCertificate = LetsencryptCACertificate()
            dbCertificate.name = chain_name or 'unknown'

            dbCertificate.le_authority_name = le_authority_name
            dbCertificate.is_ca_certificate = True
            dbCertificate.is_authority_certificate = is_authority_certificate
            dbCertificate.is_cross_signed_authority_certificate = is_cross_signed_authority_certificate
            dbCertificate.id_cross_signed_of = None
            dbCertificate.timestamp_first_seen = datetime.datetime.utcnow()
            dbCertificate.cert_pem = cert_pem
            dbCertificate.cert_pem_md5 = cert_pem_md5
            dbCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

            dbCertificate.timestamp_signed = cert_utils.parse_startdate_cert__pem_filepath(_tmpfile.name)
            dbCertificate.timestamp_expires = cert_utils.parse_enddate_cert__pem_filepath(_tmpfile.name)
            dbCertificate.cert_subject = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-subject')
            dbCertificate.cert_subject_hash = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-subject_hash')
            dbCertificate.cert_issuer = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-issuer')
            dbCertificate.cert_issuer_hash = cert_utils.cert_single_op__pem_filepath(_tmpfile.name, '-issuer_hash')

            dbSession.add(dbCertificate)
            dbSession.flush()
            is_created = True
        except:
            raise
        finally:
            _tmpfile.close()

    return dbCertificate, is_created


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


def do__LetsencryptAccountKey_authenticate(dbSession, dbLetsencryptAccountKey, account_key_path=None):
    _tmpfile = None
    try:
        if account_key_path is None:
            _tmpfile = tempfile.NamedTemporaryFile()
            _tmpfile.write(dbLetsencryptAccountKey.key_pem)
            _tmpfile.seek(0)
            account_key_path = _tmpfile.name

        # parse account key to get public key
        header, thumbprint = acme.account_key__header_thumbprint(account_key_path=account_key_path, )

        acme.acme_register_account(header,
                                   account_key_path=account_key_path)

        # this would raise if we couldn't authenticate

        dbLetsencryptAccountKey.timestamp_last_authenticated = datetime.datetime.utcnow()
        dbSession.flush()

        return True

    finally:
        if _tmpfile:
            _tmpfile.close()

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

    dbAccountKey=None,
    account_key_pem=None,

    dbPrivateKey=None,
    private_key_pem=None,

    letsencrypt_server_certificate_id__renewal_of=None,
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
    dbLetsencryptCertificateRequest = None
    dbLetsencryptServerCertificate = None
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
            dbAccountKey, _is_created = getcreate__LetsencryptAccountKey__by_pem_text(dbSession, account_key_pem)
        else:
            account_key_pem = dbAccountKey.key_pem
        # we need to use tmpfiles on the disk
        tmpfile_account = tempfile.NamedTemporaryFile()
        tmpfile_account.write(account_key_pem)
        tmpfile_account.seek(0)
        tmpfiles.append(tmpfile_account)

        if dbPrivateKey is None:
            private_key_pem = cert_utils.cleanup_pem_text(private_key_pem)
            dbPrivateKey, _is_created = getcreate__LetsencryptPrivateKey__by_pem_text(dbSession, private_key_pem)
        else:
            private_key_pem = dbPrivateKey.key_pem
        # we need to use tmpfiles on the disk
        tmpfile_pkey = tempfile.NamedTemporaryFile()
        tmpfile_pkey.write(private_key_pem)
        tmpfile_pkey.seek(0)
        tmpfiles.append(tmpfile_pkey)

        # make the CSR
        csr_text = acme.new_csr_for_domain_names(domain_names, tmpfile_pkey.name, tmpfiles)

        # store the csr_text in a tmpfile
        tmpfile_csr = tempfile.NamedTemporaryFile()
        tmpfile_csr.write(csr_text)
        tmpfile_csr.seek(0)
        tmpfiles.append(tmpfile_csr)

        # validate
        cert_utils.validate_csr__pem_filepath(tmpfile_csr.name)

        # grab the modulus
        csr_pem_modulus_md5 = cert_utils.modulus_md5_csr__pem_filepath(tmpfile_csr.name)

        # these MUST commit
        with transaction.manager as tx:

            # have we seen these certificates before?
            dbLetsencryptCertificateRequest = LetsencryptCertificateRequest()
            dbLetsencryptCertificateRequest.is_active = True
            dbLetsencryptCertificateRequest.certificate_request_type_id = LetsencryptCertificateRequestType.FULL
            dbLetsencryptCertificateRequest.timestamp_started = datetime.datetime.utcnow()
            dbLetsencryptCertificateRequest.csr_pem = csr_text
            dbLetsencryptCertificateRequest.csr_pem_md5 = utils.md5_text(csr_text)
            dbLetsencryptCertificateRequest.csr_pem_modulus_md5 = csr_pem_modulus_md5

            # note account/private keys
            dbLetsencryptCertificateRequest.letsencrypt_account_key_id = dbAccountKey.id
            dbLetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by = dbPrivateKey.id
            dbLetsencryptCertificateRequest.letsencrypt_server_certificate_id__renewal_of = letsencrypt_server_certificate_id__renewal_of

            dbSession.add(dbLetsencryptCertificateRequest)
            dbSession.flush()

            # increment account/private key counts
            dbAccountKey.count_certificate_requests += 1
            dbPrivateKey.count_certificate_requests += 1
            t_now = datetime.datetime.utcnow()
            if not dbAccountKey.timestamp_last_certificate_request or (dbAccountKey.timestamp_last_certificate_request < t_now):
                dbAccountKey.timestamp_last_certificate_request = t_now
            if not dbPrivateKey.timestamp_last_certificate_request or (dbPrivateKey.timestamp_last_certificate_request < t_now):
                dbPrivateKey.timestamp_last_certificate_request = t_now

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
        csr_domains = cert_utils.parse_csr_domains(csr_path=tmpfile_csr.name,
                                                   submitted_domain_names=domain_names,
                                                   )

        # register the account / ensure that it is registered
        if not dbAccountKey.timestamp_last_authenticated:
            do__LetsencryptAccountKey_authenticate(dbSession,
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
            if dbAccountKey not in dbSession:
                dbAccountKey = dbSession.merge(dbAccountKey)
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
                dbLetsencryptCertificateRequest = dbLetsencryptCertificateRequest,
                dbLetsencryptAccountKey = dbAccountKey,
                dbLetsencryptPrivateKey = dbPrivateKey,
                domains_list__objects = _domain_objects,
                letsencrypt_server_certificate_id__renewal_of = letsencrypt_server_certificate_id__renewal_of,
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
    dbAccountKey=None,
    dbPrivateKey=None,
    letsencrypt_server_certificate_id__renewal_of=None,
):
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    is_created = False
    dbCertificate = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.cert_pem_md5 == cert_pem_md5,
                LetsencryptServerCertificate.cert_pem == cert_pem,
                )\
        .first()
    if dbCertificate:
        if dbPrivateKey and (dbCertificate.letsencrypt_private_key_id__signed_by != dbPrivateKey.id):
            if dbCertificate.letsencrypt_private_key_id__signed_by:
                raise ValueError("Integrity Error. Competing PrivateKey (!?)")
            elif dbCertificate.letsencrypt_private_key_id__signed_by is None:
                dbCertificate.letsencrypt_private_key_id__signed_by = dbPrivateKey.id
                dbPrivateKey.count_certificates_issued += 1
                if not dbPrivateKey.timestamp_last_certificate_issue or (dbPrivateKey.timestamp_last_certificate_issue < dbCertificate.timestamp_signed):
                    dbPrivateKey.timestamp_last_certificate_issue = dbCertificate.timestamp_signed
                dbSession.flush()
        if dbAccountKey and (dbCertificate.letsencrypt_account_key_id != dbAccountKey.id):
            if dbCertificate.letsencrypt_account_key_id:
                raise ValueError("Integrity Error. Competing AccountKey (!?)")
            elif dbCertificate.letsencrypt_account_key_id is None:
                dbCertificate.letsencrypt_account_key_id = dbAccountKey.id
                dbAccountKey.count_certificates_issued += 1
                if not dbAccountKey.timestamp_last_certificate_issue or (dbAccountKey.timestamp_last_certificate_issue < dbCertificate.timestamp_signed):
                    dbAccountKey.timestamp_last_certificate_issue = dbAccountKey.timestamp_signed
                dbSession.flush()
    elif not dbCertificate:
        _tmpfileCert = None
        try:
            _tmpfileCert = tempfile.NamedTemporaryFile()
            _tmpfileCert.write(cert_pem)
            _tmpfileCert.seek(0)

            # validate
            cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

            dbCertificate = LetsencryptServerCertificate()
            _certificate_parse_to_record(_tmpfileCert, dbCertificate)

            dbCertificate.is_active = True
            dbCertificate.cert_pem = cert_pem
            dbCertificate.cert_pem_md5 = cert_pem_md5

            dbCertificate.letsencrypt_server_certificate_id__renewal_of = letsencrypt_server_certificate_id__renewal_of

            # this is the LetsEncrypt key
            if dbCACertificate is None:
                raise ValueError('dbCACertificate is None')
            # we should make sure it issued the certificate:
            if dbCertificate.cert_issuer_hash != dbCACertificate.cert_subject_hash:
                raise ValueError('dbCACertificate did not sign the certificate')
            dbCertificate.letsencrypt_ca_certificate_id__upchain = dbCACertificate.id

            # this is the private key
            # we should make sure it signed the certificate
            # the md5 check isn't exact, BUT ITS CLOSE
            if dbPrivateKey is None:
                raise ValueError('dbPrivateKey is None')
            if dbCertificate.cert_pem_modulus_md5 != dbPrivateKey.key_pem_modulus_md5:
                raise ValueError('dbPrivateKey did not sign the certificate')
            dbCertificate.letsencrypt_private_key_id__signed_by = dbPrivateKey.id
            dbPrivateKey.count_certificates_issued += 1
            if not dbPrivateKey.timestamp_last_certificate_issue or (dbPrivateKey.timestamp_last_certificate_issue < dbCertificate.timestamp_signed):
                dbPrivateKey.timestamp_last_certificate_issue = dbCertificate.timestamp_signed

            # did we submit an account key?
            if dbAccountKey:
                dbCertificate.letsencrypt_account_key_id = dbAccountKey.id
                dbAccountKey.count_certificates_issued += 1
                if not dbAccountKey.timestamp_last_certificate_issue or (dbAccountKey.timestamp_last_certificate_issue < dbAccountKey.timestamp_signed):
                    dbAccountKey.timestamp_last_certificate_issue = dbCertificate.timestamp_signed

            _subject_domain, _san_domains = cert_utils.parse_cert_domains__segmented(cert_path=_tmpfileCert.name)
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
    dbLetsencryptAccountKey = None,
    domains_list__objects = None,
    letsencrypt_server_certificate_id__renewal_of = None,

    # only one of these 2
    dbLetsencryptPrivateKey = None,
    privkey_pem = None,
):
    if not any((dbLetsencryptPrivateKey, privkey_pem)) or all((dbLetsencryptPrivateKey, privkey_pem)):
        raise ValueError("create__LetsencryptServerCertificate must accept ONE OF [`dbLetsencryptPrivateKey`, `privkey_pem`]")
    if privkey_pem:
        raise ValueError("need to figure this out; might not need it")

    # we need to figure this out; it's the chained_pem
    # letsencrypt_ca_certificate_id__upchain
    dbCACertificate, _is_created_cert = getcreate__LetsencryptCACertificate__by_pem_text(dbSession, chained_pem, chain_name)
    letsencrypt_ca_certificate_id__upchain = dbCACertificate.id

    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    try:
        _tmpfileCert = tempfile.NamedTemporaryFile()
        _tmpfileCert.write(cert_pem)
        _tmpfileCert.seek(0)

        # validate
        cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

        dbLetsencryptServerCertificate = LetsencryptServerCertificate()
        _certificate_parse_to_record(_tmpfileCert, dbLetsencryptServerCertificate)

        # we don't need these anymore, because we're parsing the cert
        # dbLetsencryptServerCertificate.timestamp_signed = timestamp_signed
        # dbLetsencryptServerCertificate.timestamp_expires = timestamp_signed

        dbLetsencryptServerCertificate.is_active = is_active
        dbLetsencryptServerCertificate.cert_pem = cert_pem
        dbLetsencryptServerCertificate.cert_pem_md5 = utils.md5_text(cert_pem)
        if dbLetsencryptCertificateRequest:
            if dbLetsencryptCertificateRequest not in dbSession:
                dbLetsencryptCertificateRequest = dbSession.merge(dbLetsencryptCertificateRequest)
            dbLetsencryptCertificateRequest.is_active = False
            dbLetsencryptServerCertificate.letsencrypt_certificate_request_id = dbLetsencryptCertificateRequest.id
        dbLetsencryptServerCertificate.letsencrypt_ca_certificate_id__upchain = letsencrypt_ca_certificate_id__upchain
        dbLetsencryptServerCertificate.letsencrypt_server_certificate_id__renewal_of = letsencrypt_server_certificate_id__renewal_of

        # note account/private keys
        dbLetsencryptServerCertificate.letsencrypt_account_key_id = dbLetsencryptAccountKey.id
        dbLetsencryptServerCertificate.letsencrypt_private_key_id__signed_by = dbLetsencryptPrivateKey.id

        dbSession.add(dbLetsencryptServerCertificate)
        dbSession.flush()

        # increment account/private key counts
        dbLetsencryptAccountKey.count_certificates_issued += 1
        dbLetsencryptPrivateKey.count_certificates_issued += 1
        if not dbLetsencryptAccountKey.timestamp_last_certificate_issue or (dbLetsencryptAccountKey.timestamp_last_certificate_issue < timestamp_signed):
            dbLetsencryptAccountKey.timestamp_last_certificate_issue = timestamp_signed
        if not dbLetsencryptPrivateKey.timestamp_last_certificate_issue or (dbLetsencryptPrivateKey.timestamp_last_certificate_issue < timestamp_signed):
            dbLetsencryptPrivateKey.timestamp_last_certificate_issue = timestamp_signed

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

    except:
        raise
    finally:
        _tmpfileCert.close()

    return dbLetsencryptServerCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def upload__LetsencryptCACertificateBundle__by_pem_text(dbSession, bundle_data):
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

        dbCACertificate, is_created = getcreate__LetsencryptCACertificate__by_pem_text(
            dbSession,
            cert_pem_text,
            cert_name,
            le_authority_name = None,
            is_authority_certificate = None,
            is_cross_signed_authority_certificate = None,
        )
        if not is_created:
            if dbCACertificate.name in ('unknown', 'manual upload'):
                dbCACertificate.name = cert_name
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.le_authority_name = le_authority_name
            if dbCACertificate.is_authority_certificate is None:
                dbCACertificate.is_authority_certificate = is_authority_certificate
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.is_cross_signed_authority_certificate = is_cross_signed_authority_certificate

        results[cert_pem] = (dbCACertificate, is_created)

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def ca_certificate_probe(dbSession):
    certs = letsencrypt_info.probe_letsencrypt_certificates()
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
    dbEvent = create__LetsencryptOperationsEvent(dbSession,
                                                 LetsencryptOperationsEventType.ca_certificate_probe,
                                                 {'is_certificates_discovered': True if certs_discovered else False,
                                                  'is_certificates_updated': True if certs_modified else False,
                                                  'v': 1,
                                                  }
                                                 )

    return dbEvent

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_update_recents(dbSession):

    # first the single
    # _t_domain = LetsencryptDomain.__table__.alias('domain')
    _q_sub = dbSession.query(LetsencryptServerCertificate.id)\
        .join(LetsencryptServerCertificate2LetsencryptDomain,
              LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id
        )\
        .filter(LetsencryptServerCertificate.is_active == True,  # noqa
                LetsencryptServerCertificate.is_single_domain_cert == True,  # noqa
                LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == LetsencryptDomain.id,
                )\
        .order_by(LetsencryptServerCertificate.timestamp_expires.desc())\
        .subquery()\
        .as_scalar()
    dbSession.execute(LetsencryptDomain.__table__
                      .update()
                      .values(letsencrypt_server_certificate_id__latest_single=_q_sub)
                      )

    # then the multiple
    # _t_domain = LetsencryptDomain.__table__.alias('domain')
    _q_sub = dbSession.query(LetsencryptServerCertificate.id)\
        .join(LetsencryptServerCertificate2LetsencryptDomain,
              LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id
        )\
        .filter(LetsencryptServerCertificate.is_active == True,  # noqa
                LetsencryptServerCertificate.is_single_domain_cert == False,  # noqa
                LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == LetsencryptDomain.id,
                )\
        .order_by(LetsencryptServerCertificate.timestamp_expires.desc())\
        .subquery()\
        .as_scalar()
    dbSession.execute(LetsencryptDomain.__table__
                      .update()
                      .values(letsencrypt_server_certificate_id__latest_multi=_q_sub)
                      )

    # update the count of active certs
    LetsencryptServerCertificate1 = sqlalchemy.orm.aliased(LetsencryptServerCertificate)
    LetsencryptServerCertificate2 = sqlalchemy.orm.aliased(LetsencryptServerCertificate)
    _q_sub = dbSession.query(sqlalchemy.func.count(LetsencryptDomain.id))\
        .outerjoin(LetsencryptServerCertificate1,
                   LetsencryptDomain.letsencrypt_server_certificate_id__latest_single == LetsencryptServerCertificate1.id
                   )\
        .outerjoin(LetsencryptServerCertificate2,
                   LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi == LetsencryptServerCertificate2.id
                   )\
        .filter(sqlalchemy.or_(LetsencryptCACertificate.id == LetsencryptServerCertificate1.letsencrypt_ca_certificate_id__upchain,
                               LetsencryptCACertificate.id == LetsencryptServerCertificate2.letsencrypt_ca_certificate_id__upchain,
                               ),
                )\
        .subquery()\
        .as_scalar()
    dbSession.execute(LetsencryptCACertificate.__table__
                      .update()
                      .values(count_active_certificates=_q_sub)
                      )

    # update the count of active PrivateKeys
    LetsencryptServerCertificate1 = sqlalchemy.orm.aliased(LetsencryptServerCertificate)
    LetsencryptServerCertificate2 = sqlalchemy.orm.aliased(LetsencryptServerCertificate)
    _q_sub = dbSession.query(sqlalchemy.func.count(LetsencryptDomain.id))\
        .outerjoin(LetsencryptServerCertificate1,
                   LetsencryptDomain.letsencrypt_server_certificate_id__latest_single == LetsencryptServerCertificate1.id
                   )\
        .outerjoin(LetsencryptServerCertificate2,
                   LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi == LetsencryptServerCertificate2.id
                   )\
        .filter(sqlalchemy.or_(LetsencryptPrivateKey.id == LetsencryptServerCertificate1.letsencrypt_private_key_id__signed_by,
                               LetsencryptPrivateKey.id == LetsencryptServerCertificate2.letsencrypt_private_key_id__signed_by,
                               ),
                )\
        .subquery()\
        .as_scalar()
    dbSession.execute(LetsencryptPrivateKey.__table__
                      .update()
                      .values(count_active_certificates=_q_sub)
                      )

    # the following works, but this is currently tracked
    if False:
        # update the counts on Account Keys
        _q_sub_req = dbSession.query(sqlalchemy.func.count(LetsencryptCertificateRequest.id))\
            .filter(LetsencryptCertificateRequest.letsencrypt_account_key_id == LetsencryptAccountKey.id,
                    )\
            .subquery()\
            .as_scalar()
        dbSession.execute(LetsencryptAccountKey.__table__
                          .update()
                          .values(count_certificate_requests=_q_sub_req,
                                  # count_certificates_issued=_q_sub_iss,
                                  )
                          )
        # update the counts on Private Keys
        _q_sub_req = dbSession.query(sqlalchemy.func.count(LetsencryptCertificateRequest.id))\
            .filter(LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by == LetsencryptPrivateKey.id,
                    )\
            .subquery()\
            .as_scalar()
        _q_sub_iss = dbSession.query(sqlalchemy.func.count(LetsencryptServerCertificate.id))\
            .filter(LetsencryptServerCertificate.letsencrypt_private_key_id__signed_by == LetsencryptPrivateKey.id,
                    )\
            .subquery()\
            .as_scalar()

        dbSession.execute(LetsencryptPrivateKey.__table__
                          .update()
                          .values(count_certificate_requests=_q_sub_req,
                                  count_certificates_issued=_q_sub_iss,
                                  )
                          )

    # should we do the timestamps?
    """
    UPDATE letsencrypt_account_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM letsencrypt_certificate_request
    WHERE letsencrypt_certificate_request.letsencrypt_account_key_id = letsencrypt_account_key.id);

    UPDATE letsencrypt_account_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM letsencrypt_server_certificate
    WHERE letsencrypt_server_certificate.letsencrypt_account_key_id = letsencrypt_account_key.id);

    UPDATE letsencrypt_private_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM letsencrypt_certificate_request
    WHERE letsencrypt_certificate_request.letsencrypt_private_key_id__signed_by = letsencrypt_private_key.id);

    UPDATE letsencrypt_private_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM letsencrypt_server_certificate
    WHERE letsencrypt_server_certificate.letsencrypt_private_key_id__signed_by = letsencrypt_private_key.id);
    """

    # mark the session changed, but we need to mark the session not scoped session.  ugh.
    # we don't need this if we add the bookkeeping object, but let's just keep this to be safe
    mark_changed(dbSession())

    # bookkeeping
    dbEvent = create__LetsencryptOperationsEvent(dbSession,
                                                 LetsencryptOperationsEventType.update_recents,
                                                 {'v': 1,
                                                  }
                                                 )
    return dbEvent


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

    # bookkeeping
    dbEvent = create__LetsencryptOperationsEvent(dbSession,
                                                 LetsencryptOperationsEventType.deactivate_expired,
                                                 {'count_deactivated': len(expired_certs),
                                                  'v': 1,
                                                  }
                                                 )
    return dbEvent


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

    # bookkeeping
    dbEvent = create__LetsencryptOperationsEvent(dbSession,
                                                 LetsencryptOperationsEventType.deactivate_duplicate,
                                                 {'count_deactivated': len(_turned_off),
                                                  'v': 1,
                                                  }
                                                 )
    return dbEvent


def create__LetsencryptOperationsEvent(dbSession, event_type_id, event_payload_dict):
    # bookkeeping
    dbEvent = LetsencryptOperationsEvent()
    dbEvent.letsencrypt_operations_event_type_id = event_type_id
    dbEvent.timestamp_operation = datetime.datetime.utcnow()
    dbEvent.event_payload = json.dumps(event_payload_dict)
    dbSession.add(dbEvent)
    dbSession.flush()
    return dbEvent
