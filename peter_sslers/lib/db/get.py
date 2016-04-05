# stdlib
import datetime
import logging

# pypi
import sqlalchemy

# localapp
from ...models import *
from .. import cert_utils
from .. import errors
from .. import utils

# setup logging
log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# ==============================================================================


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
                      sqlalchemy.orm.subqueryload('issued_certificates_5').joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                      )
    item = q.first()
    return item


def get__LetsencryptAccountKey__default(dbSession):
    q = dbSession.query(LetsencryptAccountKey)\
        .filter(LetsencryptAccountKey.is_default.op('IS')(True))
    item = q.first()
    return item


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


def get__LetsencryptCACertificate__by_pem_text(dbSession, cert_pem):
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    dbCertificate = dbSession.query(LetsencryptCACertificate)\
        .filter(LetsencryptCACertificate.cert_pem_md5 == cert_pem_md5,
                LetsencryptCACertificate.cert_pem == cert_pem,
                )\
        .first()
    return dbCertificate


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


def get__LetsencryptCertificateRequest__by_LetsencryptDomainId__count(dbSession, domain_id):
    counted = dbSession.query(LetsencryptCertificateRequest)\
        .join(LetsencryptCertificateRequest2LetsencryptDomain,
              LetsencryptCertificateRequest.id == LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id,
              )\
        .filter(LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .count()
    return counted


def get__LetsencryptCertificateRequest__by_LetsencryptDomainId__paginated(dbSession, domain_id, limit=None, offset=0):
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


def get__LetsencryptCertificateRequest__by_LetsencryptUniqueFQDNSetId__count(dbSession, unique_fqdn_set_id):
    counted = dbSession.query(LetsencryptCertificateRequest)\
        .filter(LetsencryptCertificateRequest.letsencrypt_unique_fqdn_set_id == unique_fqdn_set_id)\
        .count()
    return counted


def get__LetsencryptCertificateRequest__by_LetsencryptUniqueFQDNSetId__paginated(dbSession, unique_fqdn_set_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptCertificateRequest)\
        .filter(LetsencryptCertificateRequest.letsencrypt_unique_fqdn_set_id == unique_fqdn_set_id)\
        .order_by(LetsencryptCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


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
                  sqlalchemy.orm.joinedload('latest_certificate_single.unique_fqdn_set'),
                  sqlalchemy.orm.joinedload('latest_certificate_single.unique_fqdn_set.to_domains'),
                  sqlalchemy.orm.joinedload('latest_certificate_single.unique_fqdn_set.to_domains.domain'),

                  sqlalchemy.orm.subqueryload('latest_certificate_multi'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.private_key'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.certificate_upchain'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.unique_fqdn_set'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.unique_fqdn_set.to_domains'),
                  sqlalchemy.orm.joinedload('latest_certificate_multi.unique_fqdn_set.to_domains.domain'),
                  )
    if eagerload_web:
        # need to join back the domains to show alternate domains.
        q = q.options(
            sqlalchemy.orm.subqueryload('domain_to_certificate_requests_5')
            .joinedload('certificate_request')
            .joinedload('certificate_request_to_domains')
            .joinedload('domain'),
            sqlalchemy.orm.subqueryload('certificates_5')
            .joinedload('unique_fqdn_set')
            .joinedload('to_domains')
            .joinedload('domain'),
        )
    return q


def get__LetsencryptDomain__by_id(dbSession, domain_id, preload=False, eagerload_web=False):
    q = dbSession.query(LetsencryptDomain)\
        .filter(LetsencryptDomain.id == domain_id)
    if preload:
        q = _get__LetsencryptDomain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


def get__LetsencryptDomain__by_name(dbSession, domain_name, preload=False, eagerload_web=False):
    q = dbSession.query(LetsencryptDomain)\
        .filter(sa.func.lower(LetsencryptDomain.domain_name) == sa.func.lower(domain_name))
    if preload:
        q = _get__LetsencryptDomain__core(q, preload=preload, eagerload_web=eagerload_web)
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


def get__LetsencryptOperationsEvent__by_id(dbSession, event_id):
    item = dbSession.query(LetsencryptOperationsEvent)\
       .filter(LetsencryptOperationsEvent.id == event_id)\
       .first()
    return item


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
                      sqlalchemy.orm.subqueryload('signed_certificates_5').joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                      )
    item = q.first()
    return item


def get__LetsencryptPrivateKey__current_week(dbSession):
    q = dbSession.query(LetsencryptPrivateKey)\
        .filter(LetsencryptPrivateKey.is_autogenerated_key.op('IS')(True),
                year_week(LetsencryptPrivateKey.timestamp_first_seen) == year_week(utcnow()),
        )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptQueueDomain__count(dbSession, show_processed=False):
    q = dbSession.query(LetsencryptQueueDomain)
    if not show_processed:
        q = q.filter(LetsencryptQueueDomain.timestamp_processed.op('IS')(None),  # noqa
                     )
    counted = q.count()
    return counted


def get__LetsencryptQueueDomain__paginated(dbSession, show_processed=False, eagerload_web=False, limit=None, offset=0):
    q = dbSession.query(LetsencryptQueueDomain)
    if not show_processed:
        q = q.filter(LetsencryptQueueDomain.timestamp_processed.op('IS')(None),  # noqa
                     )
    else:
        q = q.order_by(LetsencryptQueueDomain.id.desc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__LetsencryptQueueDomain__by_id(dbSession, set_id):
    item = dbSession.query(LetsencryptQueueDomain)\
        .filter(LetsencryptQueueDomain.id == set_id)\
        .first()
    return item

def get__LetsencryptQueueDomain__by_name(dbSession, domain_name):
    q = dbSession.query(LetsencryptQueueDomain)\
        .filter(sa.func.lower(LetsencryptQueueDomain.domain_name) == sa.func.lower(domain_name))
    item = q.first()
    return item

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptQueueRenewal__count(dbSession, show_all=False):
    q = dbSession.query(LetsencryptQueueRenewal)
    if not show_all:
        q = q.filter(LetsencryptQueueRenewal.timestamp_processed.op('IS')(None),  # noqa
                     )
    counted = q.count()
    return counted


def get__LetsencryptQueueRenewal__paginated(dbSession, show_all=False, eagerload_web=False, limit=None, offset=0):
    q = dbSession.query(LetsencryptQueueRenewal)
    if not show_all:
        q = q.filter(LetsencryptQueueRenewal.timestamp_processed.op('IS')(None),  # noqa
                     )
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload('certificate').joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                      )
    else:
        q = q.order_by(LetsencryptQueueRenewal.id.desc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__LetsencryptQueueRenewal__by_id(dbSession, set_id):
    item = dbSession.query(LetsencryptQueueRenewal)\
        .filter(LetsencryptQueueRenewal.id == set_id)\
        .options(sqlalchemy.orm.subqueryload('certificate').joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                 )\
        .first()
    return item


def get__LetsencryptQueueRenewal__by_LetsencryptUniqueFQDNSetId__active(dbSession, set_id):
    q = dbSession.query(LetsencryptQueueRenewal)\
        .filter(LetsencryptQueueRenewal.letsencrypt_unique_fqdn_set_id == set_id,
                LetsencryptQueueRenewal.timestamp_processed.op('IS')(None),
                )
    items_paged = q.all()
    return items_paged

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
        q = q.options(sqlalchemy.orm.joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
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
        .options(sqlalchemy.orm.subqueryload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                 )\
        .first()
    return dbLetsencryptServerCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__LetsencryptServerCertificate__by_LetsencryptAccountKeyId__count(dbSession, key_id):
    counted = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_account_key_id == key_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptAccountKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_account_key_id == key_id)\
        .options(sqlalchemy.orm.joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                 )\
        .order_by(LetsencryptServerCertificate.id.desc())\
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
        .join(LetsencryptUniqueFQDNSet,
              LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == LetsencryptUniqueFQDNSet.id
              )\
        .join(LetsencryptUniqueFQDNSet2LetsencryptDomain,
              LetsencryptUniqueFQDNSet.id == LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id,
              )\
        .filter(LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptDomainId__paginated(dbSession, domain_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptServerCertificate)\
        .join(LetsencryptUniqueFQDNSet,
              LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == LetsencryptUniqueFQDNSet.id
              )\
        .join(LetsencryptUniqueFQDNSet2LetsencryptDomain,
              LetsencryptUniqueFQDNSet.id == LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id,
              )\
        .filter(LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
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


def get__LetsencryptServerCertificate__by_LetsencryptUniqueFQDNSetId__count(dbSession, unique_fqdn_set_id):
    counted = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == unique_fqdn_set_id)\
        .count()
    return counted


def get__LetsencryptServerCertificate__by_LetsencryptUniqueFQDNSetId__paginated(dbSession, unique_fqdn_set_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == unique_fqdn_set_id)\
        .order_by(LetsencryptServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__LetsencryptServerCertificate__by_LetsencryptUniqueFQDNSetId__latest_active(dbSession, unique_fqdn_set_id):
    item = dbSession.query(LetsencryptServerCertificate)\
        .filter(LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == unique_fqdn_set_id)\
        .filter(LetsencryptServerCertificate.is_active.op('IS')(True))\
        .order_by(LetsencryptServerCertificate.timestamp_expires.desc())\
        .first()
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


def get__LetsencryptUniqueFQDNSet__by_LetsencryptDomainId__count(dbSession, domain_id):
    counted = dbSession.query(LetsencryptUniqueFQDNSet)\
        .join(LetsencryptUniqueFQDNSet2LetsencryptDomain,
              LetsencryptUniqueFQDNSet.id == LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id,
              )\
        .filter(LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .count()
    return counted


def get__LetsencryptUniqueFQDNSet__by_LetsencryptDomainId__paginated(dbSession, domain_id, limit=None, offset=0):
    items_paged = dbSession.query(LetsencryptUniqueFQDNSet)\
        .join(LetsencryptUniqueFQDNSet2LetsencryptDomain,
              LetsencryptUniqueFQDNSet.id == LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id,
              )\
        .filter(LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id == domain_id)\
        .order_by(LetsencryptUniqueFQDNSet.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged
