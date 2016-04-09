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


def get__SslLetsEncryptAccountKey__count(dbSession):
    counted = dbSession.query(SslLetsEncryptAccountKey).count()
    return counted


def get__SslLetsEncryptAccountKey__paginated(dbSession, limit=None, offset=0):
    dbSslLetsEncryptAccountKeys = dbSession.query(SslLetsEncryptAccountKey)\
        .order_by(SslLetsEncryptAccountKey.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return dbSslLetsEncryptAccountKeys


def get__SslLetsEncryptAccountKey__by_id(dbSession, key_id, eagerload_web=False):
    q = dbSession.query(SslLetsEncryptAccountKey)\
        .filter(SslLetsEncryptAccountKey.id == key_id)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.subqueryload('certificate_requests_5').joinedload('certificate_request_to_domains').joinedload('domain'),
                      sqlalchemy.orm.subqueryload('issued_certificates_5').joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                      )
    item = q.first()
    return item


def get__SslLetsEncryptAccountKey__default(dbSession):
    q = dbSession.query(SslLetsEncryptAccountKey)\
        .filter(SslLetsEncryptAccountKey.is_default.op('IS')(True))
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslCaCertificate__count(dbSession):
    counted = dbSession.query(SslCaCertificate).count()
    return counted


def get__SslCaCertificate__paginated(dbSession, limit=None, offset=0, active_only=False):
    q = dbSession.query(SslCaCertificate)
    if active_only:
        q = q.filter(SslCaCertificate.count_active_certificates >= 1)
    q = q.order_by(SslCaCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslCaCertificate__by_id(dbSession, cert_id):
    dbSslCaCertificate = dbSession.query(SslCaCertificate)\
        .filter(SslCaCertificate.id == cert_id)\
        .first()
    return dbSslCaCertificate


def get__SslCaCertificate__by_pem_text(dbSession, cert_pem):
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    dbCertificate = dbSession.query(SslCaCertificate)\
        .filter(SslCaCertificate.cert_pem_md5 == cert_pem_md5,
                SslCaCertificate.cert_pem == cert_pem,
                )\
        .first()
    return dbCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslCertificateRequest__count(dbSession):
    counted = dbSession.query(SslCertificateRequest).count()
    return counted


def get__SslCertificateRequest__paginated(dbSession, limit=None, offset=0):
    items_paged = dbSession.query(SslCertificateRequest)\
        .options(sqlalchemy.orm.joinedload('signed_certificate'),
                 sqlalchemy.orm.subqueryload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .order_by(SslCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__SslCertificateRequest__by_id(dbSession, certificate_request_id):
    dbSslCertificateRequest = dbSession.query(SslCertificateRequest)\
        .filter(SslCertificateRequest.id == certificate_request_id)\
        .options(sqlalchemy.orm.joinedload('signed_certificate'),
                 sqlalchemy.orm.subqueryload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .one()
    return dbSslCertificateRequest


def get__SslCertificateRequest__by_pem_text(dbSession, csr_pem):
    csr_pem = cert_utils.cleanup_pem_text(csr_pem)
    csr_pem_md5 = utils.md5_text(csr_pem)
    dbCertificateRequest = dbSession.query(SslCertificateRequest)\
        .filter(SslCertificateRequest.csr_pem_md5 == csr_pem_md5,
                SslCertificateRequest.csr_pem == csr_pem,
                )\
        .first()
    return dbCertificateRequest


def get__SslCertificateRequest__by_SslLetsEncryptAccountKeyId__count(dbSession, key_id):
    counted = dbSession.query(SslCertificateRequest)\
        .filter(SslCertificateRequest.ssl_letsencrypt_account_key_id == key_id)\
        .count()
    return counted


def get__SslCertificateRequest__by_SslLetsEncryptAccountKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(SslCertificateRequest)\
        .filter(SslCertificateRequest.ssl_letsencrypt_account_key_id == key_id)\
        .options(sqlalchemy.orm.joinedload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .order_by(SslCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__SslCertificateRequest__by_SslDomainId__count(dbSession, domain_id):
    counted = dbSession.query(SslCertificateRequest)\
        .join(SslCertificateRequest2SslDomain,
              SslCertificateRequest.id == SslCertificateRequest2SslDomain.ssl_certificate_request_id,
              )\
        .filter(SslCertificateRequest2SslDomain.ssl_domain_id == domain_id)\
        .count()
    return counted


def get__SslCertificateRequest__by_SslDomainId__paginated(dbSession, domain_id, limit=None, offset=0):
    items_paged = dbSession.query(SslCertificateRequest)\
        .join(SslCertificateRequest2SslDomain,
              SslCertificateRequest.id == SslCertificateRequest2SslDomain.ssl_certificate_request_id,
              )\
        .filter(SslCertificateRequest2SslDomain.ssl_domain_id == domain_id)\
        .order_by(SslCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__SslCertificateRequest__by_SslPrivateKeyId__count(dbSession, key_id):
    counted = dbSession.query(SslCertificateRequest)\
        .filter(SslCertificateRequest.ssl_private_key_id__signed_by == key_id)\
        .count()
    return counted


def get__SslCertificateRequest__by_SslPrivateKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(SslCertificateRequest)\
        .filter(SslCertificateRequest.ssl_private_key_id__signed_by == key_id)\
        .options(sqlalchemy.orm.joinedload('certificate_request_to_domains').joinedload('domain'),
                 )\
        .order_by(SslCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__SslCertificateRequest__by_SslUniqueFQDNSetId__count(dbSession, unique_fqdn_set_id):
    counted = dbSession.query(SslCertificateRequest)\
        .filter(SslCertificateRequest.ssl_unique_fqdn_set_id == unique_fqdn_set_id)\
        .count()
    return counted


def get__SslCertificateRequest__by_SslUniqueFQDNSetId__paginated(dbSession, unique_fqdn_set_id, limit=None, offset=0):
    items_paged = dbSession.query(SslCertificateRequest)\
        .filter(SslCertificateRequest.ssl_unique_fqdn_set_id == unique_fqdn_set_id)\
        .order_by(SslCertificateRequest.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslCertificateRequest2SslDomain__challenged(dbSession, challenge, domain_name):
    active_request = dbSession.query(SslCertificateRequest2SslDomain)\
        .join(SslDomain,
              SslCertificateRequest2SslDomain.ssl_domain_id == SslDomain.id
              )\
        .join(SslCertificateRequest,
              SslCertificateRequest2SslDomain.ssl_certificate_request_id == SslCertificateRequest.id
              )\
        .filter(SslCertificateRequest2SslDomain.challenge_key == challenge,
                sa.func.lower(SslDomain.domain_name) == sa.func.lower(domain_name),
                SslCertificateRequest.is_active.op('IS')(True),
                )\
        .options(sqlalchemy.orm.contains_eager('certificate_request'),
                 sqlalchemy.orm.contains_eager('domain'),
                 )\
        .first()
    return active_request


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _SslDomain_inject_exipring_days(q, expiring_days, order=False):
    """helper function for the count/paginated queries"""
    SslServerCertificateMulti = sqlalchemy.orm.aliased(SslServerCertificate)
    SslServerCertificateSingle = sqlalchemy.orm.aliased(SslServerCertificate)
    _until = datetime.datetime.utcnow() + datetime.timedelta(days=expiring_days)
    q = q.outerjoin(SslServerCertificateMulti,
                    SslDomain.ssl_server_certificate_id__latest_multi == SslServerCertificateMulti.id
                    )\
        .outerjoin(SslServerCertificateSingle,
                   SslDomain.ssl_server_certificate_id__latest_single == SslServerCertificateSingle.id
                   )\
        .filter(sqlalchemy.or_(sqlalchemy.and_(SslServerCertificateMulti.is_active == True,  # noqa
                                               SslServerCertificateMulti.timestamp_expires <= _until,
                                               ),
                               sqlalchemy.and_(SslServerCertificateSingle.is_active == True,  # noqa
                                               SslServerCertificateSingle.timestamp_expires <= _until,
                                               ),
                               )
                )
    if order:
        q = q.order_by(sqlalchemy.func.min(SslServerCertificateMulti.timestamp_expires,
                                           SslServerCertificateSingle.timestamp_expires,
                                           ).asc(),
                       )
    return q


def get__SslDomain__count(dbSession, expiring_days=None, active_only=False):
    q = dbSession.query(SslDomain)
    if active_only and not expiring_days:
        q = q.filter(sqlalchemy.or_(SslDomain.ssl_server_certificate_id__latest_single.op('IS NOT')(None),
                                    SslDomain.ssl_server_certificate_id__latest_multi.op('IS NOT')(None),
                                    ),
                     )
    if expiring_days:
        q = _SslDomain_inject_exipring_days(q, expiring_days, order=False)
    counted = q.count()
    return counted


def get__SslDomain__paginated(dbSession, expiring_days=None, eagerload_web=False, limit=None, offset=0, active_only=False):
    q = dbSession.query(SslDomain)
    if active_only and not expiring_days:
        q = q.filter(sqlalchemy.or_(SslDomain.ssl_server_certificate_id__latest_single.op('IS NOT')(None),
                                    SslDomain.ssl_server_certificate_id__latest_multi.op('IS NOT')(None),
                                    ),
                     )
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload('latest_certificate_single'),
                      sqlalchemy.orm.joinedload('latest_certificate_multi'),
                      )
    if expiring_days:
        q = _SslDomain_inject_exipring_days(q, expiring_days, order=True)
    else:
        q = q.order_by(sa.func.lower(SslDomain.domain_name).asc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__SslDomain__core(q, preload=False, eagerload_web=False):
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


def get__SslDomain__by_id(dbSession, domain_id, preload=False, eagerload_web=False):
    q = dbSession.query(SslDomain)\
        .filter(SslDomain.id == domain_id)
    if preload:
        q = _get__SslDomain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


def get__SslDomain__by_name(dbSession, domain_name, preload=False, eagerload_web=False):
    q = dbSession.query(SslDomain)\
        .filter(sa.func.lower(SslDomain.domain_name) == sa.func.lower(domain_name))
    if preload:
        q = _get__SslDomain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslOperationsEvent__count(dbSession, event_type_ids=None):
    q = dbSession.query(SslOperationsEvent)
    if event_type_ids is not None:
        q = q.filter(SslOperationsEvent.ssl_operations_event_type_id.in_(event_type_ids))
    items_count = q.count()
    return items_count


def get__SslOperationsEvent__paginated(dbSession, event_type_ids=None, limit=None, offset=0):
    q = dbSession.query(SslOperationsEvent)
    if event_type_ids is not None:
        q = q.filter(SslOperationsEvent.ssl_operations_event_type_id.in_(event_type_ids))
    items_paged = q.order_by(SslOperationsEvent.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__SslOperationsEvent__by_id(dbSession, event_id):
    item = dbSession.query(SslOperationsEvent)\
        .filter(SslOperationsEvent.id == event_id)\
        .first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslOperationsEvent__certificate_probe__count(dbSession):
    counted = dbSession.query(SslOperationsEvent)\
        .filter(SslOperationsEvent.ssl_operations_event_type_id == SslOperationsEventType.ca_certificate_probe,
                )\
        .count()
    return counted


def get__SslOperationsEvent__certificate_probe__paginated(dbSession, limit=None, offset=0):
    paged_items = dbSession.query(SslOperationsEvent)\
        .order_by(SslOperationsEvent.id.desc())\
        .filter(SslOperationsEvent.ssl_operations_event_type_id == SslOperationsEventType.ca_certificate_probe,
                )\
        .limit(limit)\
        .offset(offset)\
        .all()
    return paged_items


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslPrivateKey__count(dbSession):
    counted = dbSession.query(SslPrivateKey).count()
    return counted


def get__SslPrivateKey__paginated(dbSession, limit=None, offset=0, active_only=False):
    q = dbSession.query(SslPrivateKey)
    if active_only:
        q = q.filter(SslPrivateKey.count_active_certificates >= 1)
    q = q.order_by(SslPrivateKey.id.desc())\
        .limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslPrivateKey__by_id(dbSession, cert_id, eagerload_web=False):
    q = dbSession.query(SslPrivateKey)\
        .filter(SslPrivateKey.id == cert_id)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.subqueryload('certificate_requests_5').joinedload('certificate_request_to_domains').joinedload('domain'),
                      sqlalchemy.orm.subqueryload('signed_certificates_5').joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                      )
    item = q.first()
    return item


def get__SslPrivateKey__current_week(dbSession):
    q = dbSession.query(SslPrivateKey)\
        .filter(SslPrivateKey.is_autogenerated_key.op('IS')(True),
                year_week(SslPrivateKey.timestamp_first_seen) == year_week(utcnow()),
                )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslQueueDomain__count(dbSession, show_processed=False):
    q = dbSession.query(SslQueueDomain)
    if not show_processed:
        q = q.filter(SslQueueDomain.timestamp_processed.op('IS')(None),  # noqa
                     )
    counted = q.count()
    return counted


def get__SslQueueDomain__paginated(dbSession, show_processed=False, eagerload_web=False, limit=None, offset=0):
    q = dbSession.query(SslQueueDomain)
    if not show_processed:
        q = q.filter(SslQueueDomain.timestamp_processed.op('IS')(None),  # noqa
                     )
    else:
        q = q.order_by(SslQueueDomain.id.desc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslQueueDomain__by_id(dbSession, set_id):
    item = dbSession.query(SslQueueDomain)\
        .filter(SslQueueDomain.id == set_id)\
        .first()
    return item


def get__SslQueueDomain__by_name(dbSession, domain_name):
    q = dbSession.query(SslQueueDomain)\
        .filter(sa.func.lower(SslQueueDomain.domain_name) == sa.func.lower(domain_name))
    item = q.first()
    return item

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslQueueRenewal__count(dbSession, show_all=False):
    q = dbSession.query(SslQueueRenewal)
    if not show_all:
        q = q.filter(SslQueueRenewal.timestamp_processed.op('IS')(None),  # noqa
                     )
    counted = q.count()
    return counted


def get__SslQueueRenewal__paginated(dbSession, show_all=False, eagerload_web=False, limit=None, offset=0):
    q = dbSession.query(SslQueueRenewal)
    if not show_all:
        q = q.filter(SslQueueRenewal.timestamp_processed.op('IS')(None),  # noqa
                     )
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload('certificate').joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                      )
    else:
        q = q.order_by(SslQueueRenewal.id.desc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslQueueRenewal__by_id(dbSession, set_id):
    item = dbSession.query(SslQueueRenewal)\
        .filter(SslQueueRenewal.id == set_id)\
        .options(sqlalchemy.orm.subqueryload('certificate').joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                 )\
        .first()
    return item


def get__SslQueueRenewal__by_SslUniqueFQDNSetId__active(dbSession, set_id):
    q = dbSession.query(SslQueueRenewal)\
        .filter(SslQueueRenewal.ssl_unique_fqdn_set_id == set_id,
                SslQueueRenewal.timestamp_processed.op('IS')(None),
                )
    items_paged = q.all()
    return items_paged

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__count(dbSession, expiring_days=None):
    q = dbSession.query(SslServerCertificate)
    if expiring_days:
        _until = datetime.datetime.utcnow() + datetime.timedelta(days=expiring_days)
        q = q.filter(SslServerCertificate.is_active == True,  # noqa
                     SslServerCertificate.timestamp_expires <= _until,
                     )
    counted = q.count()
    return counted


def get__SslServerCertificate__paginated(dbSession, expiring_days=None, eagerload_web=False, limit=None, offset=0):
    q = dbSession.query(SslServerCertificate)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                      )
    if expiring_days:
        _until = datetime.datetime.utcnow() + datetime.timedelta(days=expiring_days)
        q = q.filter(SslServerCertificate.is_active == True,  # noqa
                     SslServerCertificate.timestamp_expires <= _until,
                     )\
            .order_by(SslServerCertificate.timestamp_expires.asc())
    else:
        q = q.order_by(SslServerCertificate.id.desc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslServerCertificate__by_id(dbSession, cert_id):
    dbSslServerCertificate = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.id == cert_id)\
        .options(sqlalchemy.orm.subqueryload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                 )\
        .first()
    return dbSslServerCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__by_SslLetsEncryptAccountKeyId__count(dbSession, key_id):
    counted = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_letsencrypt_account_key_id == key_id)\
        .count()
    return counted


def get__SslServerCertificate__by_SslLetsEncryptAccountKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_letsencrypt_account_key_id == key_id)\
        .options(sqlalchemy.orm.joinedload('unique_fqdn_set').joinedload('to_domains').joinedload('domain'),
                 )\
        .order_by(SslServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__by_SslCaCertificateId__count(dbSession, cert_id):
    counted = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_ca_certificate_id__upchain == cert_id)\
        .count()
    return counted


def get__SslServerCertificate__by_SslCaCertificateId__paginated(dbSession, cert_id, limit=None, offset=0):
    items_paged = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_ca_certificate_id__upchain == cert_id)\
        .order_by(SslServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__by_SslDomainId__count(dbSession, domain_id):
    counted = dbSession.query(SslServerCertificate)\
        .join(SslUniqueFQDNSet,
              SslServerCertificate.ssl_unique_fqdn_set_id == SslUniqueFQDNSet.id
              )\
        .join(SslUniqueFQDNSet2SslDomain,
              SslUniqueFQDNSet.id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
              )\
        .filter(SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id)\
        .count()
    return counted


def get__SslServerCertificate__by_SslDomainId__paginated(dbSession, domain_id, limit=None, offset=0):
    items_paged = dbSession.query(SslServerCertificate)\
        .join(SslUniqueFQDNSet,
              SslServerCertificate.ssl_unique_fqdn_set_id == SslUniqueFQDNSet.id
              )\
        .join(SslUniqueFQDNSet2SslDomain,
              SslUniqueFQDNSet.id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
              )\
        .filter(SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id)\
        .order_by(SslServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__SslServerCertificate__by_SslPrivateKeyId__count(dbSession, key_id):
    counted = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_private_key_id__signed_by == key_id)\
        .count()
    return counted


def get__SslServerCertificate__by_SslPrivateKeyId__paginated(dbSession, key_id, limit=None, offset=0):
    items_paged = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_private_key_id__signed_by == key_id)\
        .order_by(SslServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__SslServerCertificate__by_SslUniqueFQDNSetId__count(dbSession, unique_fqdn_set_id):
    counted = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_unique_fqdn_set_id == unique_fqdn_set_id)\
        .count()
    return counted


def get__SslServerCertificate__by_SslUniqueFQDNSetId__paginated(dbSession, unique_fqdn_set_id, limit=None, offset=0):
    items_paged = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_unique_fqdn_set_id == unique_fqdn_set_id)\
        .order_by(SslServerCertificate.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged


def get__SslServerCertificate__by_SslUniqueFQDNSetId__latest_active(dbSession, unique_fqdn_set_id):
    item = dbSession.query(SslServerCertificate)\
        .filter(SslServerCertificate.ssl_unique_fqdn_set_id == unique_fqdn_set_id)\
        .filter(SslServerCertificate.is_active.op('IS')(True))\
        .order_by(SslServerCertificate.timestamp_expires.desc())\
        .first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslUniqueFQDNSet__count(dbSession):
    q = dbSession.query(SslUniqueFQDNSet)
    counted = q.count()
    return counted


def get__SslUniqueFQDNSet__paginated(dbSession, eagerload_web=False, limit=None, offset=0):
    q = dbSession.query(SslUniqueFQDNSet)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload('to_domains').joinedload('domain'),
                      )
    else:
        q = q.order_by(SslUniqueFQDNSet.id.desc())
    q = q.limit(limit)\
        .offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslUniqueFQDNSet__by_id(dbSession, set_id):
    item = dbSession.query(SslUniqueFQDNSet)\
        .filter(SslUniqueFQDNSet.id == set_id)\
        .options(sqlalchemy.orm.subqueryload('to_domains').joinedload('domain'),
                 )\
        .first()
    return item


def get__SslUniqueFQDNSet__by_SslDomainId__count(dbSession, domain_id):
    counted = dbSession.query(SslUniqueFQDNSet)\
        .join(SslUniqueFQDNSet2SslDomain,
              SslUniqueFQDNSet.id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
              )\
        .filter(SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id)\
        .count()
    return counted


def get__SslUniqueFQDNSet__by_SslDomainId__paginated(dbSession, domain_id, limit=None, offset=0):
    items_paged = dbSession.query(SslUniqueFQDNSet)\
        .join(SslUniqueFQDNSet2SslDomain,
              SslUniqueFQDNSet.id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
              )\
        .filter(SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id)\
        .order_by(SslUniqueFQDNSet.id.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    return items_paged
