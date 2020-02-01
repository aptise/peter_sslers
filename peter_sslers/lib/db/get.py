# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime

# pypi
import sqlalchemy

# localapp
from .. import cert_utils
from .. import utils
from ...model import utils as model_utils
from ...model import objects as model_objects


EVENTS_USE_ALT = True


# ==============================================================================


def get_dbSessionLogItem(ctx):
    dbSession = ctx.dbSessionLogger if EVENTS_USE_ALT else ctx.dbSession
    return dbSession


def get__SslAcmeEventLogs__count(ctx):
    dbSessionLogItem = get_dbSessionLogItem(ctx)
    counted = dbSessionLogItem.query(model_objects.SslAcmeEventLog).count()
    return counted


def get__SslAcmeEventLogs__paginated(ctx, limit=None, offset=0):
    dbSessionLogItem = get_dbSessionLogItem(ctx)
    query = (
        dbSessionLogItem.query(model_objects.SslAcmeEventLog)
        .order_by(model_objects.SslAcmeEventLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    sslAcmeEventLogs = query.all()
    return sslAcmeEventLogs


def get__SslAcmeEventLog__by_id(ctx, id):
    dbSessionLogItem = get_dbSessionLogItem(ctx)
    counted = dbSessionLogItem.query(model_objects.SslAcmeEventLog).get(id)
    return counted


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslAcmeChallengeLogs__count(ctx):
    dbSessionLogItem = get_dbSessionLogItem(ctx)
    counted = dbSessionLogItem.query(model_objects.SslAcmeChallengeLog).count()
    return counted


def get__SslAcmeChallengeLogs__paginated(
    ctx, limit=None, offset=0, acme_account_key_id=None, pending_only=None
):
    dbSessionLogItem = get_dbSessionLogItem(ctx)
    query = dbSessionLogItem.query(model_objects.SslAcmeChallengeLog)
    if acme_account_key_id:
        query = query.join(
            model_objects.SslAcmeEventLog,
            model_objects.SslAcmeChallengeLog.ssl_acme_event_log_id
            == model_objects.SslAcmeEventLog.id,
        ).filter(
            model_objects.SslAcmeEventLog.ssl_acme_account_key_id == acme_account_key_id
        )
    if pending_only:
        query = query.filter(model_objects.SslAcmeChallengeLog.count_polled == 0)
    query = (
        query.order_by(model_objects.SslAcmeChallengeLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dnSslAcmeChallengeLogs = query.all()
    return dnSslAcmeChallengeLogs


def get__SslAcmeChallengeLog__by_id(ctx, id):
    dbSessionLogItem = get_dbSessionLogItem(ctx)
    counted = dbSessionLogItem.query(model_objects.SslAcmeChallengeLog).get(id)
    return counted


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslAcmeAccountKey__count(ctx):
    counted = ctx.dbSession.query(model_objects.SslAcmeAccountKey).count()
    return counted


def get__SslAcmeAccountKey__paginated(ctx, limit=None, offset=0, active_only=False):
    query = ctx.dbSession.query(model_objects.SslAcmeAccountKey)
    if active_only:
        query = query.filter(model_objects.SslAcmeAccountKey.is_active.op("IS")(True))
    query = (
        query.order_by(model_objects.SslAcmeAccountKey.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeAccountKeys = query.all()
    return dbAcmeAccountKeys


def get__SslAcmeAccountKey__by_id(ctx, key_id, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.SslAcmeAccountKey).filter(
        model_objects.SslAcmeAccountKey.id == key_id
    )
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.subqueryload("certificate_requests__5")
            .joinedload("to_domains")
            .joinedload("domain"),
            sqlalchemy.orm.subqueryload("server_certificates__5")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
        )
    item = q.first()
    return item


def get__SslAcmeAccountKey__by_pemMd5(ctx, pem_md5, default_only=False, is_active=True):
    q = ctx.dbSession.query(model_objects.SslAcmeAccountKey).filter(
        model_objects.SslAcmeAccountKey.key_pem_md5 == pem_md5
    )
    if default_only:
        q = q.filter(model_objects.SslAcmeAccountKey.is_default.op("IS")(True))
    if is_active:
        q = q.filter(model_objects.SslAcmeAccountKey.is_active.op("IS")(True))
    item = q.first()
    return item


def get__SslAcmeAccountKey__default(ctx, active_only=None):
    q = ctx.dbSession.query(model_objects.SslAcmeAccountKey).filter(
        model_objects.SslAcmeAccountKey.is_default.op("IS")(True)
    )
    if active_only:
        q = q.filter(model_objects.SslAcmeAccountKey.is_active.op("IS")(True))
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslCaCertificate__count(ctx):
    counted = ctx.dbSession.query(model_objects.SslCaCertificate).count()
    return counted


def get__SslCaCertificate__paginated(ctx, limit=None, offset=0, active_only=False):
    q = ctx.dbSession.query(model_objects.SslCaCertificate)
    if active_only:
        q = q.filter(model_objects.SslCaCertificate.count_active_certificates >= 1)
    q = q.order_by(model_objects.SslCaCertificate.id.desc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslCaCertificate__by_id(ctx, cert_id):
    dbCaCertificate = (
        ctx.dbSession.query(model_objects.SslCaCertificate)
        .filter(model_objects.SslCaCertificate.id == cert_id)
        .first()
    )
    return dbCaCertificate


def get__SslCaCertificate__by_pem_text(ctx, cert_pem):
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    dbCertificate = (
        ctx.dbSession.query(model_objects.SslCaCertificate)
        .filter(
            model_objects.SslCaCertificate.cert_pem_md5 == cert_pem_md5,
            model_objects.SslCaCertificate.cert_pem == cert_pem,
        )
        .first()
    )
    return dbCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslCertificateRequest__count(ctx):
    counted = ctx.dbSession.query(model_objects.SslCertificateRequest).count()
    return counted


def get__SslCertificateRequest__paginated(ctx, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .options(
            sqlalchemy.orm.joinedload("server_certificate"),
            sqlalchemy.orm.subqueryload("to_domains").joinedload("domain"),
        )
        .order_by(model_objects.SslCertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__SslCertificateRequest__by_id(ctx, certificate_request_id):
    dbCertificateRequest = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .filter(model_objects.SslCertificateRequest.id == certificate_request_id)
        .options(
            sqlalchemy.orm.joinedload("server_certificate"),
            sqlalchemy.orm.subqueryload("to_domains").joinedload("domain"),
        )
        .one()
    )
    return dbCertificateRequest


def get__SslCertificateRequest__by_pem_text(ctx, csr_pem):
    csr_pem = cert_utils.cleanup_pem_text(csr_pem)
    csr_pem_md5 = utils.md5_text(csr_pem)
    dbCertificateRequest = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .filter(
            model_objects.SslCertificateRequest.csr_pem_md5 == csr_pem_md5,
            model_objects.SslCertificateRequest.csr_pem == csr_pem,
        )
        .first()
    )
    return dbCertificateRequest


def get__SslCertificateRequest__by_SslAcmeAccountKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .filter(model_objects.SslCertificateRequest.ssl_acme_account_key_id == key_id)
        .count()
    )
    return counted


def get__SslCertificateRequest__by_SslAcmeAccountKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .filter(model_objects.SslCertificateRequest.ssl_acme_account_key_id == key_id)
        .options(sqlalchemy.orm.joinedload("to_domains").joinedload("domain"))
        .order_by(model_objects.SslCertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__SslCertificateRequest__by_SslDomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .join(
            model_objects.SslCertificateRequest2SslDomain,
            model_objects.SslCertificateRequest.id
            == model_objects.SslCertificateRequest2SslDomain.ssl_certificate_request_id,
        )
        .filter(
            model_objects.SslCertificateRequest2SslDomain.ssl_domain_id == domain_id
        )
        .count()
    )
    return counted


def get__SslCertificateRequest__by_SslDomainId__paginated(
    ctx, domain_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .join(
            model_objects.SslCertificateRequest2SslDomain,
            model_objects.SslCertificateRequest.id
            == model_objects.SslCertificateRequest2SslDomain.ssl_certificate_request_id,
        )
        .filter(
            model_objects.SslCertificateRequest2SslDomain.ssl_domain_id == domain_id
        )
        .order_by(model_objects.SslCertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__SslCertificateRequest__by_SslPrivateKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .filter(
            model_objects.SslCertificateRequest.ssl_private_key_id__signed_by == key_id
        )
        .count()
    )
    return counted


def get__SslCertificateRequest__by_SslPrivateKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .filter(
            model_objects.SslCertificateRequest.ssl_private_key_id__signed_by == key_id
        )
        .options(sqlalchemy.orm.joinedload("to_domains").joinedload("domain"))
        .order_by(model_objects.SslCertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__SslCertificateRequest__by_SslUniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .filter(
            model_objects.SslCertificateRequest.ssl_unique_fqdn_set_id
            == unique_fqdn_set_id
        )
        .count()
    )
    return counted


def get__SslCertificateRequest__by_SslUniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslCertificateRequest)
        .filter(
            model_objects.SslCertificateRequest.ssl_unique_fqdn_set_id
            == unique_fqdn_set_id
        )
        .order_by(model_objects.SslCertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslCertificateRequest2SslDomain__challenged(ctx, challenge, domain_name):
    active_request = (
        ctx.dbSession.query(model_objects.SslCertificateRequest2SslDomain)
        .join(
            model_objects.SslDomain,
            model_objects.SslCertificateRequest2SslDomain.ssl_domain_id
            == model_objects.SslDomain.id,
        )
        .join(
            model_objects.SslCertificateRequest,
            model_objects.SslCertificateRequest2SslDomain.ssl_certificate_request_id
            == model_objects.SslCertificateRequest.id,
        )
        .filter(
            model_objects.SslCertificateRequest2SslDomain.challenge_key == challenge,
            sqlalchemy.func.lower(model_objects.SslDomain.domain_name)
            == sqlalchemy.func.lower(domain_name),
            model_objects.SslCertificateRequest.is_active.op("IS")(True),
        )
        .options(
            sqlalchemy.orm.contains_eager("certificate_request"),
            sqlalchemy.orm.contains_eager("domain"),
        )
        .first()
    )
    return active_request


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _SslDomain_inject_exipring_days(ctx, q, expiring_days, order=False):
    """helper function for the count/paginated queries"""
    SslServerCertificateMulti = sqlalchemy.orm.aliased(
        model_objects.SslServerCertificate
    )
    SslServerCertificateSingle = sqlalchemy.orm.aliased(
        model_objects.SslServerCertificate
    )
    _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
    q = (
        q.outerjoin(
            SslServerCertificateMulti,
            model_objects.SslDomain.ssl_server_certificate_id__latest_multi
            == SslServerCertificateMulti.id,
        )
        .outerjoin(
            SslServerCertificateSingle,
            model_objects.SslDomain.ssl_server_certificate_id__latest_single
            == SslServerCertificateSingle.id,
        )
        .filter(
            sqlalchemy.or_(
                sqlalchemy.and_(
                    SslServerCertificateMulti.is_active.is_(True),
                    SslServerCertificateMulti.timestamp_expires <= _until,
                ),
                sqlalchemy.and_(
                    SslServerCertificateSingle.is_active.is_(True),
                    SslServerCertificateSingle.timestamp_expires <= _until,
                ),
            )
        )
    )
    if order:
        q = q.order_by(
            model_utils.min_date(
                SslServerCertificateMulti.timestamp_expires,
                SslServerCertificateSingle.timestamp_expires,
            ).asc()
        )
    return q


def get__SslDomain__count(ctx, expiring_days=None, active_only=False):
    q = ctx.dbSession.query(model_objects.SslDomain)
    if active_only and not expiring_days:
        q = q.filter(
            sqlalchemy.or_(
                model_objects.SslDomain.ssl_server_certificate_id__latest_single.op(
                    "IS NOT"
                )(None),
                model_objects.SslDomain.ssl_server_certificate_id__latest_multi.op(
                    "IS NOT"
                )(None),
            )
        )
    if expiring_days:
        q = _SslDomain_inject_exipring_days(ctx, q, expiring_days, order=False)
    counted = q.count()
    return counted


def get__SslDomain__paginated(
    ctx,
    expiring_days=None,
    eagerload_web=False,
    limit=None,
    offset=0,
    active_only=False,
):
    q = ctx.dbSession.query(model_objects.SslDomain)
    if active_only and not expiring_days:
        q = q.filter(
            sqlalchemy.or_(
                model_objects.SslDomain.ssl_server_certificate_id__latest_single.op(
                    "IS NOT"
                )(None),
                model_objects.SslDomain.ssl_server_certificate_id__latest_multi.op(
                    "IS NOT"
                )(None),
            )
        )
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.joinedload("server_certificate__latest_single"),
            sqlalchemy.orm.joinedload("server_certificate__latest_multi"),
        )
    if expiring_days:
        q = _SslDomain_inject_exipring_days(ctx, q, expiring_days, order=True)
    else:
        q = q.order_by(sqlalchemy.func.lower(model_objects.SslDomain.domain_name).asc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__SslDomain__core(q, preload=False, eagerload_web=False):
    q = q.options(
        sqlalchemy.orm.subqueryload("server_certificate__latest_single"),
        sqlalchemy.orm.joinedload("server_certificate__latest_single.private_key"),
        sqlalchemy.orm.joinedload(
            "server_certificate__latest_single.certificate_upchain"
        ),
        sqlalchemy.orm.joinedload("server_certificate__latest_single.unique_fqdn_set"),
        sqlalchemy.orm.joinedload(
            "server_certificate__latest_single.unique_fqdn_set.to_domains"
        ),
        sqlalchemy.orm.joinedload(
            "server_certificate__latest_single.unique_fqdn_set.to_domains.domain"
        ),
        sqlalchemy.orm.subqueryload("server_certificate__latest_multi"),
        sqlalchemy.orm.joinedload("server_certificate__latest_multi.private_key"),
        sqlalchemy.orm.joinedload(
            "server_certificate__latest_multi.certificate_upchain"
        ),
        sqlalchemy.orm.joinedload("server_certificate__latest_multi.unique_fqdn_set"),
        sqlalchemy.orm.joinedload(
            "server_certificate__latest_multi.unique_fqdn_set.to_domains"
        ),
        sqlalchemy.orm.joinedload(
            "server_certificate__latest_multi.unique_fqdn_set.to_domains.domain"
        ),
    )
    if eagerload_web:
        # need to join back the domains to show alternate domains.
        q = q.options(
            sqlalchemy.orm.subqueryload("to_certificate_requests__5")
            .joinedload("certificate_request")
            .joinedload("to_domains")
            .joinedload("domain"),
            sqlalchemy.orm.subqueryload("server_certificates__5")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
        )
    return q


def get__SslDomain__by_id(ctx, domain_id, preload=False, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.SslDomain).filter(
        model_objects.SslDomain.id == domain_id
    )
    if preload:
        q = _get__SslDomain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


def get__SslDomain__by_name(
    ctx, domain_name, preload=False, eagerload_web=False, active_only=False
):
    q = ctx.dbSession.query(model_objects.SslDomain).filter(
        sqlalchemy.func.lower(model_objects.SslDomain.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    if preload:
        q = _get__SslDomain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslOperationsObjectEvent__count(ctx):
    q = ctx.dbSession.query(model_objects.SslOperationsObjectEvent)
    counted = q.count()
    return counted


def get__SslOperationsObjectEvent__paginated(ctx, limit=None, offset=0):
    q = (
        ctx.dbSession.query(model_objects.SslOperationsObjectEvent)
        .order_by(model_objects.SslOperationsObjectEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__SslOperationsObjectEvent__by_id(ctx, event_id, eagerload_log=False):
    q = ctx.dbSession.query(model_objects.SslOperationsObjectEvent).filter(
        model_objects.SslOperationsObjectEvent.id == event_id
    )
    if eagerload_log:
        q = q.options(
            sqlalchemy.orm.subqueryload("operations_event"),
            sqlalchemy.orm.joinedload("operations_event.children"),
            sqlalchemy.orm.joinedload("operations_event.parent"),
        )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslOperationsEvent__count(ctx, event_type_ids=None):
    q = ctx.dbSession.query(model_objects.SslOperationsEvent)
    if event_type_ids is not None:
        q = q.filter(
            model_objects.SslOperationsEvent.ssl_operations_event_type_id.in_(
                event_type_ids
            )
        )
    items_count = q.count()
    return items_count


def get__SslOperationsEvent__paginated(ctx, event_type_ids=None, limit=None, offset=0):
    q = ctx.dbSession.query(model_objects.SslOperationsEvent)
    if event_type_ids is not None:
        q = q.filter(
            model_objects.SslOperationsEvent.ssl_operations_event_type_id.in_(
                event_type_ids
            )
        )
    items_paged = (
        q.order_by(model_objects.SslOperationsEvent.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__SslOperationsEvent__by_id(ctx, event_id, eagerload_log=False):
    q = ctx.dbSession.query(model_objects.SslOperationsEvent).filter(
        model_objects.SslOperationsEvent.id == event_id
    )
    if eagerload_log:
        q = q.options(
            sqlalchemy.orm.subqueryload("object_events"),
            sqlalchemy.orm.joinedload("object_events.domain"),
            sqlalchemy.orm.joinedload("object_events.queue_domain"),
            sqlalchemy.orm.subqueryload("children"),
            sqlalchemy.orm.subqueryload("parent"),
        )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslOperationsEvent__certificate_probe__count(ctx):
    counted = (
        ctx.dbSession.query(model_objects.SslOperationsEvent)
        .filter(
            model_objects.SslOperationsEvent.ssl_operations_event_type_id
            == model_utils.SslOperationsEventType.from_string("ca_certificate__probe")
        )
        .count()
    )
    return counted


def get__SslOperationsEvent__certificate_probe__paginated(ctx, limit=None, offset=0):
    paged_items = (
        ctx.dbSession.query(model_objects.SslOperationsEvent)
        .order_by(model_objects.SslOperationsEvent.id.desc())
        .filter(
            model_objects.SslOperationsEvent.ssl_operations_event_type_id
            == model_utils.SslOperationsEventType.from_string("ca_certificate__probe")
        )
        .limit(limit)
        .offset(offset)
        .all()
    )
    return paged_items


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslPrivateKey__count(ctx):
    counted = ctx.dbSession.query(model_objects.SslPrivateKey).count()
    return counted


def get__SslPrivateKey__paginated(ctx, limit=None, offset=0, active_only=False):
    q = ctx.dbSession.query(model_objects.SslPrivateKey)
    if active_only:
        q = q.filter(model_objects.SslPrivateKey.count_active_certificates >= 1)
    q = q.order_by(model_objects.SslPrivateKey.id.desc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslPrivateKey__by_id(ctx, cert_id, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.SslPrivateKey).filter(
        model_objects.SslPrivateKey.id == cert_id
    )
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.subqueryload("certificate_requests__5")
            .joinedload("to_domains")
            .joinedload("domain"),
            sqlalchemy.orm.subqueryload("server_certificates__5")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
        )
    item = q.first()
    return item


def get__SslPrivateKey__current_week(ctx):
    q = ctx.dbSession.query(model_objects.SslPrivateKey).filter(
        model_objects.SslPrivateKey.is_autogenerated_key.op("IS")(True),
        model_utils.year_week(model_objects.SslPrivateKey.timestamp_first_seen)
        == model_utils.year_week(ctx.timestamp),
    )
    item = q.first()
    return item


def get__SslPrivateKey__by_pemMd5(ctx, pem_md5, default_only=False, is_active=True):
    q = ctx.dbSession.query(model_objects.SslPrivateKey).filter(
        model_objects.SslPrivateKey.key_pem_md5 == pem_md5
    )
    if default_only:
        q = q.filter(model_objects.SslPrivateKey.is_default.op("IS")(True))
    if is_active:
        q = q.filter(model_objects.SslPrivateKey.is_active.op("IS")(True))
    item = q.first()
    return item


def get__SslPrivateKey__default(ctx, active_only=None):
    q = ctx.dbSession.query(model_objects.SslPrivateKey).filter(
        model_objects.SslPrivateKey.is_default.op("IS")(True)
    )
    if active_only:
        q = q.filter(model_objects.SslPrivateKey.is_active.op("IS")(True))
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslQueueDomain__count(ctx, show_all=None, unprocessed_only=None):
    q = ctx.dbSession.query(model_objects.SslQueueDomain)
    if unprocessed_only and show_all:
        raise ValueError("conflicting arguments")
    if unprocessed_only:
        q = q.filter(
            model_objects.SslQueueDomain.timestamp_processed.op("IS")(None)
        )  # noqa
    counted = q.count()
    return counted


def get__SslQueueDomain__paginated(
    ctx, show_all=None, unprocessed_only=None, eagerload_web=None, limit=None, offset=0
):
    q = ctx.dbSession.query(model_objects.SslQueueDomain)
    if unprocessed_only and show_all:
        raise ValueError("conflicting arguments")
    if unprocessed_only:
        q = q.filter(
            model_objects.SslQueueDomain.timestamp_processed.op("IS")(None)
        )  # noqa
    q = q.order_by(model_objects.SslQueueDomain.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslQueueDomain__by_id(ctx, set_id, eagerload_log=None):
    q = ctx.dbSession.query(model_objects.SslQueueDomain).filter(
        model_objects.SslQueueDomain.id == set_id
    )
    if eagerload_log:
        q = q.options(
            sqlalchemy.orm.subqueryload("operations_object_events").joinedload(
                "operations_event"
            )
        )
    item = q.first()
    return item


def get__SslQueueDomain__by_name(ctx, domain_name, active_only=True):
    q = ctx.dbSession.query(model_objects.SslQueueDomain).filter(
        sqlalchemy.func.lower(model_objects.SslQueueDomain.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    if active_only:
        q = q.filter(model_objects.SslQueueDomain.is_active.op("IS")(True))
    item = q.first()
    return item


def get__SslQueueDomains__by_name(
    ctx, domain_name, active_only=None, inactive_only=None
):
    q = ctx.dbSession.query(model_objects.SslQueueDomain).filter(
        sqlalchemy.func.lower(model_objects.SslQueueDomain.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    if active_only:
        q = q.filter(model_objects.SslQueueDomain.is_active.op("IS")(True))
    elif inactive_only:
        q = q.filter(model_objects.SslQueueDomain.is_active.op("IS")(False))
    items = q.all()
    return items


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslOperationsQueueDomainEvent__count(ctx):
    q = ctx.dbSession.query(model_objects.SslOperationsQueueDomainEvent)
    counted = q.count()
    return counted


def get__SslOperationsQueueDomainEvent__paginated(ctx, limit=None, offset=0):
    q = (
        ctx.dbSession.query(model_objects.SslOperationsQueueDomainEvent)
        .options(
            sqlalchemy.orm.joinedload("queue_domain").load_only("domain_name"),
            sqlalchemy.orm.joinedload("domain").load_only("domain_name"),
        )
        .order_by(model_objects.SslOperationsQueueDomainEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslQueueRenewal__count(
    ctx, unprocessed_only=False, unprocessed_failures_only=None
):
    if unprocessed_failures_only and unprocessed_only:
        raise ValueError("only submit one strategy")
    q = ctx.dbSession.query(model_objects.SslQueueRenewal)
    if unprocessed_failures_only:
        q = q.filter(
            model_objects.SslQueueRenewal.timestamp_processed.op("IS")(None),  # noqa
            model_objects.SslQueueRenewal.timestamp_process_attempt.op("IS NOT")(
                None
            ),  # noqa
            model_objects.SslQueueRenewal.process_result.op("IS")(False),  # noqa
        )
    if unprocessed_only:
        q = q.filter(
            model_objects.SslQueueRenewal.timestamp_processed.op("IS")(None)
        )  # noqa
    counted = q.count()
    return counted


def get__SslQueueRenewal__paginated(
    ctx,
    unprocessed_only=False,
    unprocessed_failures_only=None,
    eagerload_web=False,
    eagerload_renewal=False,
    limit=None,
    offset=0,
):
    if unprocessed_failures_only and unprocessed_only:
        raise ValueError("only submit one strategy")
    q = ctx.dbSession.query(model_objects.SslQueueRenewal)
    if unprocessed_failures_only:
        q = q.filter(
            model_objects.SslQueueRenewal.timestamp_processed.op("IS")(None),  # noqa
            model_objects.SslQueueRenewal.timestamp_process_attempt.op("IS NOT")(
                None
            ),  # noqa
            model_objects.SslQueueRenewal.process_result.op("IS")(False),  # noqa
        )
    if unprocessed_only:
        q = q.filter(
            model_objects.SslQueueRenewal.timestamp_processed.op("IS")(None)
        )  # noqa
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.joinedload("certificate")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
    elif eagerload_renewal:
        q = q.options(
            sqlalchemy.orm.joinedload("server_certificate"),
            sqlalchemy.orm.subqueryload("server_certificate.acme_account_key"),
            sqlalchemy.orm.subqueryload("server_certificate.private_key"),
        )
    q = q.order_by(model_objects.SslQueueRenewal.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslQueueRenewal__by_id(ctx, set_id, load_events=None):
    q = (
        ctx.dbSession.query(model_objects.SslQueueRenewal)
        .filter(model_objects.SslQueueRenewal.id == set_id)
        .options(
            sqlalchemy.orm.subqueryload("server_certificate")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
    )
    if load_events:
        q = q.options(sqlalchemy.orm.subqueryload("operations_object_events"))
    item = q.first()
    return item


def get__SslQueueRenewal__by_SslUniqueFQDNSetId__active(ctx, set_id):
    q = ctx.dbSession.query(model_objects.SslQueueRenewal).filter(
        model_objects.SslQueueRenewal.ssl_unique_fqdn_set_id == set_id,
        model_objects.SslQueueRenewal.timestamp_processed.op("IS")(None),
    )
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__count(ctx, expiring_days=None, is_active=None):
    q = ctx.dbSession.query(model_objects.SslServerCertificate)
    if is_active is not None:
        if is_active is True:
            q = q.filter(model_objects.SslServerCertificate.is_active.is_(True))
        elif is_active is False:
            q = q.filter(model_objects.SslServerCertificate.is_active.is_(False))
    else:
        if expiring_days:
            _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
            q = q.filter(
                model_objects.SslServerCertificate.is_active.is_(True),
                model_objects.SslServerCertificate.timestamp_expires <= _until,
            )
    counted = q.count()
    return counted


def get__SslServerCertificate__paginated(
    ctx, expiring_days=None, is_active=None, eagerload_web=False, limit=None, offset=0
):
    q = ctx.dbSession.query(model_objects.SslServerCertificate)
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
    if is_active is not None:
        if is_active is True:
            q = q.filter(model_objects.SslServerCertificate.is_active.is_(True))
        elif is_active is False:
            q = q.filter(model_objects.SslServerCertificate.is_active.is_(False))
        q = q.order_by(model_objects.SslServerCertificate.timestamp_expires.asc())
    else:
        if expiring_days:
            _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
            q = q.filter(
                model_objects.SslServerCertificate.is_active.is_(True),
                model_objects.SslServerCertificate.timestamp_expires <= _until,
            ).order_by(model_objects.SslServerCertificate.timestamp_expires.asc())
        else:
            q = q.order_by(model_objects.SslServerCertificate.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslServerCertificate__by_id(ctx, cert_id):
    dbServerCertificate = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(model_objects.SslServerCertificate.id == cert_id)
        .options(
            sqlalchemy.orm.subqueryload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
        .first()
    )
    return dbServerCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__by_SslAcmeAccountKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(model_objects.SslServerCertificate.ssl_acme_account_key_id == key_id)
        .count()
    )
    return counted


def get__SslServerCertificate__by_SslAcmeAccountKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(model_objects.SslServerCertificate.ssl_acme_account_key_id == key_id)
        .options(
            sqlalchemy.orm.joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
        .order_by(model_objects.SslServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__by_SslCaCertificateId__count(ctx, cert_id):
    counted = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(
            model_objects.SslServerCertificate.ssl_ca_certificate_id__upchain == cert_id
        )
        .count()
    )
    return counted


def get__SslServerCertificate__by_SslCaCertificateId__paginated(
    ctx, cert_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(
            model_objects.SslServerCertificate.ssl_ca_certificate_id__upchain == cert_id
        )
        .order_by(model_objects.SslServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__by_SslDomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .join(
            model_objects.SslUniqueFQDNSet,
            model_objects.SslServerCertificate.ssl_unique_fqdn_set_id
            == model_objects.SslUniqueFQDNSet.id,
        )
        .join(
            model_objects.SslUniqueFQDNSet2SslDomain,
            model_objects.SslUniqueFQDNSet.id
            == model_objects.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
        )
        .filter(model_objects.SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id)
        .count()
    )
    return counted


def get__SslServerCertificate__by_SslDomainId__paginated(
    ctx, domain_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .join(
            model_objects.SslUniqueFQDNSet,
            model_objects.SslServerCertificate.ssl_unique_fqdn_set_id
            == model_objects.SslUniqueFQDNSet.id,
        )
        .join(
            model_objects.SslUniqueFQDNSet2SslDomain,
            model_objects.SslUniqueFQDNSet.id
            == model_objects.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
        )
        .filter(model_objects.SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id)
        .order_by(model_objects.SslServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__SslServerCertificate__by_SslDomainId__latest(ctx, domain_id):
    first = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .join(
            model_objects.SslUniqueFQDNSet,
            model_objects.SslServerCertificate.ssl_unique_fqdn_set_id
            == model_objects.SslUniqueFQDNSet.id,
        )
        .join(
            model_objects.SslUniqueFQDNSet2SslDomain,
            model_objects.SslUniqueFQDNSet.id
            == model_objects.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
        )
        .filter(
            model_objects.SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id,
            model_objects.SslServerCertificate.is_active.op("IS")(True),
        )
        .order_by(model_objects.SslServerCertificate.id.desc())
        .first()
    )
    return first


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslServerCertificate__by_SslPrivateKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(
            model_objects.SslServerCertificate.ssl_private_key_id__signed_by == key_id
        )
        .count()
    )
    return counted


def get__SslServerCertificate__by_SslPrivateKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(
            model_objects.SslServerCertificate.ssl_private_key_id__signed_by == key_id
        )
        .order_by(model_objects.SslServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__SslServerCertificate__by_SslUniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(
            model_objects.SslServerCertificate.ssl_unique_fqdn_set_id
            == unique_fqdn_set_id
        )
        .count()
    )
    return counted


def get__SslServerCertificate__by_SslUniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(
            model_objects.SslServerCertificate.ssl_unique_fqdn_set_id
            == unique_fqdn_set_id
        )
        .order_by(model_objects.SslServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__SslServerCertificate__by_SslUniqueFQDNSetId__latest_active(
    ctx, unique_fqdn_set_id
):
    item = (
        ctx.dbSession.query(model_objects.SslServerCertificate)
        .filter(
            model_objects.SslServerCertificate.ssl_unique_fqdn_set_id
            == unique_fqdn_set_id
        )
        .filter(model_objects.SslServerCertificate.is_active.op("IS")(True))
        .order_by(model_objects.SslServerCertificate.timestamp_expires.desc())
        .first()
    )
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__SslUniqueFQDNSet__count(ctx):
    q = ctx.dbSession.query(model_objects.SslUniqueFQDNSet)
    counted = q.count()
    return counted


def get__SslUniqueFQDNSet__paginated(ctx, eagerload_web=False, limit=None, offset=0):
    q = ctx.dbSession.query(model_objects.SslUniqueFQDNSet)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload("to_domains").joinedload("domain"))
    else:
        q = q.order_by(model_objects.SslUniqueFQDNSet.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__SslUniqueFQDNSet__by_id(ctx, set_id):
    item = (
        ctx.dbSession.query(model_objects.SslUniqueFQDNSet)
        .filter(model_objects.SslUniqueFQDNSet.id == set_id)
        .options(sqlalchemy.orm.subqueryload("to_domains").joinedload("domain"))
        .first()
    )
    return item


def get__SslUniqueFQDNSet__by_SslDomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.SslUniqueFQDNSet)
        .join(
            model_objects.SslUniqueFQDNSet2SslDomain,
            model_objects.SslUniqueFQDNSet.id
            == model_objects.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
        )
        .filter(model_objects.SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id)
        .count()
    )
    return counted


def get__SslUniqueFQDNSet__by_SslDomainId__paginated(
    ctx, domain_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.SslUniqueFQDNSet)
        .join(
            model_objects.SslUniqueFQDNSet2SslDomain,
            model_objects.SslUniqueFQDNSet.id
            == model_objects.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
        )
        .filter(model_objects.SslUniqueFQDNSet2SslDomain.ssl_domain_id == domain_id)
        .order_by(model_objects.SslUniqueFQDNSet.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
