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


# ==============================================================================


def get__AcmeEventLog__count(ctx):
    counted = ctx.dbSession.query(model_objects.AcmeEventLog).count()
    return counted


def get__AcmeEventLog__paginated(ctx, limit=None, offset=0):
    query = (
        ctx.dbSession.query(model_objects.AcmeEventLog)
        .order_by(model_objects.AcmeEventLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeEventLogs = query.all()
    return dbAcmeEventLogs


def get__AcmeEventLog__by_id(ctx, id):
    item = ctx.dbSession.query(model_objects.AcmeEventLog).get(id)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAccountProvider__default(ctx):
    dbAcmeAccountProvider_default = (
        ctx.dbSession.query(model_objects.AcmeAccountProvider)
        .filter(model_objects.AcmeAccountProvider.is_default.op("IS")(True),)
        .first()
    )
    return dbAcmeAccountProvider_default


def get__AcmeAccountProvider__by_name(ctx, name):
    query = ctx.dbSession.query(model_objects.AcmeAccountProvider).filter(
        sqlalchemy.func.lower(model_objects.AcmeAccountProvider.name) == name.lower()
    )
    return query.first()


def get__AcmeAccountProviders__paginated(ctx, limit=None, offset=0, is_enabled=None):
    query = ctx.dbSession.query(model_objects.AcmeAccountProvider)
    if is_enabled is True:
        query = query.filter(
            model_objects.AcmeAccountProvider.is_enabled.op("IS")(True)
        )
    query = (
        query.order_by(model_objects.AcmeAccountProvider.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAccountKey__count(ctx):
    counted = ctx.dbSession.query(model_objects.AcmeAccountKey).count()
    return counted


def get__AcmeAccountKey__paginated(ctx, limit=None, offset=0, active_only=False):
    query = ctx.dbSession.query(model_objects.AcmeAccountKey)
    if active_only:
        query = query.filter(model_objects.AcmeAccountKey.is_active.op("IS")(True))
    query = (
        query.order_by(model_objects.AcmeAccountKey.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeAccountKeys = query.all()
    return dbAcmeAccountKeys


def get__AcmeAccountKey__by_id(ctx, key_id, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.AcmeAccountKey).filter(
        model_objects.AcmeAccountKey.id == key_id
    )
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.subqueryload("acme_orders__5")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
            sqlalchemy.orm.subqueryload("server_certificates__5")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
        )
    item = q.first()
    return item


def get__AcmeAccountKey__by_pemMd5(ctx, pem_md5, is_active=True):
    q = ctx.dbSession.query(model_objects.AcmeAccountKey).filter(
        model_objects.AcmeAccountKey.key_pem_md5 == pem_md5
    )
    if is_active:
        q = q.filter(model_objects.AcmeAccountKey.is_active.op("IS")(True))
    item = q.first()
    return item


def get__AcmeAccountKey__GlobalDefault(ctx, active_only=None):
    q = ctx.dbSession.query(model_objects.AcmeAccountKey).filter(
        model_objects.AcmeAccountKey.is_global_default.op("IS")(True)
    )
    if active_only:
        q = q.filter(model_objects.AcmeAccountKey.is_active.op("IS")(True))
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__AcmeAuthorization__core(ctx, active_only=False, expired_only=False):
    query = ctx.dbSession.query(model_objects.AcmeAuthorization)
    if expired_only:
        active_only = True
    if active_only:
        query = query.filter(
            model_objects.AcmeAuthorization.acme_status_authorization_id.in_(
                model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
            )
        )
    if expired_only:
        query = query.filter(
            model_objects.AcmeAuthorization.timestamp_expires.op("IS NOT")(None),
            model_objects.AcmeAuthorization.timestamp_expires < ctx.timestamp,
        )
    return query


def get__AcmeAuthorization__count(ctx, active_only=False, expired_only=False):
    query = _get__AcmeAuthorization__core(
        ctx, active_only=active_only, expired_only=expired_only
    )
    counted = query.count()
    return counted


def get__AcmeAuthorization__paginated(
    ctx, limit=None, offset=0, active_only=False, expired_only=False
):
    query = _get__AcmeAuthorization__core(
        ctx, active_only=active_only, expired_only=expired_only
    )
    query = (
        query.order_by(model_objects.AcmeAuthorization.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items = query.all()
    return items


def get__AcmeAuthorization__by_id(ctx, item_id, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.AcmeAuthorization).filter(
        model_objects.AcmeAuthorization.id == item_id
    )
    item = q.first()
    return item


def get__AcmeAuthorizations__by_ids(ctx, item_ids, acme_account_key_id=None):
    q = ctx.dbSession.query(model_objects.AcmeAuthorization).filter(
        model_objects.AcmeAuthorization.id.in_(item_ids)
    )
    if acme_account_key_id is not None:
        q = q.join(
            model_objects.AcmeOrder,
            model_objects.AcmeAuthorization.acme_order_id__created
            == model_objects.AcmeOrder.id,
        ).filter(model_objects.AcmeOrder.acme_account_key_id == acme_account_key_id)
    items = q.all()
    return items


def get__AcmeAuthorization__by_authorization_url(ctx, authorization_url):
    q = ctx.dbSession.query(model_objects.AcmeAuthorization).filter(
        model_objects.AcmeAuthorization.authorization_url == authorization_url
    )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__AcmeAuthorization__by_AcmeAccountKeyId__core(
    ctx, acme_account_key_id, active_only=False, expired_only=False
):
    if expired_only:
        active_only = True
    query = (
        ctx.dbSession.query(model_objects.AcmeAuthorization)
        .join(
            model_objects.AcmeOrder2AcmeAuthorization,
            model_objects.AcmeOrder2AcmeAuthorization.acme_authorization_id
            == model_objects.AcmeAuthorization.id,
        )
        .join(
            model_objects.AcmeOrder,
            model_objects.AcmeOrder2AcmeAuthorization.acme_order_id
            == model_objects.AcmeOrder.id,
        )
        .filter(model_objects.AcmeOrder.acme_account_key_id == acme_account_key_id)
    )
    if active_only:
        query = query.filter(
            model_objects.AcmeAuthorization.acme_status_authorization_id.in_(
                model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
            )
        )
    if expired_only:
        query = query.filter(
            model_objects.AcmeAuthorization.timestamp_expires.op("IS NOT")(None),
            model_objects.AcmeAuthorization.timestamp_expires < ctx.timestamp,
        )
    return query


def get__AcmeAuthorization__by_AcmeAccountKeyId__count(
    ctx, acme_account_key_id, active_only=False, expired_only=False
):
    query = _get__AcmeAuthorization__by_AcmeAccountKeyId__core(
        ctx, acme_account_key_id, active_only=active_only, expired_only=expired_only
    )
    return query.count()


def get__AcmeAuthorization__by_AcmeAccountKeyId__paginated(
    ctx,
    acme_account_key_id,
    active_only=False,
    expired_only=False,
    limit=None,
    offset=0,
):
    query = _get__AcmeAuthorization__by_AcmeAccountKeyId__core(
        ctx, acme_account_key_id, active_only=active_only, expired_only=expired_only
    )
    query = (
        query.order_by(model_objects.AcmeAuthorization.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeAuthorizations = query.all()
    return dbAcmeAuthorizations


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAuthorization__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeAuthorization)
        .filter(model_objects.AcmeAuthorization.domain_id == domain_id)
        .count()
    )
    return counted


def get__AcmeAuthorization__by_DomainId__paginated(
    ctx, domain_id, limit=None, offset=0,
):
    query = (
        ctx.dbSession.query(model_objects.AcmeAuthorization)
        .filter(model_objects.AcmeAuthorization.domain_id == domain_id)
        .order_by(model_objects.AcmeAuthorization.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeAuthorizations = query.all()
    return dbAcmeAuthorizations


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeChallenge__count(ctx, active_only=None):
    q = ctx.dbSession.query(model_objects.AcmeChallenge)
    if active_only:
        q = q.filter(
            model_objects.AcmeChallenge.acme_status_challenge_id.in_(
                model_utils.Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE
            )
        )
    return q.count()


def get__AcmeChallenge__paginated(ctx, limit=None, offset=0, active_only=None):
    q = ctx.dbSession.query(model_objects.AcmeChallenge)
    if active_only:
        q = q.filter(
            model_objects.AcmeChallenge.acme_status_challenge_id.in_(
                model_utils.Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE
            )
        )
    q = q.order_by(model_objects.AcmeChallenge.id.desc()).limit(limit).offset(offset)
    dbAcmeChallenges = q.all()
    return dbAcmeChallenges


def get__AcmeChallenge__by_id(ctx, id):
    item = ctx.dbSession.query(model_objects.AcmeChallenge).get(id)
    return item


def get__AcmeChallenge__by_challenge_url(ctx, challenge_url):
    q = ctx.dbSession.query(model_objects.AcmeChallenge).filter(
        model_objects.AcmeChallenge.challenge_url == challenge_url
    )
    item = q.first()
    return item


def get__AcmeChallenge__challenged(ctx, domain_name, challenge):
    # todo - ensure the AcmeAuthorization or AcmeOrderless is active
    # see https://tools.ietf.org/html/rfc8555#section-8.3
    # GET : /path/to/{token}
    # the following two are IDENTICAL:
    # RESPONSE : {keyauth}
    # RESPONSE : {token}.{thumbprint}
    active_request = (
        ctx.dbSession.query(model_objects.AcmeChallenge)
        .join(
            model_objects.Domain,
            model_objects.AcmeChallenge.domain_id == model_objects.Domain.id,
        )
        .filter(
            model_objects.AcmeChallenge.token == challenge,
            sqlalchemy.func.lower(model_objects.Domain.domain_name)
            == sqlalchemy.func.lower(domain_name),
        )
        .options(sqlalchemy.orm.contains_eager("domain"),)
        .first()
    )
    return active_request


def get__AcmeChallenge__by_AcmeAuthorizationId__count(ctx, acme_authorization_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeChallenge)
        .filter(
            model_objects.AcmeChallenge.acme_authorization_id == acme_authorization_id
        )
        .count()
    )
    return counted


def get__AcmeChallenge__by_AcmeAuthorizationId__paginated(
    ctx, acme_authorization_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.AcmeChallenge)
        .filter(
            model_objects.AcmeChallenge.acme_authorization_id == acme_authorization_id
        )
        .order_by(model_objects.AcmeChallenge.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeChallenge__by_DomainId__active(ctx, domain_id):
    """
    AcmeStatus Codes
          Challenge["pending" or "processing"]
        + Authorization ["pending"] + ["*discovered*"]
        + Order ["pending"]
    - - - - - - - - - - - - - - - - - - - - - - - - -
    """
    # !!!: blocking AcmeChallenges
    # a domain can have one and only one active challenge
    query = (
        ctx.dbSession.query(model_objects.AcmeChallenge)
        # Path1: AcmeChallenge>AcmeAuthorization>AcmeOrder2AcmeAuthorization>AcmeOrder
        .join(
            model_objects.AcmeAuthorization,
            model_objects.AcmeChallenge.acme_authorization_id
            == model_objects.AcmeAuthorization.id,
            isouter=True,
        )
        .join(
            model_objects.AcmeOrder2AcmeAuthorization,
            model_objects.AcmeAuthorization.id
            == model_objects.AcmeOrder2AcmeAuthorization.acme_order_id,
            isouter=True,
        )
        .join(
            model_objects.AcmeOrder,
            model_objects.AcmeOrder2AcmeAuthorization.acme_order_id
            == model_objects.AcmeOrder.id,
            isouter=True,
        )
        # Path2: AcmeChallenge>AcmeOrderless
        .join(
            model_objects.AcmeOrderless,
            model_objects.AcmeChallenge.acme_orderless_id
            == model_objects.AcmeOrderless.id,
            isouter=True,
        )
        # shared filters
        .filter(
            model_objects.AcmeChallenge.domain_id == domain_id,
            # ???: http challenges only
            # model_objects.AcmeChallenge.acme_challenge_type_id == model_utils.AcmeChallengeType.from_string("http-01"),
            sqlalchemy.or_(
                # Path1 - Order Based Authorizations
                sqlalchemy.and_(
                    model_objects.AcmeChallenge.acme_authorization_id.op("IS NOT")(
                        None
                    ),
                    model_objects.AcmeChallenge.acme_status_challenge_id.in_(
                        model_utils.Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE
                    ),
                    model_objects.AcmeAuthorization.acme_status_authorization_id.in_(
                        model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
                    ),
                    model_objects.AcmeOrder.acme_status_order_id.in_(
                        model_utils.Acme_Status_Order.IDS_BLOCKING
                    ),
                    # TOO LAX: model_objects.AcmeOrder.is_processing.op("IS")(True),
                ),
                # Path2 - Orderless
                sqlalchemy.and_(
                    model_objects.AcmeChallenge.acme_orderless_id.op("IS NOT")(None),
                    model_objects.AcmeOrderless.is_processing.op("IS")(True),
                ),
            ),
        )
    )
    return query.first()


def get__AcmeChallenge__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeChallenge)
        .filter(model_objects.AcmeChallenge.domain_id == domain_id)
        .count()
    )
    return counted


def get__AcmeChallenge__by_DomainId__paginated(ctx, domain_id, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(model_objects.AcmeChallenge)
        .filter(model_objects.AcmeChallenge.domain_id == domain_id)
        .order_by(model_objects.AcmeChallenge.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeChallengePoll__count(ctx):
    counted = ctx.dbSession.query(model_objects.AcmeChallengePoll).count()
    return counted


def get__AcmeChallengePoll__paginated(
    ctx, limit=None, offset=0,
):
    query = ctx.dbSession.query(model_objects.AcmeChallengePoll)
    query = (
        query.order_by(model_objects.AcmeChallengePoll.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeChallengePolls = query.all()
    return dbAcmeChallengePolls


def get__AcmeChallengePoll__by_id(ctx, id):
    item = ctx.dbSession.query(model_objects.AcmeChallengePoll).get(id)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeChallengeUnknownPoll__count(ctx):
    counted = ctx.dbSession.query(model_objects.AcmeChallengeUnknownPoll).count()
    return counted


def get__AcmeChallengeUnknownPoll__paginated(
    ctx, limit=None, offset=0,
):
    query = ctx.dbSession.query(model_objects.AcmeChallengeUnknownPoll)
    query = (
        query.order_by(model_objects.AcmeChallengeUnknownPoll.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeChallengeUnknownPolls = query.all()
    return dbAcmeChallengeUnknownPolls


def get__AcmeChallengeUnknownPoll__by_id(ctx, id):
    item = ctx.dbSession.query(model_objects.AcmeChallengeUnknownPoll).get(id)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeEventLogs__by_AcmeOrderId__count(ctx, acme_order_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeEventLog)
        .filter(model_objects.AcmeEventLog.acme_order_id == acme_order_id)
        .count()
    )
    return counted


def get__AcmeEventLogs__by_AcmeOrderId__paginated(
    ctx, acme_order_id, limit=None, offset=0,
):
    query = (
        ctx.dbSession.query(model_objects.AcmeEventLog)
        .filter(model_objects.AcmeEventLog.acme_order_id == acme_order_id)
        .order_by(model_objects.AcmeEventLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeOrderless__count(ctx):
    counted = ctx.dbSession.query(model_objects.AcmeOrderless).count()
    return counted


def get__AcmeOrderless__paginated(ctx, limit=None, offset=0):
    query = ctx.dbSession.query(model_objects.AcmeOrderless)
    query = (
        query.order_by(model_objects.AcmeOrderless.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeOrderlesss = query.all()
    return dbAcmeOrderlesss


def get__AcmeOrderless__by_id(ctx, order_id, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.AcmeOrderless).filter(
        model_objects.AcmeOrderless.id == order_id
    )
    item = q.first()
    return item


def get__AcmeOrderless__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeOrderless)
        .join(
            model_objects.AcmeChallenge,
            model_objects.AcmeOrderless.id
            == model_objects.AcmeChallenge.acme_orderless_id,
        )
        .filter(model_objects.AcmeChallenge.domain_id == domain_id)
        .count()
    )
    return counted


def get__AcmeOrderless__by_DomainId__paginated(ctx, domain_id, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(model_objects.AcmeOrderless)
        .join(
            model_objects.AcmeChallenge,
            model_objects.AcmeOrderless.id
            == model_objects.AcmeChallenge.acme_orderless_id,
        )
        .filter(model_objects.AcmeChallenge.domain_id == domain_id)
        .order_by(model_objects.AcmeChallenge.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeOrder__count(ctx, active_only=None):
    query = ctx.dbSession.query(model_objects.AcmeOrder)
    if active_only:
        query = query.filter(model_objects.AcmeOrder.is_processing.op("IS")(True))
    return query.count()


def get__AcmeOrder__paginated(ctx, active_only=None, limit=None, offset=0):
    query = ctx.dbSession.query(model_objects.AcmeOrder)
    if active_only:
        query = query.filter(model_objects.AcmeOrder.is_processing.op("IS")(True))
    query = (
        query.order_by(model_objects.AcmeOrder.id.desc()).limit(limit).offset(offset)
    )
    dbAcmeOrders = query.all()
    return dbAcmeOrders


def get__AcmeOrder__by_id(ctx, order_id, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.AcmeOrder).filter(
        model_objects.AcmeOrder.id == order_id
    )
    item = q.first()
    return item


def get__AcmeOrder__by_CertificateRequest__count(ctx, certificate_request_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .filter(
            model_objects.AcmeOrder.certificate_request_id == certificate_request_id
        )
        .count()
    )
    return counted


def get__AcmeOrder__by_CertificateRequest__paginated(
    ctx, certificate_request_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .filter(
            model_objects.AcmeOrder.certificate_request_id == certificate_request_id
        )
        .order_by(model_objects.AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_AcmeAuthorizationId__count(ctx, acme_authorization_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .join(
            model_objects.AcmeOrder2AcmeAuthorization,
            model_objects.AcmeOrder.id
            == model_objects.AcmeOrder2AcmeAuthorization.acme_order_id,
        )
        .filter(
            model_objects.AcmeOrder2AcmeAuthorization.acme_authorization_id
            == acme_authorization_id
        )
        .count()
    )
    return counted


def get__AcmeOrder__by_AcmeAuthorizationId__paginated(
    ctx, acme_authorization_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .join(
            model_objects.AcmeOrder2AcmeAuthorization,
            model_objects.AcmeOrder.id
            == model_objects.AcmeOrder2AcmeAuthorization.acme_order_id,
        )
        .filter(
            model_objects.AcmeOrder2AcmeAuthorization.acme_authorization_id
            == acme_authorization_id
        )
        .order_by(model_objects.AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_AcmeAccountKeyId__count(ctx, acme_account_key_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .filter(model_objects.AcmeOrder.acme_account_key_id == acme_account_key_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_AcmeAccountKeyId__paginated(
    ctx, acme_account_key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .filter(model_objects.AcmeOrder.acme_account_key_id == acme_account_key_id)
        .order_by(model_objects.AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .join(
            model_objects.UniqueFQDNSet,
            model_objects.AcmeOrder.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet.id,
        )
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(model_objects.UniqueFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_DomainId__paginated(
    ctx, domain_id, limit=None, offset=0,
):
    query = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .join(
            model_objects.UniqueFQDNSet,
            model_objects.AcmeOrder.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet.id,
        )
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(model_objects.UniqueFQDNSet2Domain.domain_id == domain_id)
        .order_by(model_objects.AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeOrders = query.all()
    return dbAcmeOrders


def get__AcmeOrder__by_UniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .filter(model_objects.AcmeOrder.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_UniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.AcmeOrder)
        .filter(model_objects.AcmeOrder.unique_fqdn_set_id == unique_fqdn_set_id)
        .order_by(model_objects.AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CACertificate__count(ctx):
    counted = ctx.dbSession.query(model_objects.CACertificate).count()
    return counted


def get__CACertificate__paginated(ctx, limit=None, offset=0, active_only=False):
    q = ctx.dbSession.query(model_objects.CACertificate)
    if active_only:
        q = q.filter(model_objects.CACertificate.count_active_certificates >= 1)
    q = q.order_by(model_objects.CACertificate.id.desc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__CACertificate__by_id(ctx, cert_id):
    dbCACertificate = (
        ctx.dbSession.query(model_objects.CACertificate)
        .filter(model_objects.CACertificate.id == cert_id)
        .first()
    )
    return dbCACertificate


def get__CACertificate__by_pem_text(ctx, cert_pem):
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    dbCertificate = (
        ctx.dbSession.query(model_objects.CACertificate)
        .filter(
            model_objects.CACertificate.cert_pem_md5 == cert_pem_md5,
            model_objects.CACertificate.cert_pem == cert_pem,
        )
        .first()
    )
    return dbCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateRequest__count(ctx):
    counted = ctx.dbSession.query(model_objects.CertificateRequest).count()
    return counted


def get__CertificateRequest__paginated(ctx, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .options(
            sqlalchemy.orm.joinedload("server_certificates"),
            sqlalchemy.orm.subqueryload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
        )
        .order_by(model_objects.CertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateRequest__by_id(ctx, certificate_request_id):
    dbCertificateRequest = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .filter(model_objects.CertificateRequest.id == certificate_request_id)
        .options(
            sqlalchemy.orm.joinedload("server_certificates__5"),
            sqlalchemy.orm.subqueryload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
        )
        .first()
    )
    return dbCertificateRequest


def get__CertificateRequest__by_pem_text(ctx, csr_pem):
    csr_pem = cert_utils.cleanup_pem_text(csr_pem)
    csr_pem_md5 = utils.md5_text(csr_pem)
    dbCertificateRequest = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .filter(
            model_objects.CertificateRequest.csr_pem_md5 == csr_pem_md5,
            model_objects.CertificateRequest.csr_pem == csr_pem,
        )
        .first()
    )
    return dbCertificateRequest


def get__CertificateRequest__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .join(
            model_objects.UniqueFQDNSet,
            model_objects.CertificateRequest.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet.id,
        )
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(model_objects.UniqueFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__CertificateRequest__by_DomainId__paginated(
    ctx, domain_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .join(
            model_objects.UniqueFQDNSet,
            model_objects.CertificateRequest.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet.id,
        )
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(model_objects.UniqueFQDNSet2Domain.domain_id == domain_id)
        .order_by(model_objects.CertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateRequest__by_PrivateKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .filter(model_objects.CertificateRequest.private_key_id == key_id)
        .count()
    )
    return counted


def get__CertificateRequest__by_PrivateKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .filter(model_objects.CertificateRequest.private_key_id == key_id)
        .options(
            sqlalchemy.orm.joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
        .order_by(model_objects.CertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateRequest__by_UniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .filter(
            model_objects.CertificateRequest.unique_fqdn_set_id == unique_fqdn_set_id
        )
        .count()
    )
    return counted


def get__CertificateRequest__by_UniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.CertificateRequest)
        .filter(
            model_objects.CertificateRequest.unique_fqdn_set_id == unique_fqdn_set_id
        )
        .order_by(model_objects.CertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _Domain_inject_exipring_days(ctx, q, expiring_days, order=False):
    """helper function for the count/paginated queries"""
    ServerCertificateMulti = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    ServerCertificateSingle = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
    q = (
        q.outerjoin(
            ServerCertificateMulti,
            model_objects.Domain.server_certificate_id__latest_multi
            == ServerCertificateMulti.id,
        )
        .outerjoin(
            ServerCertificateSingle,
            model_objects.Domain.server_certificate_id__latest_single
            == ServerCertificateSingle.id,
        )
        .filter(
            sqlalchemy.or_(
                sqlalchemy.and_(
                    ServerCertificateMulti.is_active.is_(True),
                    ServerCertificateMulti.timestamp_expires <= _until,
                ),
                sqlalchemy.and_(
                    ServerCertificateSingle.is_active.is_(True),
                    ServerCertificateSingle.timestamp_expires <= _until,
                ),
            )
        )
    )
    if order:
        q = q.order_by(
            model_utils.min_date(
                ServerCertificateMulti.timestamp_expires,
                ServerCertificateSingle.timestamp_expires,
            ).asc()
        )
    return q


def get__Domain__count(ctx, expiring_days=None, active_only=False):
    q = ctx.dbSession.query(model_objects.Domain)
    if active_only and not expiring_days:
        q = q.filter(
            sqlalchemy.or_(
                model_objects.Domain.server_certificate_id__latest_single.op("IS NOT")(
                    None
                ),
                model_objects.Domain.server_certificate_id__latest_multi.op("IS NOT")(
                    None
                ),
            )
        )
    if expiring_days:
        q = _Domain_inject_exipring_days(ctx, q, expiring_days, order=False)
    counted = q.count()
    return counted


def get__Domain__paginated(
    ctx,
    expiring_days=None,
    eagerload_web=False,
    limit=None,
    offset=0,
    active_certs_only=None,
):
    q = ctx.dbSession.query(model_objects.Domain)
    if active_certs_only and not expiring_days:
        q = q.filter(
            sqlalchemy.or_(
                model_objects.Domain.server_certificate_id__latest_single.op("IS NOT")(
                    None
                ),
                model_objects.Domain.server_certificate_id__latest_multi.op("IS NOT")(
                    None
                ),
            )
        )
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.joinedload("server_certificate__latest_single"),
            sqlalchemy.orm.joinedload("server_certificate__latest_multi"),
        )
    if expiring_days:
        q = _Domain_inject_exipring_days(ctx, q, expiring_days, order=True)
    else:
        q = q.order_by(sqlalchemy.func.lower(model_objects.Domain.domain_name).asc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__Domain__core(q, preload=False, eagerload_web=False):
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
        q = q.options(
            sqlalchemy.orm.subqueryload("acme_orders__5"),
            sqlalchemy.orm.subqueryload("certificate_requests__5"),
            sqlalchemy.orm.subqueryload("server_certificates__5"),
        )
    return q


def get__Domain__by_id(ctx, domain_id, preload=False, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.Domain).filter(
        model_objects.Domain.id == domain_id
    )
    if preload:
        q = _get__Domain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


def get__Domain__by_name(
    ctx, domain_name, preload=False, eagerload_web=False, active_only=False
):
    q = ctx.dbSession.query(model_objects.Domain).filter(
        sqlalchemy.func.lower(model_objects.Domain.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    if preload:
        q = _get__Domain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__DomainBlacklisted__by_name(ctx, domain_name):
    q = ctx.dbSession.query(model_objects.DomainBlacklisted).filter(
        sqlalchemy.func.lower(model_objects.DomainBlacklisted.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    item = q.first()
    return item


def get__DomainBlacklisted__count(ctx):
    q = ctx.dbSession.query(model_objects.DomainBlacklisted)
    counted = q.count()
    return counted


def get__DomainBlacklisted__paginated(
    ctx, limit=None, offset=0,
):
    q = (
        ctx.dbSession.query(model_objects.DomainBlacklisted)
        .order_by(
            sqlalchemy.func.lower(model_objects.DomainBlacklisted.domain_name).asc()
        )
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__Domains_challenged__core(ctx):
    """
    AcmeStatus Codes
          Challenge["pending" or "processing"]
        + Authorization ["pending"] + ["*discovered*"]
        + Order ["pending"]
    - - - - - - - - - - - - - - - - - - - - - - - - -
    """
    # !!!: blocking AcmeChallenges
    q = (
        ctx.dbSession.query(model_objects.Domain)
        # domain joins on everything
        .join(
            model_objects.AcmeChallenge,
            model_objects.Domain.id == model_objects.AcmeChallenge.domain_id,
        )
        # Path1: AcmeChallenge>AcmeAuthorization>AcmeOrder2AcmeAuthorization>AcmeOrder
        .join(
            model_objects.AcmeAuthorization,
            model_objects.AcmeChallenge.acme_authorization_id
            == model_objects.AcmeAuthorization.id,
            isouter=True,
        )
        .join(
            model_objects.AcmeOrder2AcmeAuthorization,
            model_objects.AcmeAuthorization.id
            == model_objects.AcmeOrder2AcmeAuthorization.acme_order_id,
            isouter=True,
        )
        .join(
            model_objects.AcmeOrder,
            model_objects.AcmeOrder2AcmeAuthorization.acme_order_id
            == model_objects.AcmeOrder.id,
            isouter=True,
        )
        # Path2: AcmeChallenge>AcmeOrderless
        .join(
            model_objects.AcmeOrderless,
            model_objects.AcmeChallenge.acme_orderless_id
            == model_objects.AcmeOrderless.id,
            isouter=True,
        )
        # shared filters
        .filter(
            # ???: http challenges only
            # model_objects.AcmeChallenge.acme_challenge_type_id == model_utils.AcmeChallengeType.from_string("http-01"),
            sqlalchemy.or_(
                # Path1 - Order Based Authorizations
                sqlalchemy.and_(
                    model_objects.AcmeChallenge.acme_authorization_id.op("IS NOT")(
                        None
                    ),
                    model_objects.AcmeChallenge.acme_status_challenge_id.in_(
                        model_utils.Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE
                    ),
                    model_objects.AcmeAuthorization.acme_status_authorization_id.in_(
                        model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
                    ),
                    model_objects.AcmeOrder.acme_status_order_id.in_(
                        model_utils.Acme_Status_Order.IDS_BLOCKING
                    ),
                    # TOO LAX: model_objects.AcmeOrder.is_processing.op("IS")(True),
                ),
                # Path2 - Orderless
                sqlalchemy.and_(
                    model_objects.AcmeChallenge.acme_orderless_id.op("IS NOT")(None),
                    model_objects.AcmeOrderless.is_processing.op("IS")(True),
                ),
            ),
        )
    )
    return q


def get__Domains_challenged__count(ctx):
    q = _get__Domains_challenged__core(ctx)
    counted = q.count()
    return counted


def get__Domains_challenged__paginated(
    ctx, limit=None, offset=0,
):
    q = _get__Domains_challenged__core(ctx)
    q = q.order_by(sqlalchemy.func.lower(model_objects.Domain.domain_name).asc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__OperationsObjectEvent__count(ctx):
    q = ctx.dbSession.query(model_objects.OperationsObjectEvent)
    counted = q.count()
    return counted


def get__OperationsObjectEvent__paginated(ctx, limit=None, offset=0):
    q = (
        ctx.dbSession.query(model_objects.OperationsObjectEvent)
        .order_by(model_objects.OperationsObjectEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__OperationsObjectEvent__by_id(ctx, event_id, eagerload_log=False):
    q = ctx.dbSession.query(model_objects.OperationsObjectEvent).filter(
        model_objects.OperationsObjectEvent.id == event_id
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


def get__OperationsEvent__count(ctx, event_type_ids=None):
    q = ctx.dbSession.query(model_objects.OperationsEvent)
    if event_type_ids is not None:
        q = q.filter(
            model_objects.OperationsEvent.operations_event_type_id.in_(event_type_ids)
        )
    items_count = q.count()
    return items_count


def get__OperationsEvent__paginated(ctx, event_type_ids=None, limit=None, offset=0):
    q = ctx.dbSession.query(model_objects.OperationsEvent)
    if event_type_ids is not None:
        q = q.filter(
            model_objects.OperationsEvent.operations_event_type_id.in_(event_type_ids)
        )
    items_paged = (
        q.order_by(model_objects.OperationsEvent.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__OperationsEvent__by_id(ctx, event_id, eagerload_log=False):
    q = ctx.dbSession.query(model_objects.OperationsEvent).filter(
        model_objects.OperationsEvent.id == event_id
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


def get__OperationsEvent__certificate_probe__count(ctx):
    counted = (
        ctx.dbSession.query(model_objects.OperationsEvent)
        .filter(
            model_objects.OperationsEvent.operations_event_type_id
            == model_utils.OperationsEventType.from_string("CaCertificate__probe")
        )
        .count()
    )
    return counted


def get__OperationsEvent__certificate_probe__paginated(ctx, limit=None, offset=0):
    paged_items = (
        ctx.dbSession.query(model_objects.OperationsEvent)
        .order_by(model_objects.OperationsEvent.id.desc())
        .filter(
            model_objects.OperationsEvent.operations_event_type_id
            == model_utils.OperationsEventType.from_string("CaCertificate__probe")
        )
        .limit(limit)
        .offset(offset)
        .all()
    )
    return paged_items


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__PrivateKey__count(ctx, active_usage_only=None):
    q = ctx.dbSession.query(model_objects.PrivateKey)
    if active_usage_only:
        q = q.filter(model_objects.PrivateKey.count_active_certificates >= 1)
    counted = q.count()
    return counted


def get__PrivateKey__paginated(ctx, limit=None, offset=0, active_usage_only=None):
    q = ctx.dbSession.query(model_objects.PrivateKey)
    if active_usage_only:
        q = q.filter(model_objects.PrivateKey.count_active_certificates >= 1)
    q = q.order_by(model_objects.PrivateKey.id.desc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__PrivateKey__by_id(ctx, key_id, eagerload_web=False):
    q = ctx.dbSession.query(model_objects.PrivateKey).filter(
        model_objects.PrivateKey.id == key_id
    )
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.subqueryload("certificate_requests__5")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
            sqlalchemy.orm.subqueryload("server_certificates__5")
            .joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain"),
        )
    item = q.first()
    return item


def get__PrivateKey_CurrentWeek_Global(ctx):
    q = ctx.dbSession.query(model_objects.PrivateKey).filter(
        model_objects.PrivateKey.private_key_type_id
        == model_utils.PrivateKeyType.from_string("global_weekly"),
        model_utils.year_week(model_objects.PrivateKey.timestamp_created)
        == model_utils.year_week(ctx.timestamp),
        model_objects.PrivateKey.is_compromised.op("IS NOT")(True),
        model_objects.PrivateKey.is_active.op("IS")(True),
    )
    item = q.first()
    return item


def get__PrivateKey_CurrentDay_Global(ctx):
    q = ctx.dbSession.query(model_objects.PrivateKey).filter(
        model_objects.PrivateKey.private_key_type_id
        == model_utils.PrivateKeyType.from_string("global_daily"),
        model_utils.year_day(model_objects.PrivateKey.timestamp_created)
        == model_utils.year_day(ctx.timestamp),
        model_objects.PrivateKey.is_compromised.op("IS NOT")(True),
        model_objects.PrivateKey.is_active.op("IS")(True),
    )
    item = q.first()
    return item


def get__PrivateKey_CurrentWeek_AcmeAccountKey(ctx, acme_account_key_id):
    q = ctx.dbSession.query(model_objects.PrivateKey).filter(
        model_objects.PrivateKey.private_key_type_id
        == model_utils.PrivateKeyType.from_string("account_weekly"),
        model_utils.year_week(model_objects.PrivateKey.timestamp_created)
        == model_utils.year_week(ctx.timestamp),
        model_objects.PrivateKey.is_compromised.op("IS NOT")(True),
        model_objects.PrivateKey.is_active.op("IS")(True),
        model_objects.PrivateKey.acme_account_key_id__owner == acme_account_key_id,
    )
    item = q.first()
    return item


def get__PrivateKey_CurrentDay_AcmeAccountKey(ctx, acme_account_key_id):
    q = ctx.dbSession.query(model_objects.PrivateKey).filter(
        model_objects.PrivateKey.private_key_type_id
        == model_utils.PrivateKeyType.from_string("account_daily"),
        model_utils.year_day(model_objects.PrivateKey.timestamp_created)
        == model_utils.year_day(ctx.timestamp),
        model_objects.PrivateKey.is_compromised.op("IS NOT")(True),
        model_objects.PrivateKey.is_active.op("IS")(True),
        model_objects.PrivateKey.acme_account_key_id__owner == acme_account_key_id,
    )
    item = q.first()
    return item


def get__PrivateKey__by_pemMd5(ctx, pem_md5, is_active=True):
    q = ctx.dbSession.query(model_objects.PrivateKey).filter(
        model_objects.PrivateKey.key_pem_md5 == pem_md5
    )
    if is_active:
        q = q.filter(model_objects.PrivateKey.is_active.op("IS")(True))
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__PrivateKey__by_AcmeAccountKeyIdOwner__count(ctx, account_key_id):
    counted = (
        ctx.dbSession.query(model_objects.PrivateKey)
        .filter(model_objects.PrivateKey.acme_account_key_id__owner == account_key_id)
        .count()
    )
    return counted


def get__PrivateKey__by_AcmeAccountKeyIdOwner__paginated(
    ctx, account_key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.PrivateKey)
        .filter(model_objects.PrivateKey.acme_account_key_id__owner == account_key_id)
        .order_by(model_objects.PrivateKey.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__QueueDomain__count(ctx, show_all=None, unprocessed_only=None):
    q = ctx.dbSession.query(model_objects.QueueDomain)
    if unprocessed_only and show_all:
        raise ValueError("conflicting arguments")
    if unprocessed_only:
        q = q.filter(
            model_objects.QueueDomain.timestamp_processed.op("IS")(None)
        )  # noqa
    counted = q.count()
    return counted


def get__QueueDomain__paginated(
    ctx, show_all=None, unprocessed_only=None, eagerload_web=None, limit=None, offset=0
):
    q = ctx.dbSession.query(model_objects.QueueDomain)
    if unprocessed_only and show_all:
        raise ValueError("conflicting arguments")
    if unprocessed_only:
        q = q.filter(
            model_objects.QueueDomain.timestamp_processed.op("IS")(None)
        )  # noqa
    q = q.order_by(model_objects.QueueDomain.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__QueueDomain__by_id(ctx, set_id, eagerload_log=None):
    q = ctx.dbSession.query(model_objects.QueueDomain).filter(
        model_objects.QueueDomain.id == set_id
    )
    if eagerload_log:
        q = q.options(
            sqlalchemy.orm.subqueryload("operations_object_events").joinedload(
                "operations_event"
            )
        )
    item = q.first()
    return item


def get__QueueDomain__by_name__single(ctx, domain_name, active_only=True):
    q = ctx.dbSession.query(model_objects.QueueDomain).filter(
        sqlalchemy.func.lower(model_objects.QueueDomain.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    if active_only:
        q = q.filter(model_objects.QueueDomain.is_active.op("IS")(True))
    item = q.first()
    return item


def get__QueueDomain__by_name__many(
    ctx, domain_name, active_only=None, inactive_only=None
):
    q = ctx.dbSession.query(model_objects.QueueDomain).filter(
        sqlalchemy.func.lower(model_objects.QueueDomain.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    if active_only:
        q = q.filter(model_objects.QueueDomain.is_active.op("IS")(True))
    elif inactive_only:
        q = q.filter(model_objects.QueueDomain.is_active.op("IS")(False))
    items = q.all()
    return items


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__OperationsQueueDomainEvent__count(ctx):
    q = ctx.dbSession.query(model_objects.OperationsQueueDomainEvent)
    counted = q.count()
    return counted


def get__OperationsQueueDomainEvent__paginated(ctx, limit=None, offset=0):
    q = (
        ctx.dbSession.query(model_objects.OperationsQueueDomainEvent)
        .options(
            sqlalchemy.orm.joinedload("queue_domain").load_only("domain_name"),
            sqlalchemy.orm.joinedload("domain").load_only("domain_name"),
        )
        .order_by(model_objects.OperationsQueueDomainEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__QueueCertificate__count(
    ctx, unprocessed_only=False, unprocessed_failures_only=None
):
    if unprocessed_failures_only and unprocessed_only:
        raise ValueError("only submit one strategy")
    q = ctx.dbSession.query(model_objects.QueueCertificate)
    if unprocessed_failures_only:
        q = q.filter(
            model_objects.QueueCertificate.timestamp_processed.op("IS")(None),  # noqa
            model_objects.QueueCertificate.timestamp_process_attempt.op("IS NOT")(
                None
            ),  # noqa
            model_objects.QueueCertificate.process_result.op("IS")(False),  # noqa
        )
    if unprocessed_only:
        q = q.filter(
            model_objects.QueueCertificate.timestamp_processed.op("IS")(None)
        )  # noqa
    counted = q.count()
    return counted


def get__QueueCertificate__paginated(
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
    q = ctx.dbSession.query(model_objects.QueueCertificate)
    if unprocessed_failures_only:
        q = q.filter(
            model_objects.QueueCertificate.timestamp_processed.op("IS")(None),  # noqa
            model_objects.QueueCertificate.timestamp_process_attempt.op("IS NOT")(
                None
            ),  # noqa
            model_objects.QueueCertificate.process_result.op("IS")(False),  # noqa
        )
    if unprocessed_only:
        q = q.filter(
            model_objects.QueueCertificate.timestamp_processed.op("IS")(None)
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
    q = q.order_by(model_objects.QueueCertificate.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__QueueCertificate__by_id(ctx, set_id, load_events=None):
    q = ctx.dbSession.query(model_objects.QueueCertificate).filter(
        model_objects.QueueCertificate.id == set_id
    )
    if load_events:
        q = q.options(sqlalchemy.orm.subqueryload("operations_object_events"))
    item = q.first()
    return item


def get__QueueCertificate__by_UniqueFQDNSetId__active(ctx, set_id):
    q = ctx.dbSession.query(model_objects.QueueCertificate).filter(
        model_objects.QueueCertificate.unique_fqdn_set_id == set_id,
        model_objects.QueueCertificate.timestamp_processed.op("IS")(None),
    )
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__ServerCertificate__count(ctx, expiring_days=None, is_active=None):
    q = ctx.dbSession.query(model_objects.ServerCertificate)
    if is_active is not None:
        if is_active is True:
            q = q.filter(model_objects.ServerCertificate.is_active.is_(True))
        elif is_active is False:
            q = q.filter(model_objects.ServerCertificate.is_active.is_(False))
    else:
        if expiring_days:
            _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
            q = q.filter(
                model_objects.ServerCertificate.is_active.is_(True),
                model_objects.ServerCertificate.timestamp_expires <= _until,
            )
    counted = q.count()
    return counted


def get__ServerCertificate__paginated(
    ctx, expiring_days=None, is_active=None, eagerload_web=False, limit=None, offset=0
):
    q = ctx.dbSession.query(model_objects.ServerCertificate)
    if eagerload_web:
        q = q.options(
            sqlalchemy.orm.joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
    if is_active is not None:
        if is_active is True:
            q = q.filter(model_objects.ServerCertificate.is_active.is_(True))
        elif is_active is False:
            q = q.filter(model_objects.ServerCertificate.is_active.is_(False))
        q = q.order_by(model_objects.ServerCertificate.timestamp_expires.asc())
    else:
        if expiring_days:
            _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
            q = q.filter(
                model_objects.ServerCertificate.is_active.is_(True),
                model_objects.ServerCertificate.timestamp_expires <= _until,
            ).order_by(model_objects.ServerCertificate.timestamp_expires.asc())
        else:
            q = q.order_by(model_objects.ServerCertificate.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__ServerCertificate__by_id(ctx, cert_id):
    dbServerCertificate = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(model_objects.ServerCertificate.id == cert_id)
        .options(
            sqlalchemy.orm.subqueryload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
        .first()
    )
    return dbServerCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__ServerCertificate__by_AcmeAccountKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .join(
            model_objects.AcmeOrder,
            model_objects.ServerCertificate.id
            == model_objects.AcmeOrder.server_certificate_id,
        )
        .filter(model_objects.AcmeOrder.acme_account_key_id == key_id)
        .count()
    )
    return counted


def get__ServerCertificate__by_AcmeAccountKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .join(
            model_objects.AcmeOrder,
            model_objects.ServerCertificate.id
            == model_objects.AcmeOrder.server_certificate_id,
        )
        .filter(model_objects.AcmeOrder.acme_account_key_id == key_id)
        .options(
            sqlalchemy.orm.joinedload("unique_fqdn_set")
            .joinedload("to_domains")
            .joinedload("domain")
        )
        .order_by(model_objects.ServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__ServerCertificate__by_CACertificateId__count(ctx, cert_id):
    counted = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(model_objects.ServerCertificate.ca_certificate_id__upchain == cert_id)
        .count()
    )
    return counted


def get__ServerCertificate__by_CACertificateId__paginated(
    ctx, cert_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(model_objects.ServerCertificate.ca_certificate_id__upchain == cert_id)
        .order_by(model_objects.ServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__ServerCertificate__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .join(
            model_objects.UniqueFQDNSet,
            model_objects.ServerCertificate.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet.id,
        )
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(model_objects.UniqueFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__ServerCertificate__by_DomainId__paginated(
    ctx, domain_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .join(
            model_objects.UniqueFQDNSet,
            model_objects.ServerCertificate.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet.id,
        )
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(model_objects.UniqueFQDNSet2Domain.domain_id == domain_id)
        .order_by(model_objects.ServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__ServerCertificate__by_DomainId__latest(ctx, domain_id):
    first = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .join(
            model_objects.UniqueFQDNSet,
            model_objects.ServerCertificate.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet.id,
        )
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.UniqueFQDNSet2Domain.domain_id == domain_id,
            model_objects.ServerCertificate.is_active.op("IS")(True),
        )
        .order_by(model_objects.ServerCertificate.id.desc())
        .first()
    )
    return first


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__ServerCertificate__by_PrivateKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(model_objects.ServerCertificate.private_key_id == key_id)
        .count()
    )
    return counted


def get__ServerCertificate__by_PrivateKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(model_objects.ServerCertificate.private_key_id == key_id)
        .order_by(model_objects.ServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__ServerCertificate__by_UniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(
            model_objects.ServerCertificate.unique_fqdn_set_id == unique_fqdn_set_id
        )
        .count()
    )
    return counted


def get__ServerCertificate__by_UniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(
            model_objects.ServerCertificate.unique_fqdn_set_id == unique_fqdn_set_id
        )
        .order_by(model_objects.ServerCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__ServerCertificate__by_UniqueFQDNSetId__latest_active(ctx, unique_fqdn_set_id):
    item = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(
            model_objects.ServerCertificate.unique_fqdn_set_id == unique_fqdn_set_id
        )
        .filter(model_objects.ServerCertificate.is_active.op("IS")(True))
        .order_by(model_objects.ServerCertificate.timestamp_expires.desc())
        .first()
    )
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__UniqueFQDNSet__count(ctx):
    q = ctx.dbSession.query(model_objects.UniqueFQDNSet)
    counted = q.count()
    return counted


def get__UniqueFQDNSet__paginated(ctx, eagerload_web=False, limit=None, offset=0):
    q = ctx.dbSession.query(model_objects.UniqueFQDNSet)
    if eagerload_web:
        q = q.options(sqlalchemy.orm.joinedload("to_domains").joinedload("domain"))
    q = q.order_by(model_objects.UniqueFQDNSet.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__UniqueFQDNSet__by_id(ctx, set_id):
    item = (
        ctx.dbSession.query(model_objects.UniqueFQDNSet)
        .filter(model_objects.UniqueFQDNSet.id == set_id)
        .options(sqlalchemy.orm.subqueryload("to_domains").joinedload("domain"))
        .first()
    )
    return item


def get__UniqueFQDNSet__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(model_objects.UniqueFQDNSet)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(model_objects.UniqueFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__UniqueFQDNSet__by_DomainId__paginated(ctx, domain_id, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(model_objects.UniqueFQDNSet)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.UniqueFQDNSet.id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(model_objects.UniqueFQDNSet2Domain.domain_id == domain_id)
        .order_by(model_objects.UniqueFQDNSet.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
