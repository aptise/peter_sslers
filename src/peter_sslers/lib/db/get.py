# stdlib
import datetime
import logging

# pypi
import cert_utils
import sqlalchemy
from sqlalchemy.orm import contains_eager
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import subqueryload

# localapp
from ...model import utils as model_utils
from ...model.objects import AcmeAccount
from ...model.objects import AcmeAccountKey
from ...model.objects import AcmeAccountProvider
from ...model.objects import AcmeAuthorization
from ...model.objects import AcmeChallenge
from ...model.objects import AcmeChallengePoll
from ...model.objects import AcmeChallengeUnknownPoll
from ...model.objects import AcmeDnsServer
from ...model.objects import AcmeDnsServerAccount
from ...model.objects import AcmeEventLog
from ...model.objects import AcmeOrder
from ...model.objects import AcmeOrder2AcmeAuthorization
from ...model.objects import AcmeOrderless
from ...model.objects import CertificateCA
from ...model.objects import CertificateCAChain
from ...model.objects import CertificateCAPreference
from ...model.objects import CertificateRequest
from ...model.objects import CertificateSigned
from ...model.objects import CertificateSignedChain
from ...model.objects import CoverageAssuranceEvent
from ...model.objects import Domain
from ...model.objects import DomainAutocert
from ...model.objects import DomainBlocklisted
from ...model.objects import OperationsEvent
from ...model.objects import OperationsObjectEvent
from ...model.objects import PrivateKey
from ...model.objects import QueueCertificate
from ...model.objects import QueueDomain
from ...model.objects import RootStore
from ...model.objects import RootStoreVersion
from ...model.objects import UniqueFQDNSet
from ...model.objects import UniqueFQDNSet2Domain


# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


def get__AcmeEventLog__count(ctx):
    counted = ctx.dbSession.query(AcmeEventLog).count()
    return counted


def get__AcmeEventLog__paginated(ctx, limit=None, offset=0):
    query = (
        ctx.dbSession.query(AcmeEventLog)
        .order_by(AcmeEventLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeEventLogs = query.all()
    return dbAcmeEventLogs


def get__AcmeEventLog__by_id(ctx, id_):
    item = ctx.dbSession.query(AcmeEventLog).get(id_)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAccountProvider__default(ctx):
    dbAcmeAccountProvider_default = (
        ctx.dbSession.query(AcmeAccountProvider)
        .filter(
            AcmeAccountProvider.is_default.is_(True),
        )
        .first()
    )
    return dbAcmeAccountProvider_default


def get__AcmeAccountProvider__by_name(ctx, name):
    query = ctx.dbSession.query(AcmeAccountProvider).filter(
        sqlalchemy.func.lower(AcmeAccountProvider.name) == name.lower()
    )
    return query.first()


def get__AcmeAccountProvider__by_server(ctx, server):
    query = ctx.dbSession.query(AcmeAccountProvider).filter(
        AcmeAccountProvider.server == server
    )
    return query.first()


def get__AcmeAccountProviders__paginated(ctx, limit=None, offset=0, is_enabled=None):
    query = ctx.dbSession.query(AcmeAccountProvider)
    if is_enabled is True:
        query = query.filter(AcmeAccountProvider.is_enabled.is_(True))
    query = query.order_by(AcmeAccountProvider.id.desc()).limit(limit).offset(offset)
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAccount__count(ctx):
    counted = ctx.dbSession.query(AcmeAccount).count()
    return counted


def get__AcmeAccount__paginated(ctx, limit=None, offset=0, active_only=False):
    query = ctx.dbSession.query(AcmeAccount)
    if active_only:
        query = query.filter(AcmeAccount.is_active.is_(True))
    query = query.order_by(AcmeAccount.id.desc()).limit(limit).offset(offset)
    dbAcmeAccounts = query.all()
    return dbAcmeAccounts


def get__AcmeAccount__by_id(ctx, acme_account_id):
    q = ctx.dbSession.query(AcmeAccount).filter(AcmeAccount.id == acme_account_id)
    item = q.first()
    return item


def get__AcmeAccount__by_pemMd5(ctx, pem_md5, is_active=True):
    q = (
        ctx.dbSession.query(AcmeAccount)
        .join(
            AcmeAccountKey,
            AcmeAccount.id == AcmeAccountKey.acme_account_id,
        )
        .filter(AcmeAccountKey.key_pem_md5 == pem_md5)
        .options(contains_eager(AcmeAccount.acme_account_key))
    )
    if is_active:
        q = q.filter(AcmeAccount.is_active.is_(True))
        q = q.filter(AcmeAccountKey.is_active.is_(True))
    item = q.first()
    return item


def get__AcmeAccount__GlobalDefault(ctx, active_only=None):
    q = ctx.dbSession.query(AcmeAccount).filter(AcmeAccount.is_global_default.is_(True))
    if active_only:
        q = q.filter(AcmeAccount.is_active.is_(True))
    item = q.first()
    return item


def get__AcmeAccount__by_account_url(ctx, account_url):
    q = ctx.dbSession.query(AcmeAccount).filter(AcmeAccount.account_url == account_url)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAccountKey__by_AcmeAccountId__count(ctx, acme_account_id):
    counted = (
        ctx.dbSession.query(AcmeAccountKey)
        .filter(AcmeAccountKey.acme_account_id == acme_account_id)
        .count()
    )
    return counted


def get__AcmeAccountKey__by_AcmeAccountId__paginated(
    ctx,
    acme_account_id,
    limit=None,
    offset=0,
):
    query = (
        ctx.dbSession.query(AcmeAccountKey)
        .filter(AcmeAccountKey.acme_account_id == acme_account_id)
        .order_by(AcmeAccountKey.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeAccountKeys = query.all()
    return dbAcmeAccountKeys


def get__AcmeAccountKey__count(ctx):
    counted = ctx.dbSession.query(AcmeAccountKey).count()
    return counted


def get__AcmeAccountKey__paginated(ctx, limit=None, offset=0, active_only=False):
    query = ctx.dbSession.query(AcmeAccountKey)
    if active_only:
        query = query.filter(AcmeAccountKey.is_active.is_(True))
    query = query.order_by(AcmeAccountKey.id.desc()).limit(limit).offset(offset)
    dbAcmeAccountKeys = query.all()
    return dbAcmeAccountKeys


def get__AcmeAccountKey__by_id(ctx, key_id, eagerload_web=False):
    q = ctx.dbSession.query(AcmeAccountKey).filter(AcmeAccountKey.id == key_id)
    if eagerload_web:
        q = q.options(
            subqueryload(AcmeAccountKey.acme_orders__5)
            .joinedload(AcmeOrder.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
            subqueryload(AcmeAccountKey.certificate_signeds__5)
            .joinedload(CertificateSigned.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
        )
    item = q.first()
    return item


def get__AcmeAccountKey__by_pemMd5(ctx, pem_md5, is_active=True):
    q = ctx.dbSession.query(AcmeAccountKey).filter(
        AcmeAccountKey.key_pem_md5 == pem_md5
    )
    if is_active:
        q = q.filter(AcmeAccountKey.is_active.is_(True))
    item = q.first()
    return item


def get__AcmeAccountKey__by_key_pem(ctx, key_pem):
    q = ctx.dbSession.query(AcmeAccountKey).filter(AcmeAccountKey.key_pem == key_pem)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__AcmeAuthorization__core(ctx, active_only=False, expired_only=False):
    query = ctx.dbSession.query(AcmeAuthorization)
    if expired_only:
        active_only = True
    if active_only:
        query = query.filter(
            AcmeAuthorization.acme_status_authorization_id.in_(
                model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
            )
        )
    if expired_only:
        query = query.filter(
            AcmeAuthorization.timestamp_expires.is_not(None),
            AcmeAuthorization.timestamp_expires < ctx.timestamp,
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
    query = query.order_by(AcmeAuthorization.id.desc()).limit(limit).offset(offset)
    items = query.all()
    return items


def get__AcmeAuthorization__by_id(ctx, item_id, eagerload_web=False):
    q = ctx.dbSession.query(AcmeAuthorization).filter(AcmeAuthorization.id == item_id)
    item = q.first()
    return item


def get__AcmeAuthorizations__by_ids(ctx, item_ids, acme_account_id=None):
    q = ctx.dbSession.query(AcmeAuthorization).filter(
        AcmeAuthorization.id.in_(item_ids)
    )
    if acme_account_id is not None:
        # use the acme_order_id__created to filter down to the account
        q = q.join(
            AcmeOrder,
            AcmeAuthorization.acme_order_id__created == AcmeOrder.id,
        ).filter(AcmeOrder.acme_account_id == acme_account_id)
    items = q.all()
    return items


def get__AcmeAuthorization__by_authorization_url(ctx, authorization_url):
    q = ctx.dbSession.query(AcmeAuthorization).filter(
        AcmeAuthorization.authorization_url == authorization_url
    )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__AcmeAuthorization__by_AcmeAccountId__core(
    ctx, acme_account_id, active_only=False, expired_only=False
):
    if expired_only:
        active_only = True
    query = (
        ctx.dbSession.query(AcmeAuthorization)
        .join(
            AcmeOrder2AcmeAuthorization,
            AcmeOrder2AcmeAuthorization.acme_authorization_id == AcmeAuthorization.id,
        )
        .join(
            AcmeOrder,
            AcmeOrder2AcmeAuthorization.acme_order_id == AcmeOrder.id,
        )
        .filter(AcmeOrder.acme_account_id == acme_account_id)
    )
    if active_only:
        query = query.filter(
            AcmeAuthorization.acme_status_authorization_id.in_(
                model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
            )
        )
    if expired_only:
        query = query.filter(
            AcmeAuthorization.timestamp_expires.is_not(None),
            AcmeAuthorization.timestamp_expires < ctx.timestamp,
        )
    return query


def get__AcmeAuthorization__by_AcmeAccountId__count(
    ctx, acme_account_id, active_only=False, expired_only=False
):
    query = _get__AcmeAuthorization__by_AcmeAccountId__core(
        ctx, acme_account_id, active_only=active_only, expired_only=expired_only
    )
    return query.count()


def get__AcmeAuthorization__by_AcmeAccountId__paginated(
    ctx,
    acme_account_id,
    active_only=False,
    expired_only=False,
    limit=None,
    offset=0,
):
    query = _get__AcmeAuthorization__by_AcmeAccountId__core(
        ctx, acme_account_id, active_only=active_only, expired_only=expired_only
    )
    query = query.order_by(AcmeAuthorization.id.desc()).limit(limit).offset(offset)
    dbAcmeAuthorizations = query.all()
    return dbAcmeAuthorizations


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAuthorization__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(AcmeAuthorization)
        .filter(AcmeAuthorization.domain_id == domain_id)
        .count()
    )
    return counted


def get__AcmeAuthorization__by_DomainId__paginated(
    ctx,
    domain_id,
    limit=None,
    offset=0,
):
    query = (
        ctx.dbSession.query(AcmeAuthorization)
        .filter(AcmeAuthorization.domain_id == domain_id)
        .order_by(AcmeAuthorization.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeAuthorizations = query.all()
    return dbAcmeAuthorizations


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__AcmeChallenge__filter(
    q, active_only=None, resolved_only=None, processing_only=None
):
    # shared filtering for `AcmeChallenge`
    q_filter = None
    if active_only:
        q_filter = model_utils.Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE
    elif resolved_only:
        q_filter = model_utils.Acme_Status_Challenge.IDS_RESOLVED
    elif processing_only:
        q_filter = model_utils.Acme_Status_Challenge.IDS_PROCESSING
    #
    if q_filter:
        q = q.filter(AcmeChallenge.acme_status_challenge_id.in_(q_filter))
    return q


def get__AcmeChallenge__count(
    ctx, active_only=None, resolved_only=None, processing_only=None
):
    q = ctx.dbSession.query(AcmeChallenge)
    q = _get__AcmeChallenge__filter(
        q,
        active_only=active_only,
        resolved_only=resolved_only,
        processing_only=processing_only,
    )
    return q.count()


def get__AcmeChallenge__paginated(
    ctx,
    limit=None,
    offset=0,
    active_only=None,
    resolved_only=None,
    processing_only=None,
):
    q = ctx.dbSession.query(AcmeChallenge)
    q = _get__AcmeChallenge__filter(
        q,
        active_only=active_only,
        resolved_only=resolved_only,
        processing_only=processing_only,
    )
    q = q.order_by(AcmeChallenge.id.desc()).limit(limit).offset(offset)
    dbAcmeChallenges = q.all()
    return dbAcmeChallenges


def get__AcmeChallenge__by_id(ctx, id_):
    item = ctx.dbSession.query(AcmeChallenge).get(id_)
    return item


def get__AcmeChallenge__by_challenge_url(ctx, challenge_url):
    q = ctx.dbSession.query(AcmeChallenge).filter(
        AcmeChallenge.challenge_url == challenge_url
    )
    item = q.first()
    return item


def get__AcmeChallenge__challenged(ctx, domain_name, challenge):
    # ???: Should we ensure the associated AcmeAuthorization/AcmeOrderless is active?
    # see https://tools.ietf.org/html/rfc8555#section-8.3
    # GET : /path/to/{token}
    # the following two are IDENTICAL:
    # RESPONSE : {keyauth}
    # RESPONSE : {token}.{thumbprint}
    active_request = (
        ctx.dbSession.query(AcmeChallenge)
        .join(
            Domain,
            AcmeChallenge.domain_id == Domain.id,
        )
        .filter(
            AcmeChallenge.token == challenge,
            sqlalchemy.func.lower(Domain.domain_name)
            == sqlalchemy.func.lower(domain_name),
        )
        .options(
            contains_eager(AcmeChallenge.domain),
        )
        .first()
    )
    return active_request


def get__AcmeChallenge__by_AcmeAuthorizationId__count(ctx, acme_authorization_id):
    counted = (
        ctx.dbSession.query(AcmeChallenge)
        .filter(AcmeChallenge.acme_authorization_id == acme_authorization_id)
        .count()
    )
    return counted


def get__AcmeChallenge__by_AcmeAuthorizationId__paginated(
    ctx, acme_authorization_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(AcmeChallenge)
        .filter(AcmeChallenge.acme_authorization_id == acme_authorization_id)
        .order_by(AcmeChallenge.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeChallenges__by_DomainId__active(
    ctx, domain_id, acme_challenge_type_id=None
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_id: (required) An id for an instance of :class:`model.objects.Domain`
    :param acme_challenge_type_id: (optional) A specific type of challenge, referencing :class:`model.utils.AcmeChallengeType`

    returns: list

    AcmeStatus Codes
          Challenge["pending" or "processing"]
        + Authorization ["pending"] + ["*discovered*"]
        + Order ["pending"]
    - - - - - - - - - - - - - - - - - - - - - - - - -
    """
    # !!!: blocking AcmeChallenges
    # a domain can have one and only one active challenge
    query = (
        ctx.dbSession.query(AcmeChallenge)
        # Path1: AcmeChallenge>AcmeAuthorization>AcmeOrder2AcmeAuthorization>AcmeOrder
        .join(
            AcmeAuthorization,
            AcmeChallenge.acme_authorization_id == AcmeAuthorization.id,
            isouter=True,
        )
        .join(
            AcmeOrder2AcmeAuthorization,
            AcmeAuthorization.id == AcmeOrder2AcmeAuthorization.acme_order_id,
            isouter=True,
        )
        .join(
            AcmeOrder,
            AcmeOrder2AcmeAuthorization.acme_order_id == AcmeOrder.id,
            isouter=True,
        )
        # Path2: AcmeChallenge>AcmeOrderless
        .join(
            AcmeOrderless,
            AcmeChallenge.acme_orderless_id == AcmeOrderless.id,
            isouter=True,
        )
        # shared filters
        .filter(
            AcmeChallenge.domain_id == domain_id,
            # ???: http challenges only
            # AcmeChallenge.acme_challenge_type_id == model_utils.AcmeChallengeType.from_string("http-01"),
            sqlalchemy.or_(
                # Path1 - Order Based Authorizations
                sqlalchemy.and_(
                    AcmeChallenge.acme_authorization_id.is_not(None),
                    AcmeChallenge.acme_status_challenge_id.in_(
                        model_utils.Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE
                    ),
                    AcmeAuthorization.acme_status_authorization_id.in_(
                        model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
                    ),
                    AcmeOrder.acme_status_order_id.in_(
                        model_utils.Acme_Status_Order.IDS_BLOCKING
                    ),
                    # TOO LAX: AcmeOrder.is_processing.is_(True),
                ),
                # Path2 - Orderless
                sqlalchemy.and_(
                    AcmeChallenge.acme_orderless_id.is_not(None),
                    AcmeOrderless.is_processing.is_(True),
                ),
            ),
        )
    )
    if acme_challenge_type_id:
        query = query.filter(
            AcmeChallenge.acme_challenge_type_id == acme_challenge_type_id
        )
    return query.all()


def get__AcmeChallenge__by_DomainId__count(ctx, domain_id, acme_challenge_type_id=None):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_id: (required) An id for an instance of :class:`model.objects.Domain`
    :param acme_challenge_type_id: (optional) A specific type of challenge, referencing :class:`model.utils.AcmeChallengeType`
    """
    query = ctx.dbSession.query(AcmeChallenge).filter(
        AcmeChallenge.domain_id == domain_id
    )
    if acme_challenge_type_id:
        query = query.filter(
            AcmeChallenge.acme_challenge_type_id == acme_challenge_type_id
        )
    counted = query.count()
    return counted


def get__AcmeChallenge__by_DomainId__paginated(ctx, domain_id, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(AcmeChallenge)
        .filter(AcmeChallenge.domain_id == domain_id)
        .order_by(AcmeChallenge.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeChallengePoll__count(ctx):
    counted = ctx.dbSession.query(AcmeChallengePoll).count()
    return counted


def get__AcmeChallengePoll__paginated(
    ctx,
    limit=None,
    offset=0,
):
    query = ctx.dbSession.query(AcmeChallengePoll)
    query = query.order_by(AcmeChallengePoll.id.desc()).limit(limit).offset(offset)
    dbAcmeChallengePolls = query.all()
    return dbAcmeChallengePolls


def get__AcmeChallengePoll__by_id(ctx, id_):
    item = ctx.dbSession.query(AcmeChallengePoll).get(id_)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeChallengeUnknownPoll__count(ctx):
    counted = ctx.dbSession.query(AcmeChallengeUnknownPoll).count()
    return counted


def get__AcmeChallengeUnknownPoll__paginated(
    ctx,
    limit=None,
    offset=0,
):
    query = ctx.dbSession.query(AcmeChallengeUnknownPoll)
    query = (
        query.order_by(AcmeChallengeUnknownPoll.id.desc()).limit(limit).offset(offset)
    )
    dbAcmeChallengeUnknownPolls = query.all()
    return dbAcmeChallengeUnknownPolls


def get__AcmeChallengeUnknownPoll__by_id(ctx, id_):
    item = ctx.dbSession.query(AcmeChallengeUnknownPoll).get(id_)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeDnsServer__by_root_url(ctx, root_url):
    q = ctx.dbSession.query(AcmeDnsServer).filter(AcmeDnsServer.root_url == root_url)
    return q.first()


def get__AcmeDnsServer__GlobalDefault(ctx):
    q = ctx.dbSession.query(AcmeDnsServer).filter(
        AcmeDnsServer.is_global_default.is_(True)
    )
    return q.first()


def get__AcmeDnsServer__by_id(ctx, id_):
    item = ctx.dbSession.query(AcmeDnsServer).get(id_)
    return item


def get__AcmeDnsServer__count(ctx):
    counted = ctx.dbSession.query(AcmeDnsServer).count()
    return counted


def get__AcmeDnsServer__paginated(
    ctx,
    limit=None,
    offset=0,
):
    query = (
        ctx.dbSession.query(AcmeDnsServer)
        .order_by(AcmeDnsServer.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeDnsServerAccount__by_id(ctx, id_):
    item = ctx.dbSession.query(AcmeDnsServerAccount).get(id_)
    return item


def get__AcmeDnsServerAccounts__by_ids(ctx, ids):
    items = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(AcmeDnsServerAccount.id.in_(ids))
        .all()
    )
    return items


def get__AcmeDnsServerAccount__count(ctx):
    counted = ctx.dbSession.query(AcmeDnsServerAccount).count()
    return counted


def get__AcmeDnsServerAccount__paginated(
    ctx,
    limit=None,
    offset=0,
):
    query = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .join(
            Domain,
            AcmeDnsServerAccount.domain_id == Domain.id,
        )
        .order_by(
            sqlalchemy.func.lower(Domain.domain_name).asc(),
            sqlalchemy.func.lower(AcmeDnsServerAccount.fulldomain).asc(),
            AcmeDnsServerAccount.acme_dns_server_id.asc(),
        )
        .options(contains_eager(AcmeDnsServerAccount.domain))
        .limit(limit)
        .offset(offset)
    )
    return query.all()


def get__AcmeDnsServerAccount__by_DomainId(ctx, domain_id):
    item = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(
            AcmeDnsServerAccount.domain_id == domain_id,
        )
        .first()
    )
    return item


def get__AcmeDnsServerAccount__by_AcmeDnsServerId_DomainId(
    ctx, acme_dns_server_id, domain_id
):
    item = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(
            AcmeDnsServerAccount.acme_dns_server_id == acme_dns_server_id,
            AcmeDnsServerAccount.domain_id == domain_id,
        )
        .first()
    )
    return item


def get__AcmeDnsServerAccount__by_AcmeDnsServerId__count(ctx, acme_dns_server_id):
    counted = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(AcmeDnsServerAccount.acme_dns_server_id == acme_dns_server_id)
        .count()
    )
    return counted


def get__AcmeDnsServerAccount__by_AcmeDnsServerId__paginated(
    ctx,
    acme_dns_server_id,
    limit=None,
    offset=0,
):
    query = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(AcmeDnsServerAccount.acme_dns_server_id == acme_dns_server_id)
        .order_by(AcmeDnsServerAccount.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeEventLogs__by_AcmeOrderId__count(ctx, acme_order_id):
    counted = (
        ctx.dbSession.query(AcmeEventLog)
        .filter(AcmeEventLog.acme_order_id == acme_order_id)
        .count()
    )
    return counted


def get__AcmeEventLogs__by_AcmeOrderId__paginated(
    ctx,
    acme_order_id,
    limit=None,
    offset=0,
):
    query = (
        ctx.dbSession.query(AcmeEventLog)
        .filter(AcmeEventLog.acme_order_id == acme_order_id)
        .order_by(AcmeEventLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeOrderless__count(ctx):
    counted = ctx.dbSession.query(AcmeOrderless).count()
    return counted


def get__AcmeOrderless__paginated(ctx, limit=None, offset=0):
    query = ctx.dbSession.query(AcmeOrderless)
    query = query.order_by(AcmeOrderless.id.desc()).limit(limit).offset(offset)
    dbAcmeOrderlesss = query.all()
    return dbAcmeOrderlesss


def get__AcmeOrderless__by_id(ctx, order_id, eagerload_web=False):
    q = ctx.dbSession.query(AcmeOrderless).filter(AcmeOrderless.id == order_id)
    item = q.first()
    return item


def get__AcmeOrderless__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(AcmeOrderless)
        .join(
            AcmeChallenge,
            AcmeOrderless.id == AcmeChallenge.acme_orderless_id,
        )
        .filter(AcmeChallenge.domain_id == domain_id)
        .count()
    )
    return counted


def get__AcmeOrderless__by_DomainId__paginated(ctx, domain_id, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(AcmeOrderless)
        .join(
            AcmeChallenge,
            AcmeOrderless.id == AcmeChallenge.acme_orderless_id,
        )
        .filter(AcmeChallenge.domain_id == domain_id)
        .order_by(AcmeChallenge.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeOrder__count(ctx, active_only=None):
    query = ctx.dbSession.query(AcmeOrder)
    if active_only is not None:
        query = query.filter(AcmeOrder.is_processing.is_(active_only))
    return query.count()


def get__AcmeOrder__paginated(ctx, active_only=None, limit=None, offset=0):
    """
    active_only: how this is invoked:
        None: all
        True: 'active'
        False; finished
    """
    query = ctx.dbSession.query(AcmeOrder)
    if active_only is True:
        query = query.filter(
            AcmeOrder.acme_status_order_id.in_(model_utils.Acme_Status_Order.IDS_active)
        )
    elif active_only is False:
        query = query.filter(
            AcmeOrder.acme_status_order_id.in_(
                model_utils.Acme_Status_Order.IDS_finished
            )
        )
    query = query.order_by(AcmeOrder.id.desc()).limit(limit).offset(offset)
    dbAcmeOrders = query.all()
    return dbAcmeOrders


def get__AcmeOrder__by_id(ctx, order_id, eagerload_web=False):
    q = ctx.dbSession.query(AcmeOrder).filter(AcmeOrder.id == order_id)
    item = q.first()
    return item


def get__AcmeOrder__by_order_url(ctx, order_url):
    q = ctx.dbSession.query(AcmeOrder).filter(AcmeOrder.order_url == order_url)
    item = q.first()
    return item


def get__AcmeOrder__by_CertificateRequest__count(ctx, certificate_request_id):
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.certificate_request_id == certificate_request_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_CertificateRequest__paginated(
    ctx, certificate_request_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.certificate_request_id == certificate_request_id)
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_AcmeAuthorizationId__count(ctx, acme_authorization_id):
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .join(
            AcmeOrder2AcmeAuthorization,
            AcmeOrder.id == AcmeOrder2AcmeAuthorization.acme_order_id,
        )
        .filter(
            AcmeOrder2AcmeAuthorization.acme_authorization_id == acme_authorization_id
        )
        .count()
    )
    return counted


def get__AcmeOrder__by_AcmeAuthorizationId__paginated(
    ctx, acme_authorization_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(AcmeOrder)
        .join(
            AcmeOrder2AcmeAuthorization,
            AcmeOrder.id == AcmeOrder2AcmeAuthorization.acme_order_id,
        )
        .filter(
            AcmeOrder2AcmeAuthorization.acme_authorization_id == acme_authorization_id
        )
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_AcmeAccountId__count(ctx, acme_account_id):
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.acme_account_id == acme_account_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_AcmeAccountId__paginated(
    ctx, acme_account_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.acme_account_id == acme_account_id)
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .join(
            UniqueFQDNSet,
            AcmeOrder.unique_fqdn_set_id == UniqueFQDNSet.id,
        )
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_DomainId__paginated(
    ctx,
    domain_id,
    limit=None,
    offset=0,
):
    query = (
        ctx.dbSession.query(AcmeOrder)
        .join(
            UniqueFQDNSet,
            AcmeOrder.unique_fqdn_set_id == UniqueFQDNSet.id,
        )
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeOrders = query.all()
    return dbAcmeOrders


def get__AcmeOrder__by_UniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_UniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.unique_fqdn_set_id == unique_fqdn_set_id)
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateCA__count(ctx):
    counted = ctx.dbSession.query(CertificateCA).count()
    return counted


def get__CertificateCA__paginated(ctx, limit=None, offset=0):
    q = (
        ctx.dbSession.query(CertificateCA)
        .order_by(CertificateCA.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__CertificateCAPreference__paginated(ctx, limit=None, offset=0):
    q = ctx.dbSession.query(CertificateCAPreference)
    q = q.order_by(CertificateCAPreference.id.asc()).limit(limit).offset(offset)
    q = q.options(joinedload(CertificateCAPreference.certificate_ca))
    items_paged = q.all()
    return items_paged


def get__CertificateCA__by_id(ctx, cert_id):
    dbCertificateCA = (
        ctx.dbSession.query(CertificateCA).filter(CertificateCA.id == cert_id).first()
    )
    return dbCertificateCA


def get__CertificateCAs__by_fingerprint_sha1_substring(ctx, fingerprint_sha1_substring):
    dbCertificateCAs = (
        ctx.dbSession.query(CertificateCA)
        .filter(CertificateCA.fingerprint_sha1.startswith(fingerprint_sha1_substring))
        .all()
    )
    return dbCertificateCAs


def get__CertificateCA__by_fingerprint_sha1(ctx, fingerprint_sha1):
    dbCertificateCA = (
        ctx.dbSession.query(CertificateCA)
        .filter(CertificateCA.fingerprint_sha1 == fingerprint_sha1)
        .one()
    )
    return dbCertificateCA


def get__CertificateCA__by_pem_text(ctx, cert_pem):
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = cert_utils.utils.md5_text(cert_pem)
    dbCertificateCA = (
        ctx.dbSession.query(CertificateCA)
        .filter(
            CertificateCA.cert_pem_md5 == cert_pem_md5,
            CertificateCA.cert_pem == cert_pem,
        )
        .first()
    )
    return dbCertificateCA


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateCAChain__count(ctx):
    counted = ctx.dbSession.query(CertificateCAChain).count()
    return counted


def get__CertificateCAChain__paginated(ctx, limit=None, offset=0, active_only=False):
    q = ctx.dbSession.query(CertificateCAChain)
    if active_only:
        q = q.join(
            CertificateCA,
            CertificateCAChain.certificate_ca_0_id == CertificateCA.id,
        ).filter(CertificateCA.count_active_certificates >= 1)
    q = q.order_by(CertificateCAChain.id.desc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__CertificateCAChain__by_id(ctx, chain_id):
    dbCertificateCAChain = (
        ctx.dbSession.query(CertificateCAChain)
        .filter(CertificateCAChain.id == chain_id)
        .first()
    )
    return dbCertificateCAChain


def get__CertificateCAChain__by_pem_text(ctx, chain_pem):
    chain_pem = cert_utils.cleanup_pem_text(chain_pem)
    chain_pem_md5 = cert_utils.utils.md5_text(chain_pem)
    dbCertificateCAChain = (
        ctx.dbSession.query(CertificateCAChain)
        .filter(
            CertificateCAChain.chain_pem_md5 == chain_pem_md5,
            CertificateCAChain.chain_pem == chain_pem,
        )
        .first()
    )
    return dbCertificateCAChain


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__CertificateCAChain__by_certificateCaId__core(
    ctx, certificate_ca_id, column=None
):
    """
    column is either
        * CertificateCAChain.certificate_ca_0_id
        * CertificateCAChain.certificate_ca_n_id
    """
    query = ctx.dbSession.query(CertificateCAChain).filter(column == certificate_ca_id)
    return query


def get__CertificateCAChain__by_CertificateCAId0__count(ctx, certificate_ca_id):
    query = _get__CertificateCAChain__by_certificateCaId__core(
        ctx, certificate_ca_id, CertificateCAChain.certificate_ca_0_id
    )
    return query.count()


def get__CertificateCAChain__by_CertificateCAId0__paginated(
    ctx, certificate_ca_id, limit=None, offset=0
):
    query = _get__CertificateCAChain__by_certificateCaId__core(
        ctx, certificate_ca_id, CertificateCAChain.certificate_ca_0_id
    )
    items_paged = (
        query.order_by(CertificateCAChain.id.desc()).limit(limit).offset(offset).all()
    )
    return items_paged


def get__CertificateCAChain__by_CertificateCAIdN__count(ctx, certificate_ca_id):
    query = _get__CertificateCAChain__by_certificateCaId__core(
        ctx, certificate_ca_id, CertificateCAChain.certificate_ca_n_id
    )
    return query.count()


def get__CertificateCAChain__by_CertificateCAIdN__paginated(
    ctx, certificate_ca_id, limit=None, offset=0
):
    query = _get__CertificateCAChain__by_certificateCaId__core(
        ctx, certificate_ca_id, CertificateCAChain.certificate_ca_n_id
    )
    items_paged = (
        query.order_by(CertificateCAChain.id.desc()).limit(limit).offset(offset).all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateRequest__count(ctx):
    counted = ctx.dbSession.query(CertificateRequest).count()
    return counted


def get__CertificateRequest__paginated(ctx, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(CertificateRequest)
        .options(
            joinedload(CertificateRequest.certificate_signeds).options(
                subqueryload(CertificateSigned.unique_fqdn_set)
                .joinedload(UniqueFQDNSet.to_domains)
                .joinedload(UniqueFQDNSet2Domain.domain),
            ),
        )
        .order_by(CertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateRequest__by_id(ctx, certificate_request_id):
    dbCertificateRequest = (
        ctx.dbSession.query(CertificateRequest)
        .filter(CertificateRequest.id == certificate_request_id)
        .options(
            joinedload(CertificateRequest.certificate_signeds__5).options(
                subqueryload(CertificateSigned.unique_fqdn_set)
                .joinedload(UniqueFQDNSet.to_domains)
                .joinedload(UniqueFQDNSet2Domain.domain),
            ),
        )
        .first()
    )
    return dbCertificateRequest


def get__CertificateRequest__by_pem_text(ctx, csr_pem):
    csr_pem = cert_utils.cleanup_pem_text(csr_pem)
    csr_pem_md5 = cert_utils.utils.md5_text(csr_pem)
    dbCertificateRequest = (
        ctx.dbSession.query(CertificateRequest)
        .filter(
            CertificateRequest.csr_pem_md5 == csr_pem_md5,
            CertificateRequest.csr_pem == csr_pem,
        )
        .first()
    )
    return dbCertificateRequest


def get__CertificateRequest__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(CertificateRequest)
        .join(
            UniqueFQDNSet,
            CertificateRequest.unique_fqdn_set_id == UniqueFQDNSet.id,
        )
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__CertificateRequest__by_DomainId__paginated(
    ctx, domain_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(CertificateRequest)
        .join(
            UniqueFQDNSet,
            CertificateRequest.unique_fqdn_set_id == UniqueFQDNSet.id,
        )
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
        .order_by(CertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateRequest__by_PrivateKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(CertificateRequest)
        .filter(CertificateRequest.private_key_id == key_id)
        .count()
    )
    return counted


def get__CertificateRequest__by_PrivateKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(CertificateRequest)
        .filter(CertificateRequest.private_key_id == key_id)
        .options(
            subqueryload(CertificateRequest.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
        )
        .order_by(CertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateRequest__by_UniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(CertificateRequest)
        .filter(CertificateRequest.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__CertificateRequest__by_UniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(CertificateRequest)
        .filter(CertificateRequest.unique_fqdn_set_id == unique_fqdn_set_id)
        .order_by(CertificateRequest.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CoverageAssuranceEvent__count(ctx, unresolved_only=None):
    q = ctx.dbSession.query(CoverageAssuranceEvent)
    if unresolved_only:
        q = q.filter(
            CoverageAssuranceEvent.coverage_assurance_resolution_id
            == model_utils.CoverageAssuranceResolution.from_string("unresolved")
        )
    counted = q.count()
    return counted


def get__CoverageAssuranceEvent__paginated(
    ctx, show_all=None, unresolved_only=None, limit=None, offset=0
):
    q = ctx.dbSession.query(CoverageAssuranceEvent)
    if unresolved_only:
        q = q.filter(
            CoverageAssuranceEvent.coverage_assurance_resolution_id
            == model_utils.CoverageAssuranceResolution.from_string("unresolved")
        )
    q = q.order_by(CoverageAssuranceEvent.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__CoverageAssuranceEvent__by_id(ctx, event_id):
    q = ctx.dbSession.query(CoverageAssuranceEvent).filter(
        CoverageAssuranceEvent.id == event_id
    )
    item = q.first()
    return item


def get__CoverageAssuranceEvent__by_parentId__count(
    ctx, parent_id, limit=None, offset=0
):
    q = ctx.dbSession.query(CoverageAssuranceEvent).filter(
        CoverageAssuranceEvent.coverage_assurance_event_id__parent == parent_id
    )
    return q.count()


def get__CoverageAssuranceEvent__by_parentId__paginated(
    ctx, parent_id, limit=None, offset=0
):
    q = ctx.dbSession.query(CoverageAssuranceEvent).filter(
        CoverageAssuranceEvent.coverage_assurance_event_id__parent == parent_id
    )
    q = q.order_by(CoverageAssuranceEvent.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _Domain_inject_exipring_days(ctx, q, expiring_days, order=False):
    """helper function for the count/paginated queries"""
    CertificateSignedMulti = sqlalchemy.orm.aliased(CertificateSigned)
    CertificateSignedSingle = sqlalchemy.orm.aliased(CertificateSigned)
    _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
    q = (
        q.outerjoin(
            CertificateSignedMulti,
            Domain.certificate_signed_id__latest_multi == CertificateSignedMulti.id,
        )
        .outerjoin(
            CertificateSignedSingle,
            Domain.certificate_signed_id__latest_single == CertificateSignedSingle.id,
        )
        .filter(
            sqlalchemy.or_(
                sqlalchemy.and_(
                    CertificateSignedMulti.is_active.is_(True),
                    CertificateSignedMulti.timestamp_not_after <= _until,
                ),
                sqlalchemy.and_(
                    CertificateSignedSingle.is_active.is_(True),
                    CertificateSignedSingle.timestamp_not_after <= _until,
                ),
            )
        )
    )
    if order:
        q = q.order_by(
            model_utils.min_date(
                CertificateSignedMulti.timestamp_not_after,
                CertificateSignedSingle.timestamp_not_after,
            ).asc()
        )
    return q


def get__Domain__count(ctx, expiring_days=None, active_only=False):
    q = ctx.dbSession.query(Domain)
    if active_only and not expiring_days:
        q = q.filter(
            sqlalchemy.or_(
                Domain.certificate_signed_id__latest_single.is_not(None),
                Domain.certificate_signed_id__latest_multi.is_not(None),
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
    q = ctx.dbSession.query(Domain)
    if active_certs_only and not expiring_days:
        q = q.filter(
            sqlalchemy.or_(
                Domain.certificate_signed_id__latest_single.is_not(None),
                Domain.certificate_signed_id__latest_multi.is_not(None),
            )
        )
    if eagerload_web:
        q = q.options(
            joinedload(Domain.certificate_signed__latest_single),
            joinedload(Domain.certificate_signed__latest_multi),
        )
    if expiring_days:
        q = _Domain_inject_exipring_days(ctx, q, expiring_days, order=True)
    else:
        q = q.order_by(sqlalchemy.func.lower(Domain.domain_name).asc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__Domain__core(q, preload=False, eagerload_web=False):
    q = q.options(
        subqueryload(Domain.certificate_signed__latest_single).options(
            joinedload(CertificateSigned.private_key),
            joinedload(CertificateSigned.certificate_signed_chains),
            joinedload(CertificateSigned.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
        ),
        subqueryload(Domain.certificate_signed__latest_multi).options(
            joinedload(CertificateSigned.private_key),
            joinedload(CertificateSigned.certificate_signed_chains),
            joinedload(CertificateSigned.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
        ),
    )
    if eagerload_web:
        q = q.options(
            subqueryload(Domain.acme_orders__5),
            subqueryload(Domain.certificate_requests__5),
            subqueryload(Domain.certificate_signeds__5),
        )
    return q


def get__Domain__by_id(ctx, domain_id, preload=False, eagerload_web=False):
    q = ctx.dbSession.query(Domain).filter(Domain.id == domain_id)
    if preload:
        q = _get__Domain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


def get__Domain__by_name(
    ctx, domain_name, preload=False, eagerload_web=False, active_only=False
):
    q = ctx.dbSession.query(Domain).filter(
        sqlalchemy.func.lower(Domain.domain_name) == sqlalchemy.func.lower(domain_name)
    )
    if preload:
        q = _get__Domain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


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
        ctx.dbSession.query(Domain)
        # domain joins on everything
        .join(
            AcmeChallenge,
            Domain.id == AcmeChallenge.domain_id,
        )
        # Path1: AcmeChallenge>AcmeAuthorization>AcmeOrder2AcmeAuthorization>AcmeOrder
        .join(
            AcmeAuthorization,
            AcmeChallenge.acme_authorization_id == AcmeAuthorization.id,
            isouter=True,
        )
        .join(
            AcmeOrder2AcmeAuthorization,
            AcmeAuthorization.id == AcmeOrder2AcmeAuthorization.acme_order_id,
            isouter=True,
        )
        .join(
            AcmeOrder,
            AcmeOrder2AcmeAuthorization.acme_order_id == AcmeOrder.id,
            isouter=True,
        )
        # Path2: AcmeChallenge>AcmeOrderless
        .join(
            AcmeOrderless,
            AcmeChallenge.acme_orderless_id == AcmeOrderless.id,
            isouter=True,
        )
        # shared filters
        .filter(
            # ???: http challenges only
            # AcmeChallenge.acme_challenge_type_id == model_utils.AcmeChallengeType.from_string("http-01"),
            sqlalchemy.or_(
                # Path1 - Order Based Authorizations
                sqlalchemy.and_(
                    AcmeChallenge.acme_authorization_id.is_not(None),
                    AcmeChallenge.acme_status_challenge_id.in_(
                        model_utils.Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE
                    ),
                    AcmeAuthorization.acme_status_authorization_id.in_(
                        model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
                    ),
                    AcmeOrder.acme_status_order_id.in_(
                        model_utils.Acme_Status_Order.IDS_BLOCKING
                    ),
                    # TOO LAX: AcmeOrder.is_processing.is_(True),
                ),
                # Path2 - Orderless
                sqlalchemy.and_(
                    AcmeChallenge.acme_orderless_id.is_not(None),
                    AcmeOrderless.is_processing.is_(True),
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
    ctx,
    limit=None,
    offset=0,
):
    q = _get__Domains_challenged__core(ctx)
    q = q.order_by(sqlalchemy.func.lower(Domain.domain_name).asc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__DomainAutocert__by_blockingDomainId(ctx, domain_id):
    # block autocerts on a domain if active or within the past 10 minutes
    q = ctx.dbSession.query(DomainAutocert).filter(
        DomainAutocert.id == domain_id,
        sqlalchemy.or_(
            DomainAutocert.is_successful.is_(None),
            sqlalchemy.and_(
                DomainAutocert.is_successful.is_not(None),
                DomainAutocert.timestamp_created
                <= (ctx.timestamp - datetime.timedelta(minutes=10)),
            ),
        ),
    )
    return q.first()


def get__DomainAutocert__count(ctx):
    q = ctx.dbSession.query(DomainAutocert)
    counted = q.count()
    return counted


def get__DomainAutocert__paginated(
    ctx,
    limit=None,
    offset=0,
):
    q = (
        ctx.dbSession.query(DomainAutocert)
        .order_by(DomainAutocert.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__DomainAutocert__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(DomainAutocert)
        .filter(DomainAutocert.domain_id == domain_id)
        .count()
    )
    return counted


def get__DomainAutocert__by_DomainId__paginated(ctx, domain_id, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(DomainAutocert)
        .filter(DomainAutocert.domain_id == domain_id)
        .order_by(DomainAutocert.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__DomainBlocklisted__by_name(ctx, domain_name):
    q = ctx.dbSession.query(DomainBlocklisted).filter(
        sqlalchemy.func.lower(DomainBlocklisted.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    item = q.first()
    return item


def get__DomainBlocklisted__count(ctx):
    q = ctx.dbSession.query(DomainBlocklisted)
    counted = q.count()
    return counted


def get__DomainBlocklisted__paginated(
    ctx,
    limit=None,
    offset=0,
):
    q = (
        ctx.dbSession.query(DomainBlocklisted)
        .order_by(sqlalchemy.func.lower(DomainBlocklisted.domain_name).asc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__OperationsObjectEvent__count(ctx):
    q = ctx.dbSession.query(OperationsObjectEvent)
    counted = q.count()
    return counted


def get__OperationsObjectEvent__paginated(ctx, limit=None, offset=0):
    q = (
        ctx.dbSession.query(OperationsObjectEvent)
        .order_by(OperationsObjectEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__OperationsObjectEvent__by_id(ctx, event_id, eagerload_log=False):
    q = ctx.dbSession.query(OperationsObjectEvent).filter(
        OperationsObjectEvent.id == event_id
    )
    if eagerload_log:
        q = q.options(
            subqueryload(OperationsObjectEvent.operations_event).options(
                joinedload(OperationsEvent.children),
                joinedload(OperationsEvent.parent),
            ),
        )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__OperationsEvent__count(ctx, event_type_ids=None):
    q = ctx.dbSession.query(OperationsEvent)
    if event_type_ids is not None:
        q = q.filter(OperationsEvent.operations_event_type_id.in_(event_type_ids))
    items_count = q.count()
    return items_count


def get__OperationsEvent__paginated(ctx, event_type_ids=None, limit=None, offset=0):
    q = ctx.dbSession.query(OperationsEvent)
    if event_type_ids is not None:
        q = q.filter(OperationsEvent.operations_event_type_id.in_(event_type_ids))
    items_paged = (
        q.order_by(OperationsEvent.id.desc()).limit(limit).offset(offset).all()
    )
    return items_paged


def get__OperationsEvent__by_id(ctx, event_id, eagerload_log=False):
    q = ctx.dbSession.query(OperationsEvent).filter(OperationsEvent.id == event_id)
    if eagerload_log:
        q = q.options(
            subqueryload(OperationsEvent.object_events).options(
                joinedload(OperationsObjectEvent.domain),
                joinedload(OperationsObjectEvent.queue_domain),
            ),
            subqueryload(OperationsEvent.children),
            subqueryload(OperationsEvent.parent),
        )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__PrivateKey__count(ctx, active_usage_only=None):
    q = ctx.dbSession.query(PrivateKey)
    if active_usage_only:
        q = q.filter(PrivateKey.count_active_certificates >= 1)
    counted = q.count()
    return counted


def get__PrivateKey__paginated(ctx, limit=None, offset=0, active_usage_only=None):
    q = ctx.dbSession.query(PrivateKey)
    if active_usage_only:
        q = q.filter(PrivateKey.count_active_certificates >= 1)
    q = q.order_by(PrivateKey.id.desc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__PrivateKey__by_id(ctx, key_id, eagerload_web=False):
    q = ctx.dbSession.query(PrivateKey).filter(PrivateKey.id == key_id)
    if eagerload_web:
        q = q.options(
            subqueryload(PrivateKey.certificate_requests__5)
            .joinedload(CertificateRequest.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
            subqueryload(PrivateKey.certificate_signeds__5)
            .joinedload(CertificateSigned.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
        )
    item = q.first()
    return item


def get__PrivateKey_CurrentWeek_Global(ctx):
    q = ctx.dbSession.query(PrivateKey).filter(
        PrivateKey.private_key_type_id
        == model_utils.PrivateKeyType.from_string("global_weekly"),
        model_utils.year_week(PrivateKey.timestamp_created)
        == model_utils.year_week(ctx.timestamp),
        PrivateKey.is_compromised.is_not(True),
        PrivateKey.is_active.is_(True),
    )
    item = q.first()
    return item


def get__PrivateKey_CurrentDay_Global(ctx):
    q = ctx.dbSession.query(PrivateKey).filter(
        PrivateKey.private_key_type_id
        == model_utils.PrivateKeyType.from_string("global_daily"),
        model_utils.year_day(PrivateKey.timestamp_created)
        == model_utils.year_day(ctx.timestamp),
        PrivateKey.is_compromised.is_not(True),
        PrivateKey.is_active.is_(True),
    )
    item = q.first()
    return item


def get__PrivateKey_CurrentWeek_AcmeAccount(ctx, acme_account_id):
    q = ctx.dbSession.query(PrivateKey).filter(
        PrivateKey.private_key_type_id
        == model_utils.PrivateKeyType.from_string("account_weekly"),
        model_utils.year_week(PrivateKey.timestamp_created)
        == model_utils.year_week(ctx.timestamp),
        PrivateKey.is_compromised.is_not(True),
        PrivateKey.is_active.is_(True),
        PrivateKey.acme_account_id__owner == acme_account_id,
    )
    item = q.first()
    return item


def get__PrivateKey_CurrentDay_AcmeAccount(ctx, acme_account_id):
    q = ctx.dbSession.query(PrivateKey).filter(
        PrivateKey.private_key_type_id
        == model_utils.PrivateKeyType.from_string("account_daily"),
        model_utils.year_day(PrivateKey.timestamp_created)
        == model_utils.year_day(ctx.timestamp),
        PrivateKey.is_compromised.is_not(True),
        PrivateKey.is_active.is_(True),
        PrivateKey.acme_account_id__owner == acme_account_id,
    )
    item = q.first()
    return item


def get__PrivateKey__by_pemMd5(ctx, pem_md5, is_active=True):
    q = ctx.dbSession.query(PrivateKey).filter(PrivateKey.key_pem_md5 == pem_md5)
    if is_active:
        q = q.filter(PrivateKey.is_active.is_(True))
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__PrivateKey__by_AcmeAccountIdOwner__count(ctx, acme_account_id):
    counted = (
        ctx.dbSession.query(PrivateKey)
        .filter(PrivateKey.acme_account_id__owner == acme_account_id)
        .count()
    )
    return counted


def get__PrivateKey__by_AcmeAccountIdOwner__paginated(
    ctx, acme_account_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(PrivateKey)
        .filter(PrivateKey.acme_account_id__owner == acme_account_id)
        .order_by(PrivateKey.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__QueueDomain__count(ctx, show_all=None, unprocessed_only=None):
    q = ctx.dbSession.query(QueueDomain)
    if unprocessed_only and show_all:
        raise ValueError("conflicting arguments")
    if unprocessed_only:
        q = q.filter(QueueDomain.timestamp_processed.is_(None))
    counted = q.count()
    return counted


def get__QueueDomain__paginated(
    ctx, show_all=None, unprocessed_only=None, eagerload_web=None, limit=None, offset=0
):
    q = ctx.dbSession.query(QueueDomain)
    if unprocessed_only and show_all:
        raise ValueError("conflicting arguments")
    if unprocessed_only:
        q = q.filter(QueueDomain.timestamp_processed.is_(None))
    q = q.order_by(QueueDomain.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__QueueDomain__by_id(ctx, set_id, eagerload_log=None):
    q = ctx.dbSession.query(QueueDomain).filter(QueueDomain.id == set_id)
    if eagerload_log:
        q = q.options(
            subqueryload(QueueDomain.operations_object_events).joinedload(
                OperationsObjectEvent.operations_event
            )
        )
    item = q.first()
    return item


def get__QueueDomain__by_name__single(ctx, domain_name, active_only=True):
    q = ctx.dbSession.query(QueueDomain).filter(
        sqlalchemy.func.lower(QueueDomain.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    if active_only:
        q = q.filter(QueueDomain.is_active.is_(True))
    item = q.first()
    return item


def get__QueueDomain__by_name__many(
    ctx, domain_name, active_only=None, inactive_only=None
):
    q = ctx.dbSession.query(QueueDomain).filter(
        sqlalchemy.func.lower(QueueDomain.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    if active_only:
        q = q.filter(QueueDomain.is_active.is_(True))
    elif inactive_only:
        q = q.filter(QueueDomain.is_active.is_(False))
    items = q.all()
    return items


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__QueueCertificate__core(
    ctx,
    failures_only=None,
    successes_only=None,
    unprocessed_only=None,
):
    if (
        sum(
            bool(f)
            for f in (
                failures_only,
                successes_only,
                unprocessed_only,
            )
        )
        > 1
    ):
        raise ValueError("only submit one strategy")
    q = ctx.dbSession.query(QueueCertificate)
    if failures_only:
        q = q.filter(
            QueueCertificate.timestamp_processed.is_not(None),
            QueueCertificate.timestamp_process_attempt.is_not(None),
            QueueCertificate.process_result.is_(False),
        )
    elif successes_only:
        q = q.filter(
            QueueCertificate.timestamp_processed.is_not(None),
            QueueCertificate.timestamp_process_attempt.is_not(None),
            QueueCertificate.process_result.is_(True),
        )
    elif unprocessed_only:
        q = q.filter(QueueCertificate.timestamp_processed.is_(None))
    return q


def get__QueueCertificate__count(
    ctx,
    failures_only=None,
    successes_only=None,
    unprocessed_only=False,
):
    q = _get__QueueCertificate__core(
        ctx,
        failures_only=failures_only,
        successes_only=successes_only,
        unprocessed_only=unprocessed_only,
    )
    counted = q.count()
    return counted


def get__QueueCertificate__paginated(
    ctx,
    failures_only=None,
    successes_only=None,
    unprocessed_only=False,
    eagerload_web=False,
    eagerload_renewal=False,
    limit=None,
    offset=0,
):
    q = _get__QueueCertificate__core(
        ctx,
        failures_only=failures_only,
        successes_only=successes_only,
        unprocessed_only=unprocessed_only,
    )
    if eagerload_web:
        q = q.options(
            joinedload(QueueCertificate.acme_order__source),
            joinedload(QueueCertificate.certificate_signed__source),
            joinedload(QueueCertificate.unique_fqdn_set__source),
            joinedload(QueueCertificate.acme_order__generated),
            joinedload(QueueCertificate.certificate_request__generated),
            joinedload(QueueCertificate.certificate_signed__generated),
            joinedload(QueueCertificate.acme_account).joinedload(
                AcmeAccount.acme_account_key
            ),
            joinedload(QueueCertificate.private_key),
            joinedload(QueueCertificate.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
        )
    elif eagerload_renewal:
        q = q.options(
            joinedload(QueueCertificate.acme_order__source),
            joinedload(QueueCertificate.certificate_signed__source),
            joinedload(QueueCertificate.unique_fqdn_set__source),
            joinedload(QueueCertificate.acme_account).joinedload(
                AcmeAccount.acme_account_key
            ),
            joinedload(QueueCertificate.private_key),
            joinedload(QueueCertificate.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain),
        )
    q = q.order_by(QueueCertificate.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__QueueCertificate__by_id(ctx, set_id, load_events=None):
    q = ctx.dbSession.query(QueueCertificate).filter(QueueCertificate.id == set_id)
    if load_events:
        q = q.options(subqueryload(QueueCertificate.operations_object_events))
    item = q.first()
    return item


def get__QueueCertificate__by_AcmeAccountId__count(ctx, acme_account_id):
    counted = (
        ctx.dbSession.query(QueueCertificate)
        .filter(QueueCertificate.acme_account_id == acme_account_id)
        .count()
    )
    return counted


def get__QueueCertificate__by_AcmeAccountId__paginated(
    ctx, acme_account_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(QueueCertificate)
        .filter(QueueCertificate.acme_account_id == acme_account_id)
        .order_by(QueueCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def _get__QueueCertificate__by_DomainId__core(ctx, domain_id):
    q = (
        ctx.dbSession.query(QueueCertificate)
        .join(
            UniqueFQDNSet,
            QueueCertificate.unique_fqdn_set_id == UniqueFQDNSet.id,
        )
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
    )
    return q


def get__QueueCertificate__by_DomainId__count(ctx, domain_id):
    q = _get__QueueCertificate__by_DomainId__core(ctx, domain_id)
    counted = q.count()
    return counted


def get__QueueCertificate__by_DomainId__paginated(ctx, domain_id, limit=None, offset=0):
    q = _get__QueueCertificate__by_DomainId__core(ctx, domain_id)
    items_paged = (
        q.order_by(QueueCertificate.id.desc()).limit(limit).offset(offset).all()
    )
    return items_paged


def get__QueueCertificate__by_PrivateKeyId__count(ctx, private_key_id):
    counted = (
        ctx.dbSession.query(QueueCertificate)
        .filter(QueueCertificate.private_key_id == private_key_id)
        .count()
    )
    return counted


def get__QueueCertificate__by_PrivateKeyId__paginated(
    ctx, private_key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(QueueCertificate)
        .filter(QueueCertificate.private_key_id == private_key_id)
        .order_by(QueueCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__QueueCertificate__by_UniqueFQDNSetId__active(ctx, set_id):
    q = ctx.dbSession.query(QueueCertificate).filter(
        QueueCertificate.unique_fqdn_set_id == set_id,
        QueueCertificate.timestamp_processed.is_(None),
    )
    items_paged = q.all()
    return items_paged


def get__QueueCertificate__by_UniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(QueueCertificate)
        .filter(QueueCertificate.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__QueueCertificate__by_UniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(QueueCertificate)
        .filter(QueueCertificate.unique_fqdn_set_id == unique_fqdn_set_id)
        .order_by(QueueCertificate.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateSigned__count(ctx, expiring_days=None, is_active=None):
    q = ctx.dbSession.query(CertificateSigned)
    if is_active is not None:
        if is_active is True:
            q = q.filter(CertificateSigned.is_active.is_(True))
        elif is_active is False:
            q = q.filter(CertificateSigned.is_active.is_(False))
    else:
        if expiring_days:
            _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
            q = q.filter(
                CertificateSigned.is_active.is_(True),
                CertificateSigned.timestamp_not_after <= _until,
            )
    counted = q.count()
    return counted


def get__CertificateSigned__paginated(
    ctx, expiring_days=None, is_active=None, eagerload_web=False, limit=None, offset=0
):
    q = ctx.dbSession.query(CertificateSigned)
    if eagerload_web:
        q = q.options(
            joinedload(CertificateSigned.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain)
        )
    if is_active is not None:
        if is_active is True:
            q = q.filter(CertificateSigned.is_active.is_(True))
        elif is_active is False:
            q = q.filter(CertificateSigned.is_active.is_(False))
        # q = q.order_by(CertificateSigned.timestamp_not_after.asc())
        q = q.order_by(CertificateSigned.id.desc())
    else:
        if expiring_days:
            _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
            q = q.filter(
                CertificateSigned.is_active.is_(True),
                CertificateSigned.timestamp_not_after <= _until,
            ).order_by(CertificateSigned.timestamp_not_after.asc())
        else:
            q = q.order_by(CertificateSigned.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__CertificateSigned__by_id(ctx, cert_id):
    dbCertificateSigned = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.id == cert_id)
        .options(
            subqueryload(CertificateSigned.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain)
        )
        .first()
    )
    return dbCertificateSigned


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateSigned__by_AcmeAccountId__count(ctx, acme_account_id):
    counted = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            AcmeOrder,
            CertificateSigned.id == AcmeOrder.certificate_signed_id,
        )
        .filter(AcmeOrder.acme_account_id == acme_account_id)
        .count()
    )
    return counted


def get__CertificateSigned__by_AcmeAccountId__paginated(
    ctx, acme_account_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            AcmeOrder,
            CertificateSigned.id == AcmeOrder.certificate_signed_id,
        )
        .filter(AcmeOrder.acme_account_id == acme_account_id)
        .options(
            joinedload(CertificateSigned.unique_fqdn_set)
            .joinedload(UniqueFQDNSet.to_domains)
            .joinedload(UniqueFQDNSet2Domain.domain)
        )
        .order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__CertificateSigned__by_CertificateCAId__primary(ctx, cert_ca_id):
    """
    we no longer track the Certificate to the CertificateCA directly, but instead
    through the CertificateCAChain
        Certificate > CertificateChains > CertificateCAChain > CertificateCA
    """
    query_core = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            CertificateSignedChain,
            CertificateSigned.id == CertificateSignedChain.certificate_signed_id,
        )
        .join(
            CertificateCAChain,
            CertificateSignedChain.certificate_ca_chain_id == CertificateCAChain.id,
        )
        .filter(CertificateCAChain.certificate_ca_0_id == cert_ca_id)
        .filter(CertificateSignedChain.is_upstream_default.is_(True))
    )
    return query_core


def get__CertificateSigned__by_CertificateCAId__primary__count(ctx, cert_ca_id):
    query_core = _get__CertificateSigned__by_CertificateCAId__primary(ctx, cert_ca_id)
    counted = query_core.count()
    return counted


def get__CertificateSigned__by_CertificateCAId__primary__paginated(
    ctx, cert_ca_id, limit=None, offset=0
):
    query_core = _get__CertificateSigned__by_CertificateCAId__primary(ctx, cert_ca_id)
    items_paged = (
        query_core.order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def _get__CertificateSigned__by_CertificateCAId__alt(ctx, cert_ca_id):
    """
    we no longer track the Certificate to the CertificateCA directly, but instead
    through the CertificateCAChain
        Certificate > CertificateChains > CertificateCAChain > CertificateCA
    """
    query_core = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            CertificateSignedChain,
            CertificateSigned.id == CertificateSignedChain.certificate_signed_id,
        )
        .join(
            CertificateCAChain,
            CertificateSignedChain.certificate_ca_chain_id == CertificateCAChain.id,
        )
        .filter(CertificateCAChain.certificate_ca_0_id == cert_ca_id)
        .filter(CertificateSignedChain.is_upstream_default.isnot(True))
    )
    return query_core


def get__CertificateSigned__by_CertificateCAId__alt__count(ctx, cert_ca_id):
    query_core = _get__CertificateSigned__by_CertificateCAId__alt(ctx, cert_ca_id)
    counted = query_core.count()
    return counted


def get__CertificateSigned__by_CertificateCAId__alt__paginated(
    ctx, cert_ca_id, limit=None, offset=0
):
    query_core = _get__CertificateSigned__by_CertificateCAId__alt(ctx, cert_ca_id)
    items_paged = (
        query_core.order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateSigned__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            UniqueFQDNSet,
            CertificateSigned.unique_fqdn_set_id == UniqueFQDNSet.id,
        )
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__CertificateSigned__by_DomainId__paginated(
    ctx, domain_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            UniqueFQDNSet,
            CertificateSigned.unique_fqdn_set_id == UniqueFQDNSet.id,
        )
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
        .order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateSigned__by_DomainId__latest(ctx, domain_id):
    first = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            UniqueFQDNSet,
            CertificateSigned.unique_fqdn_set_id == UniqueFQDNSet.id,
        )
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            UniqueFQDNSet2Domain.domain_id == domain_id,
            CertificateSigned.is_active.is_(True),
        )
        .order_by(CertificateSigned.id.desc())
        .first()
    )
    return first


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateSigned__by_PrivateKeyId__count(ctx, key_id):
    counted = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.private_key_id == key_id)
        .count()
    )
    return counted


def get__CertificateSigned__by_PrivateKeyId__paginated(
    ctx, key_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.private_key_id == key_id)
        .order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateSigned__by_UniqueFQDNSetId__count(ctx, unique_fqdn_set_id):
    counted = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__CertificateSigned__by_UniqueFQDNSetId__paginated(
    ctx, unique_fqdn_set_id, limit=None, offset=0
):
    items_paged = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.unique_fqdn_set_id == unique_fqdn_set_id)
        .order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateSigned__by_UniqueFQDNSetId__latest_active(ctx, unique_fqdn_set_id):
    item = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.unique_fqdn_set_id == unique_fqdn_set_id)
        .filter(CertificateSigned.is_active.is_(True))
        .order_by(CertificateSigned.timestamp_not_after.desc())
        .first()
    )
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__RootStore__count(ctx):
    q = ctx.dbSession.query(RootStore)
    counted = q.count()
    return counted


def get__RootStore__paginated(ctx, limit=None, offset=0):
    q = (
        ctx.dbSession.query(RootStore)
        .order_by(sqlalchemy.func.lower(RootStore.name).asc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__RootStore__by_id(ctx, root_store_id):
    item = ctx.dbSession.query(RootStore).filter(RootStore.id == root_store_id).first()
    return item


def get__RootStoreVersion__by_id(ctx, root_store_version_id):
    item = (
        ctx.dbSession.query(RootStoreVersion)
        .filter(RootStoreVersion.id == root_store_version_id)
        .first()
    )
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__UniqueFQDNSet__count(ctx):
    q = ctx.dbSession.query(UniqueFQDNSet)
    counted = q.count()
    return counted


def get__UniqueFQDNSet__paginated(ctx, eagerload_web=False, limit=None, offset=0):
    q = ctx.dbSession.query(UniqueFQDNSet)
    if eagerload_web:
        q = q.options(
            joinedload(UniqueFQDNSet.to_domains).joinedload(UniqueFQDNSet2Domain.domain)
        )
    q = q.order_by(UniqueFQDNSet.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__UniqueFQDNSet__by_id(ctx, set_id):
    item = (
        ctx.dbSession.query(UniqueFQDNSet)
        .filter(UniqueFQDNSet.id == set_id)
        .options(
            subqueryload(UniqueFQDNSet.to_domains).joinedload(
                UniqueFQDNSet2Domain.domain
            )
        )
        .first()
    )
    return item


def get__UniqueFQDNSet__by_DomainId__count(ctx, domain_id):
    counted = (
        ctx.dbSession.query(UniqueFQDNSet)
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__UniqueFQDNSet__by_DomainId__paginated(ctx, domain_id, limit=None, offset=0):
    items_paged = (
        ctx.dbSession.query(UniqueFQDNSet)
        .join(
            UniqueFQDNSet2Domain,
            UniqueFQDNSet.id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(UniqueFQDNSet2Domain.domain_id == domain_id)
        .order_by(UniqueFQDNSet.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
