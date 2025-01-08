# stdlib
import datetime
import logging
from typing import Iterable
from typing import List
from typing import Optional
from typing import TYPE_CHECKING

# pypi
import cert_utils
import sqlalchemy
from sqlalchemy.orm import contains_eager
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import subqueryload

# localapp
from ...model import utils as model_utils
from ...model.objects import AcmeAccount
from ...model.objects import AcmeAccountKey
from ...model.objects import AcmeAuthorization
from ...model.objects import AcmeAuthorizationPotential
from ...model.objects import AcmeChallenge
from ...model.objects import AcmeChallengePoll
from ...model.objects import AcmeChallengeUnknownPoll
from ...model.objects import AcmeDnsServer
from ...model.objects import AcmeDnsServerAccount
from ...model.objects import AcmeEventLog
from ...model.objects import AcmeOrder
from ...model.objects import AcmeOrder2AcmeAuthorization
from ...model.objects import AcmeServer
from ...model.objects import AriCheck
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
from ...model.objects import RenewalConfiguration
from ...model.objects import RootStore
from ...model.objects import RootStoreVersion
from ...model.objects import UniqueFQDNSet
from ...model.objects import UniqueFQDNSet2Domain
from ...model.objects import UniquelyChallengedFQDNSet
from ...model.objects import UniquelyChallengedFQDNSet2Domain


if TYPE_CHECKING:
    from ..utils import ApiContext

# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


def get__AcmeEventLog__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(AcmeEventLog).count()
    return counted


def get__AcmeEventLog__paginated(
    ctx: "ApiContext", limit: Optional[int] = None, offset: int = 0
) -> List[AcmeEventLog]:
    query = (
        ctx.dbSession.query(AcmeEventLog)
        .order_by(AcmeEventLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeEventLogs = query.all()
    return dbAcmeEventLogs


def get__AcmeEventLog__by_id(ctx: "ApiContext", id_: int) -> Optional[AcmeEventLog]:
    item = ctx.dbSession.query(AcmeEventLog).get(id_)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeServer__default(
    ctx: "ApiContext",
) -> Optional[AcmeServer]:
    dbAcmeServer_default = (
        ctx.dbSession.query(AcmeServer)
        .filter(
            AcmeServer.is_default.is_(True),
        )
        .first()
    )
    return dbAcmeServer_default


def get__AcmeServer__by_id(ctx: "ApiContext", id_: str) -> Optional[AcmeServer]:
    query = ctx.dbSession.query(AcmeServer).filter(AcmeServer.id == id_)
    return query.first()


def get__AcmeServer__by_name(ctx: "ApiContext", name: str) -> Optional[AcmeServer]:
    query = ctx.dbSession.query(AcmeServer).filter(
        sqlalchemy.func.lower(AcmeServer.name) == name.lower()
    )
    return query.first()


def get__AcmeServer__by_server(ctx: "ApiContext", server: str) -> Optional[AcmeServer]:
    query = ctx.dbSession.query(AcmeServer).filter(AcmeServer.server == server)
    return query.first()


def get__AcmeServers__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
    is_enabled: Optional[bool] = None,
) -> List[AcmeServer]:
    query = ctx.dbSession.query(AcmeServer)
    if is_enabled is True:
        query = query.filter(AcmeServer.is_enabled.is_(True))
    query = query.order_by(AcmeServer.id.desc()).limit(limit).offset(offset)
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAccount__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(AcmeAccount).count()
    return counted


def get__AcmeAccount__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
    active_only: bool = False,
) -> List[AcmeAccount]:
    query = ctx.dbSession.query(AcmeAccount)
    if active_only:
        query = query.filter(AcmeAccount.is_active.is_(True))
    query = query.order_by(AcmeAccount.id.desc()).limit(limit).offset(offset)
    dbAcmeAccounts = query.all()
    return dbAcmeAccounts


def get__AcmeAccount__by_id(
    ctx: "ApiContext", acme_account_id: int
) -> Optional[AcmeAccount]:
    q = ctx.dbSession.query(AcmeAccount).filter(AcmeAccount.id == acme_account_id)
    item = q.first()
    return item


def get__AcmeAccount__by_pemMd5(
    ctx: "ApiContext", pem_md5: str, is_active: bool = True
) -> Optional[AcmeAccount]:
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


def get__AcmeAccount__GlobalDefault(
    ctx: "ApiContext", active_only: Optional[bool] = None
) -> Optional[AcmeAccount]:
    q = ctx.dbSession.query(AcmeAccount).filter(AcmeAccount.is_global_default.is_(True))
    if active_only:
        q = q.filter(AcmeAccount.is_active.is_(True))
    item = q.first()
    return item


def get__AcmeAccount__by_account_url(
    ctx: "ApiContext", account_url: str
) -> Optional[AcmeAccount]:
    q = ctx.dbSession.query(AcmeAccount).filter(AcmeAccount.account_url == account_url)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAccountKey__by_AcmeAccountId__count(
    ctx: "ApiContext",
    acme_account_id: int,
) -> int:
    counted = (
        ctx.dbSession.query(AcmeAccountKey)
        .filter(AcmeAccountKey.acme_account_id == acme_account_id)
        .count()
    )
    return counted


def get__AcmeAccountKey__by_AcmeAccountId__paginated(
    ctx: "ApiContext",
    acme_account_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeAccountKey]:
    query = (
        ctx.dbSession.query(AcmeAccountKey)
        .filter(AcmeAccountKey.acme_account_id == acme_account_id)
        .order_by(AcmeAccountKey.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeAccountKeys = query.all()
    return dbAcmeAccountKeys


def get__AcmeAccountKey__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(AcmeAccountKey).count()
    return counted


def get__AcmeAccountKey__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
    active_only: Optional[bool] = False,
) -> List[AcmeAccountKey]:
    query = ctx.dbSession.query(AcmeAccountKey)
    if active_only:
        query = query.filter(AcmeAccountKey.is_active.is_(True))
    query = query.order_by(AcmeAccountKey.id.desc()).limit(limit).offset(offset)
    dbAcmeAccountKeys = query.all()
    return dbAcmeAccountKeys


def get__AcmeAccountKey__by_id(
    ctx: "ApiContext", key_id: int, eagerload_web: bool = False
) -> Optional[AcmeAccountKey]:
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


def get__AcmeAccountKey__by_pemMd5(
    ctx: "ApiContext", pem_md5: str, is_active: bool = True
) -> Optional[AcmeAccountKey]:
    q = ctx.dbSession.query(AcmeAccountKey).filter(
        AcmeAccountKey.key_pem_md5 == pem_md5
    )
    if is_active:
        q = q.filter(AcmeAccountKey.is_active.is_(True))
    item = q.first()
    return item


def get__AcmeAccountKey__by_key_pem(
    ctx: "ApiContext", key_pem: str
) -> Optional[AcmeAccountKey]:
    q = ctx.dbSession.query(AcmeAccountKey).filter(AcmeAccountKey.key_pem == key_pem)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__AcmeAuthorization__core(
    ctx: "ApiContext", active_only: bool = False, expired_only: bool = False
):
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


def get__AcmeAuthorization__count(
    ctx: "ApiContext", active_only: bool = False, expired_only: bool = False
) -> int:
    query = _get__AcmeAuthorization__core(
        ctx, active_only=active_only, expired_only=expired_only
    )
    counted = query.count()
    return counted


def get__AcmeAuthorization__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
    active_only: bool = False,
    expired_only: bool = False,
) -> List[AcmeAuthorization]:
    query = _get__AcmeAuthorization__core(
        ctx, active_only=active_only, expired_only=expired_only
    )
    query = query.order_by(AcmeAuthorization.id.desc()).limit(limit).offset(offset)
    items = query.all()
    return items


def get__AcmeAuthorization__by_id(
    ctx: "ApiContext", item_id: int, eagerload_web: bool = False
) -> Optional[AcmeAuthorization]:
    q = ctx.dbSession.query(AcmeAuthorization).filter(AcmeAuthorization.id == item_id)
    item = q.first()
    return item


def get__AcmeAuthorizations__by_ids(
    ctx: "ApiContext", item_ids: Iterable[int], acme_account_id: Optional[int] = None
) -> List[AcmeAuthorization]:
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


def get__AcmeAuthorization__by_authorization_url(
    ctx: "ApiContext", authorization_url: str
) -> Optional[AcmeAuthorization]:
    q = ctx.dbSession.query(AcmeAuthorization).filter(
        AcmeAuthorization.authorization_url == authorization_url
    )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__AcmeAuthorization__by_AcmeAccountId__core(
    ctx: "ApiContext",
    acme_account_id: int,
    active_only: bool = False,
    expired_only: bool = False,
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
    ctx: "ApiContext",
    acme_account_id: int,
    active_only: bool = False,
    expired_only: bool = False,
) -> int:
    query = _get__AcmeAuthorization__by_AcmeAccountId__core(
        ctx, acme_account_id, active_only=active_only, expired_only=expired_only
    )
    return query.count()


def get__AcmeAuthorization__by_AcmeAccountId__paginated(
    ctx: "ApiContext",
    acme_account_id: int,
    active_only: bool = False,
    expired_only: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeAuthorization]:
    query = _get__AcmeAuthorization__by_AcmeAccountId__core(
        ctx, acme_account_id, active_only=active_only, expired_only=expired_only
    )
    query = query.order_by(AcmeAuthorization.id.desc()).limit(limit).offset(offset)
    dbAcmeAuthorizations = query.all()
    return dbAcmeAuthorizations


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeAuthorization__by_DomainId__count(
    ctx: "ApiContext", domain_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeAuthorization)
        .filter(AcmeAuthorization.domain_id == domain_id)
        .count()
    )
    return counted


def get__AcmeAuthorization__by_DomainId__paginated(
    ctx: "ApiContext",
    domain_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeAuthorization]:
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


def get__AcmeAuthorizationPotential__by_id(
    ctx: "ApiContext",
    id_: int,
) -> Optional[AcmeAuthorizationPotential]:
    query = ctx.dbSession.query(AcmeAuthorizationPotential).filter(
        AcmeAuthorizationPotential.id == id_
    )
    dbAcmeAuthorizationPotential = query.first()
    return dbAcmeAuthorizationPotential


def get__AcmeAuthorizationPotentials__count(
    ctx: "ApiContext",
) -> int:
    query = ctx.dbSession.query(AcmeAuthorizationPotential)
    counted = query.count()
    return counted


def get__AcmeAuthorizationPotentials__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = 100,
    offset: int = 0,
) -> List[AcmeAuthorizationPotential]:
    q = ctx.dbSession.query(AcmeAuthorizationPotential)
    items_ = (
        q.order_by(AcmeAuthorizationPotential.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_


def get__AcmeAuthorizationPotentials__by_DomainId__count(
    ctx: "ApiContext",
    domain_id: int,
) -> int:
    query = ctx.dbSession.query(AcmeAuthorizationPotential).filter(
        AcmeAuthorizationPotential.domain_id == domain_id
    )
    counted = query.count()
    return counted


def get__AcmeAuthorizationPotentials__by_DomainId__paginated(
    ctx: "ApiContext",
    domain_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeAuthorizationPotential]:
    query = (
        ctx.dbSession.query(AcmeAuthorizationPotential)
        .filter(AcmeAuthorizationPotential.domain_id == domain_id)
        .order_by(AcmeAuthorizationPotential.id.desc())
    )
    dbAcmeAuthorizationPotential = query.all()
    return dbAcmeAuthorizationPotential


def get__AcmeAuthorizationPotential__by_AcmeOrderId_DomainId(
    ctx: "ApiContext",
    acme_order_id: int,
    domain_id: int,
) -> Optional[AcmeAuthorizationPotential]:
    query = ctx.dbSession.query(AcmeAuthorizationPotential).filter(
        AcmeAuthorizationPotential.acme_order_id == acme_order_id,
        AcmeAuthorizationPotential.domain_id == domain_id,
    )
    dbAcmeAuthorizationPotential = query.first()
    return dbAcmeAuthorizationPotential


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__AcmeChallenge__filter(
    q,
    active_only: Optional[bool] = None,
    resolved_only: Optional[bool] = None,
    processing_only: Optional[bool] = None,
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
    ctx: "ApiContext",
    active_only: Optional[bool] = None,
    resolved_only: Optional[bool] = None,
    processing_only: Optional[bool] = None,
) -> int:
    q = ctx.dbSession.query(AcmeChallenge)
    q = _get__AcmeChallenge__filter(
        q,
        active_only=active_only,
        resolved_only=resolved_only,
        processing_only=processing_only,
    )
    return q.count()


def get__AcmeChallenge__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
    active_only: Optional[bool] = None,
    resolved_only: Optional[bool] = None,
    processing_only: Optional[bool] = None,
) -> List[AcmeChallenge]:
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


def get__AcmeChallenge__by_id(ctx: "ApiContext", id_: int) -> Optional[AcmeChallenge]:
    item = ctx.dbSession.query(AcmeChallenge).get(id_)
    return item


def get__AcmeChallenge__by_challenge_url(
    ctx: "ApiContext", challenge_url: str
) -> Optional[AcmeChallenge]:
    q = ctx.dbSession.query(AcmeChallenge).filter(
        AcmeChallenge.challenge_url == challenge_url
    )
    item = q.first()
    return item


def get__AcmeChallenge__challenged(
    ctx: "ApiContext", domain_name: str, challenge: str
) -> Optional[AcmeChallenge]:
    # ???: Should we ensure the associated AcmeAuthorization is active?
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


def get__AcmeChallenge__by_AcmeAuthorizationId__count(
    ctx: "ApiContext", acme_authorization_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeChallenge)
        .filter(AcmeChallenge.acme_authorization_id == acme_authorization_id)
        .count()
    )
    return counted


def get__AcmeChallenge__by_AcmeAuthorizationId__paginated(
    ctx: "ApiContext",
    acme_authorization_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeChallenge]:
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
    ctx: "ApiContext", domain_id: int, acme_challenge_type_id: Optional[int] = None
) -> List[AcmeChallenge]:
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
            ),
        )
    )
    if acme_challenge_type_id:
        query = query.filter(
            AcmeChallenge.acme_challenge_type_id == acme_challenge_type_id
        )
    return query.all()


def get__AcmeChallenge__by_DomainId__count(
    ctx: "ApiContext", domain_id: int, acme_challenge_type_id: Optional[int] = None
) -> int:
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


def get__AcmeChallenge__by_DomainId__paginated(
    ctx: "ApiContext", domain_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[AcmeChallenge]:
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


def get__AcmeChallengePoll__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(AcmeChallengePoll).count()
    return counted


def get__AcmeChallengePoll__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeChallengePoll]:
    query = ctx.dbSession.query(AcmeChallengePoll)
    query = query.order_by(AcmeChallengePoll.id.desc()).limit(limit).offset(offset)
    dbAcmeChallengePolls = query.all()
    return dbAcmeChallengePolls


def get__AcmeChallengePoll__by_id(
    ctx: "ApiContext", id_: int
) -> Optional[AcmeChallengePoll]:
    item = ctx.dbSession.query(AcmeChallengePoll).get(id_)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeChallengeUnknownPoll__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(AcmeChallengeUnknownPoll).count()
    return counted


def get__AcmeChallengeUnknownPoll__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeChallengeUnknownPoll]:
    query = ctx.dbSession.query(AcmeChallengeUnknownPoll)
    query = (
        query.order_by(AcmeChallengeUnknownPoll.id.desc()).limit(limit).offset(offset)
    )
    dbAcmeChallengeUnknownPolls = query.all()
    return dbAcmeChallengeUnknownPolls


def get__AcmeChallengeUnknownPoll__by_id(
    ctx: "ApiContext", id_: int
) -> Optional[AcmeChallengeUnknownPoll]:
    item = ctx.dbSession.query(AcmeChallengeUnknownPoll).get(id_)
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeDnsServer__by_root_url(
    ctx: "ApiContext", root_url: str
) -> Optional[AcmeDnsServer]:
    q = ctx.dbSession.query(AcmeDnsServer).filter(AcmeDnsServer.root_url == root_url)
    return q.first()


def get__AcmeDnsServer__GlobalDefault(ctx: "ApiContext") -> Optional[AcmeDnsServer]:
    q = ctx.dbSession.query(AcmeDnsServer).filter(
        AcmeDnsServer.is_global_default.is_(True)
    )
    return q.first()


def get__AcmeDnsServer__by_id(ctx: "ApiContext", id_: int) -> Optional[AcmeDnsServer]:
    item = ctx.dbSession.query(AcmeDnsServer).get(id_)
    return item


def get__AcmeDnsServer__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(AcmeDnsServer).count()
    return counted


def get__AcmeDnsServer__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeDnsServer]:
    query = (
        ctx.dbSession.query(AcmeDnsServer)
        .order_by(AcmeDnsServer.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeDnsServerAccount__by_id(
    ctx: "ApiContext", id_: int
) -> Optional[AcmeDnsServerAccount]:
    item = ctx.dbSession.query(AcmeDnsServerAccount).get(id_)
    return item


def get__AcmeDnsServerAccounts__by_ids(
    ctx: "ApiContext", ids: List[int]
) -> List[AcmeDnsServerAccount]:
    items = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(AcmeDnsServerAccount.id.in_(ids))
        .all()
    )
    return items


def get__AcmeDnsServerAccount__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(AcmeDnsServerAccount).count()
    return counted


def get__AcmeDnsServerAccount__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeDnsServerAccount]:
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


def get__AcmeDnsServerAccount__by_DomainId(
    ctx: "ApiContext", domain_id: int
) -> Optional[AcmeDnsServerAccount]:
    item = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(
            AcmeDnsServerAccount.domain_id == domain_id,
        )
        .first()
    )
    return item


def get__AcmeDnsServerAccount__by_AcmeDnsServerId_DomainId(
    ctx: "ApiContext", acme_dns_server_id: int, domain_id: int
) -> Optional[AcmeDnsServerAccount]:
    item = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(
            AcmeDnsServerAccount.acme_dns_server_id == acme_dns_server_id,
            AcmeDnsServerAccount.domain_id == domain_id,
        )
        .first()
    )
    return item


def get__AcmeDnsServerAccount__by_AcmeDnsServerId__count(
    ctx: "ApiContext", acme_dns_server_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(AcmeDnsServerAccount.acme_dns_server_id == acme_dns_server_id)
        .count()
    )
    return counted


def get__AcmeDnsServerAccount__by_AcmeDnsServerId__paginated(
    ctx: "ApiContext",
    acme_dns_server_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeDnsServerAccount]:
    query = (
        ctx.dbSession.query(AcmeDnsServerAccount)
        .filter(AcmeDnsServerAccount.acme_dns_server_id == acme_dns_server_id)
        .order_by(AcmeDnsServerAccount.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeEventLogs__by_AcmeOrderId__count(
    ctx: "ApiContext", acme_order_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeEventLog)
        .filter(AcmeEventLog.acme_order_id == acme_order_id)
        .count()
    )
    return counted


def get__AcmeEventLogs__by_AcmeOrderId__paginated(
    ctx: "ApiContext",
    acme_order_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeEventLog]:
    query = (
        ctx.dbSession.query(AcmeEventLog)
        .filter(AcmeEventLog.acme_order_id == acme_order_id)
        .order_by(AcmeEventLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return query.all()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AcmeOrder__count(ctx: "ApiContext", active_only: Optional[bool] = None) -> int:
    query = ctx.dbSession.query(AcmeOrder)
    if active_only is not None:
        query = query.filter(AcmeOrder.is_processing.is_(active_only))
    return query.count()


def get__AcmeOrder__paginated(
    ctx: "ApiContext",
    active_only: Optional[bool] = None,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeOrder]:
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


def get__AcmeOrder__by_id(
    ctx: "ApiContext", order_id: int, eagerload_web: bool = False
) -> Optional[AcmeOrder]:
    q = ctx.dbSession.query(AcmeOrder).filter(AcmeOrder.id == order_id)
    item = q.first()
    return item


def get__AcmeOrder__by_order_url(
    ctx: "ApiContext", order_url: str
) -> Optional[AcmeOrder]:
    q = ctx.dbSession.query(AcmeOrder).filter(AcmeOrder.order_url == order_url)
    item = q.first()
    return item


def get__AcmeOrder__by_CertificateRequest__count(
    ctx: "ApiContext", certificate_request_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.certificate_request_id == certificate_request_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_CertificateRequest__paginated(
    ctx: "ApiContext",
    certificate_request_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeOrder]:
    items_paged = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.certificate_request_id == certificate_request_id)
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_AcmeAuthorizationId__count(
    ctx: "ApiContext", acme_authorization_id: int
) -> int:
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
    ctx: "ApiContext",
    acme_authorization_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeOrder]:
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


def get__AcmeOrder__by_AcmeAccountId__count(
    ctx: "ApiContext", acme_account_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.acme_account_id == acme_account_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_AcmeAccountId__paginated(
    ctx: "ApiContext",
    acme_account_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeOrder]:
    items_paged = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.acme_account_id == acme_account_id)
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_DomainId__count(ctx: "ApiContext", domain_id: int) -> int:
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
    ctx: "ApiContext",
    domain_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeOrder]:
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


def get__AcmeOrder__by_RenewalConfigurationId__count(
    ctx: "ApiContext", renewal_configuration_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.renewal_configuration_id == renewal_configuration_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_RenewalConfigurationId__paginated(
    ctx: "ApiContext",
    renewal_configuration_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeOrder]:
    query = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.renewal_configuration_id == renewal_configuration_id)
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
    )
    dbAcmeOrders = query.all()
    return dbAcmeOrders


def get__AcmeOrder__by_UniqueFQDNSetId__count(
    ctx: "ApiContext", unique_fqdn_set_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__AcmeOrder__by_UniqueFQDNSetId__paginated(
    ctx: "ApiContext",
    unique_fqdn_set_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeOrder]:
    items_paged = (
        ctx.dbSession.query(AcmeOrder)
        .filter(AcmeOrder.unique_fqdn_set_id == unique_fqdn_set_id)
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__AcmeOrder__by_UniquelyChallengedFQDNSetId__count(
    ctx: "ApiContext", uniquely_challenged_fqdn_set_id: int
) -> int:
    counted = (
        ctx.dbSession.query(AcmeOrder)
        .filter(
            AcmeOrder.uniquely_challenged_fqdn_set_id == uniquely_challenged_fqdn_set_id
        )
        .count()
    )
    return counted


def get__AcmeOrder__by_UniquelyChallengedFQDNSetId__paginated(
    ctx: "ApiContext",
    uniquely_challenged_fqdn_set_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AcmeOrder]:
    items_paged = (
        ctx.dbSession.query(AcmeOrder)
        .filter(
            AcmeOrder.uniquely_challenged_fqdn_set_id == uniquely_challenged_fqdn_set_id
        )
        .order_by(AcmeOrder.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__AriChecks__count(
    ctx: "ApiContext",
    strategy: str,
) -> int:
    if strategy == "all":
        counted = ctx.dbSession.query(AriCheck).count()
    elif strategy == "cert-latest":
        counted = (
            ctx.dbSession.query(AriCheck)
            .distinct(AriCheck.certificate_signed_id)
            .group_by(AriCheck.certificate_signed_id)
            .order_by(AriCheck.id.desc())
            .count()
        )
    elif strategy == "cert-latest-overdue":
        counted = (
            ctx.dbSession.query(AriCheck)
            .distinct(AriCheck.certificate_signed_id)
            .group_by(AriCheck.certificate_signed_id)
            .filter(AriCheck.timestamp_retry_after < ctx.timestamp)
            .order_by(AriCheck.id.desc())
            .count()
        )
    else:
        raise ValueError("unknown strategy")
    return counted


def get__AriChecks___paginated(
    ctx: "ApiContext",
    strategy: str,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AriCheck]:
    if strategy == "all":
        q = (
            ctx.dbSession.query(AriCheck)
            .order_by(AriCheck.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items_paged = q.all()
    elif strategy == "cert-latest":
        q = (
            ctx.dbSession.query(AriCheck)
            .distinct(AriCheck.certificate_signed_id)
            .group_by(AriCheck.certificate_signed_id)
            .order_by(AriCheck.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items_paged = q.all()
    elif strategy == "cert-latest-overdue":
        q = (
            ctx.dbSession.query(AriCheck)
            .distinct(AriCheck.certificate_signed_id)
            .group_by(AriCheck.certificate_signed_id)
            .filter(AriCheck.timestamp_retry_after < ctx.timestamp)
            .order_by(AriCheck.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items_paged = q.all()
    else:
        raise ValueError("unknown strategy")
    return items_paged


def get__AriCheck__by_CertificateSignedId__count(
    ctx: "ApiContext",
    cert_id: int,
) -> int:
    counted = (
        ctx.dbSession.query(AriCheck)
        .filter(AriCheck.certificate_signed_id == cert_id)
        .count()
    )
    return counted


def get__AriCheck__by_CertificateSignedId__paginated(
    ctx: "ApiContext",
    cert_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[AriCheck]:
    q = (
        ctx.dbSession.query(AriCheck)
        .filter(AriCheck.certificate_signed_id == cert_id)
        .order_by(AriCheck.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__AriCheck__by_id(
    ctx: "ApiContext",
    id: int,
) -> Optional[AriCheck]:
    q = ctx.dbSession.query(AriCheck).filter(AriCheck.id == id)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateCA__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(CertificateCA).count()
    return counted


def get__CertificateCA__paginated(
    ctx: "ApiContext", limit: Optional[int] = None, offset: int = 0
) -> List[CertificateCA]:
    q = (
        ctx.dbSession.query(CertificateCA)
        .order_by(CertificateCA.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__CertificateCAPreference__paginated(
    ctx: "ApiContext", limit: Optional[int] = None, offset: int = 0
) -> List[CertificateCA]:
    q = ctx.dbSession.query(CertificateCAPreference)
    q = q.order_by(CertificateCAPreference.id.asc()).limit(limit).offset(offset)
    q = q.options(joinedload(CertificateCAPreference.certificate_ca))
    items_paged = q.all()
    return items_paged


def get__CertificateCA__by_id(
    ctx: "ApiContext", cert_id: int
) -> Optional[CertificateCA]:
    dbCertificateCA = (
        ctx.dbSession.query(CertificateCA).filter(CertificateCA.id == cert_id).first()
    )
    return dbCertificateCA


def get__CertificateCAs__by_fingerprint_sha1_substring(
    ctx: "ApiContext", fingerprint_sha1_substring: str
) -> List[CertificateCA]:
    dbCertificateCAs = (
        ctx.dbSession.query(CertificateCA)
        .filter(CertificateCA.fingerprint_sha1.startswith(fingerprint_sha1_substring))
        .all()
    )
    return dbCertificateCAs


def get__CertificateCA__by_fingerprint_sha1(
    ctx: "ApiContext", fingerprint_sha1: str
) -> CertificateCA:
    dbCertificateCA = (
        ctx.dbSession.query(CertificateCA)
        .filter(CertificateCA.fingerprint_sha1 == fingerprint_sha1)
        .one()
    )
    return dbCertificateCA


def get__CertificateCA__by_pem_text(
    ctx: "ApiContext", cert_pem: str
) -> Optional[CertificateCA]:
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


def get__CertificateCAChain__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(CertificateCAChain).count()
    return counted


def get__CertificateCAChain__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
    active_only: bool = False,
) -> List[CertificateCAChain]:
    q = ctx.dbSession.query(CertificateCAChain)
    if active_only:
        q = q.join(
            CertificateCA,
            CertificateCAChain.certificate_ca_0_id == CertificateCA.id,
        ).filter(CertificateCA.count_active_certificates >= 1)
    q = q.order_by(CertificateCAChain.id.desc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__CertificateCAChain__by_id(
    ctx: "ApiContext", chain_id: int
) -> Optional[CertificateCAChain]:
    dbCertificateCAChain = (
        ctx.dbSession.query(CertificateCAChain)
        .filter(CertificateCAChain.id == chain_id)
        .first()
    )
    return dbCertificateCAChain


def get__CertificateCAChain__by_pem_text(
    ctx: "ApiContext", chain_pem: str
) -> Optional[CertificateCAChain]:
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
    ctx: "ApiContext",
    certificate_ca_id: int,
    column: InstrumentedAttribute[int],
):
    """
    column is either
        * CertificateCAChain.certificate_ca_0_id
        * CertificateCAChain.certificate_ca_n_id
    """
    query = ctx.dbSession.query(CertificateCAChain).filter(column == certificate_ca_id)
    return query


def get__CertificateCAChain__by_CertificateCAId0__count(
    ctx: "ApiContext", certificate_ca_id: int
) -> int:
    query = _get__CertificateCAChain__by_certificateCaId__core(
        ctx, certificate_ca_id, CertificateCAChain.certificate_ca_0_id
    )
    return query.count()


def get__CertificateCAChain__by_CertificateCAId0__paginated(
    ctx: "ApiContext",
    certificate_ca_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CertificateCAChain]:
    query = _get__CertificateCAChain__by_certificateCaId__core(
        ctx, certificate_ca_id, CertificateCAChain.certificate_ca_0_id
    )
    items_paged = (
        query.order_by(CertificateCAChain.id.desc()).limit(limit).offset(offset).all()
    )
    return items_paged


def get__CertificateCAChain__by_CertificateCAIdN__count(
    ctx: "ApiContext", certificate_ca_id: int
) -> int:
    query = _get__CertificateCAChain__by_certificateCaId__core(
        ctx, certificate_ca_id, CertificateCAChain.certificate_ca_n_id
    )
    return query.count()


def get__CertificateCAChain__by_CertificateCAIdN__paginated(
    ctx: "ApiContext",
    certificate_ca_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CertificateCAChain]:
    query = _get__CertificateCAChain__by_certificateCaId__core(
        ctx, certificate_ca_id, CertificateCAChain.certificate_ca_n_id
    )
    items_paged = (
        query.order_by(CertificateCAChain.id.desc()).limit(limit).offset(offset).all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateRequest__count(ctx: "ApiContext") -> int:
    counted = ctx.dbSession.query(CertificateRequest).count()
    return counted


def get__CertificateRequest__paginated(
    ctx: "ApiContext", limit: Optional[int] = None, offset: int = 0
) -> List[CertificateRequest]:
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


def get__CertificateRequest__by_id(
    ctx: "ApiContext", certificate_request_id: int
) -> Optional[CertificateRequest]:
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


def get__CertificateRequest__by_pem_text(
    ctx: "ApiContext", csr_pem: str
) -> Optional[CertificateRequest]:
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


def get__CertificateRequest__by_DomainId__count(
    ctx: "ApiContext", domain_id: int
) -> int:
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
    ctx: "ApiContext", domain_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[CertificateRequest]:
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


def get__CertificateRequest__by_PrivateKeyId__count(
    ctx: "ApiContext", key_id: int
) -> int:
    counted = (
        ctx.dbSession.query(CertificateRequest)
        .filter(CertificateRequest.private_key_id == key_id)
        .count()
    )
    return counted


def get__CertificateRequest__by_PrivateKeyId__paginated(
    ctx: "ApiContext", key_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[CertificateRequest]:
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


def get__CertificateRequest__by_UniqueFQDNSetId__count(
    ctx: "ApiContext", unique_fqdn_set_id: int
) -> int:
    counted = (
        ctx.dbSession.query(CertificateRequest)
        .filter(CertificateRequest.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__CertificateRequest__by_UniqueFQDNSetId__paginated(
    ctx: "ApiContext",
    unique_fqdn_set_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CertificateRequest]:
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


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateSigned__count(
    ctx: "ApiContext",
    expiring_days: Optional[int] = None,
    is_active: Optional[bool] = None,
    is_unexpired: Optional[bool] = None,
) -> int:
    if (expiring_days is not None) and (is_unexpired is not None):
        raise ValueError("only submit one of: expiring_days, is_unexpired")
    q = ctx.dbSession.query(CertificateSigned)
    if is_active is not None:
        if is_active is True:
            q = q.filter(CertificateSigned.is_active.is_(True))
        elif is_active is False:
            q = q.filter(CertificateSigned.is_active.is_(False))
    if expiring_days is not None:
        _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
        q = q.filter(
            CertificateSigned.timestamp_not_after <= _until,
        )
    elif is_unexpired:
        q = q.filter(
            CertificateSigned.timestamp_not_after > ctx.timestamp,
        )
    counted = q.count()
    return counted


def get__CertificateSigned__paginated(
    ctx: "ApiContext",
    expiring_days: Optional[int] = None,
    is_active: Optional[bool] = None,
    is_unexpired: Optional[bool] = None,
    eagerload_web: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CertificateSigned]:
    if (expiring_days is not None) and (is_unexpired is not None):
        raise ValueError("only submit one of: expiring_days, is_unexpired")
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
    if expiring_days is not None:
        _until = ctx.timestamp + datetime.timedelta(days=expiring_days)
        q = q.filter(
            CertificateSigned.timestamp_not_after <= _until,
        ).order_by(CertificateSigned.timestamp_not_after.asc())
    elif is_unexpired:
        q = q.filter(
            CertificateSigned.timestamp_not_after > ctx.timestamp,
        ).order_by(CertificateSigned.timestamp_not_after.asc())
    else:
        q = q.order_by(CertificateSigned.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__CertificateSigned__by_id(
    ctx: "ApiContext", cert_id: int
) -> Optional[CertificateSigned]:
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


def get__CertificateSigned__by_AcmeAccountId__count(
    ctx: "ApiContext", acme_account_id: int
) -> int:
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
    ctx: "ApiContext",
    acme_account_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CertificateSigned]:
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


def _get__CertificateSigned__by_CertificateCAId__primary(
    ctx: "ApiContext", cert_ca_id: int
):
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


def get__CertificateSigned__by_CertificateCAId__primary__count(
    ctx: "ApiContext", cert_ca_id: int
) -> int:
    query_core = _get__CertificateSigned__by_CertificateCAId__primary(ctx, cert_ca_id)
    counted = query_core.count()
    return counted


def get__CertificateSigned__by_CertificateCAId__primary__paginated(
    ctx: "ApiContext", cert_ca_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[CertificateSigned]:
    query_core = _get__CertificateSigned__by_CertificateCAId__primary(ctx, cert_ca_id)
    items_paged = (
        query_core.order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def _get__CertificateSigned__by_CertificateCAId__alt(
    ctx: "ApiContext", cert_ca_id: int
):
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


def get__CertificateSigned__by_CertificateCAId__alt__count(
    ctx: "ApiContext", cert_ca_id: int
) -> int:
    query_core = _get__CertificateSigned__by_CertificateCAId__alt(ctx, cert_ca_id)
    counted = query_core.count()
    return counted


def get__CertificateSigned__by_CertificateCAId__alt__paginated(
    ctx: "ApiContext", cert_ca_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[CertificateSigned]:
    query_core = _get__CertificateSigned__by_CertificateCAId__alt(ctx, cert_ca_id)
    items_paged = (
        query_core.order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CertificateSigned__by_DomainId__count(
    ctx: "ApiContext", domain_id: int
) -> int:
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
    ctx: "ApiContext", domain_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[CertificateSigned]:
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


def get__CertificateSigned__by_DomainId__latest(
    ctx: "ApiContext", domain_id: int
) -> Optional[CertificateSigned]:
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


def get__CertificateSigned__by_PrivateKeyId__count(
    ctx: "ApiContext", key_id: int
) -> int:
    counted = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.private_key_id == key_id)
        .count()
    )
    return counted


def get__CertificateSigned__by_PrivateKeyId__paginated(
    ctx: "ApiContext", key_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[CertificateSigned]:
    items_paged = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.private_key_id == key_id)
        .order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateSigned__by_RenewalConfigurationId__count(
    ctx: "ApiContext", renewal_configuration_id: int
) -> int:
    counted = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            AcmeOrder,
            CertificateSigned.acme_order_id == AcmeOrder.id,
        )
        .join(
            RenewalConfiguration,
            AcmeOrder.renewal_configuration_id == RenewalConfiguration.id,
        )
        .filter(AcmeOrder.renewal_configuration_id == renewal_configuration_id)
        .count()
    )
    return counted


def get__CertificateSigned__by_RenewalConfigurationId__paginated(
    ctx: "ApiContext",
    renewal_configuration_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CertificateSigned]:
    items_paged = (
        ctx.dbSession.query(CertificateSigned)
        .join(
            AcmeOrder,
            CertificateSigned.acme_order_id == AcmeOrder.id,
        )
        .join(
            RenewalConfiguration,
            AcmeOrder.renewal_configuration_id == RenewalConfiguration.id,
        )
        .filter(AcmeOrder.renewal_configuration_id == renewal_configuration_id)
        .order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateSigned__by_UniqueFQDNSetId__count(
    ctx: "ApiContext", unique_fqdn_set_id: int
) -> int:
    counted = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__CertificateSigned__by_UniqueFQDNSetId__paginated(
    ctx: "ApiContext",
    unique_fqdn_set_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CertificateSigned]:
    items_paged = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.unique_fqdn_set_id == unique_fqdn_set_id)
        .order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__CertificateSigned__by_UniqueFQDNSetId__latest_active(
    ctx: "ApiContext", unique_fqdn_set_id: int
) -> Optional[CertificateSigned]:
    item = (
        ctx.dbSession.query(CertificateSigned)
        .filter(CertificateSigned.unique_fqdn_set_id == unique_fqdn_set_id)
        .filter(CertificateSigned.is_active.is_(True))
        .order_by(CertificateSigned.timestamp_not_after.desc())
        .first()
    )
    return item


def get__CertificateSigneds__by_UniquelyChallengedFQDNSetId__count(
    ctx: "ApiContext", uniquely_challenged_fqdn_set_id: int
) -> int:
    counted = (
        ctx.dbSession.query(CertificateSigned)
        .join(AcmeOrder, CertificateSigned.id == AcmeOrder.certificate_signed_id)
        .filter(
            AcmeOrder.uniquely_challenged_fqdn_set_id == uniquely_challenged_fqdn_set_id
        )
        .count()
    )
    return counted


def get__CertificateSigneds__by_UniquelyChallengedFQDNSetId__paginated(
    ctx: "ApiContext",
    uniquely_challenged_fqdn_set_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CertificateSigned]:
    items_paged = (
        ctx.dbSession.query(CertificateSigned)
        .join(AcmeOrder, CertificateSigned.id == AcmeOrder.certificate_signed_id)
        .filter(
            AcmeOrder.uniquely_challenged_fqdn_set_id == uniquely_challenged_fqdn_set_id
        )
        .order_by(CertificateSigned.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__CoverageAssuranceEvent__count(
    ctx: "ApiContext", unresolved_only: Optional[bool] = None
) -> int:
    q = ctx.dbSession.query(CoverageAssuranceEvent)
    if unresolved_only:
        q = q.filter(
            CoverageAssuranceEvent.coverage_assurance_resolution_id
            == model_utils.CoverageAssuranceResolution.from_string("unresolved")
        )
    counted = q.count()
    return counted


def get__CoverageAssuranceEvent__paginated(
    ctx: "ApiContext",
    show_all: Optional[bool] = None,
    unresolved_only: Optional[bool] = None,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[CoverageAssuranceEvent]:
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


def get__CoverageAssuranceEvent__by_id(
    ctx: "ApiContext", event_id: int
) -> Optional[CoverageAssuranceEvent]:
    q = ctx.dbSession.query(CoverageAssuranceEvent).filter(
        CoverageAssuranceEvent.id == event_id
    )
    item = q.first()
    return item


def get__CoverageAssuranceEvent__by_parentId__count(
    ctx: "ApiContext", parent_id: int, limit: Optional[int] = None, offset: int = 0
) -> int:
    q = ctx.dbSession.query(CoverageAssuranceEvent).filter(
        CoverageAssuranceEvent.coverage_assurance_event_id__parent == parent_id
    )
    return q.count()


def get__CoverageAssuranceEvent__by_parentId__paginated(
    ctx: "ApiContext", parent_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[CoverageAssuranceEvent]:
    q = ctx.dbSession.query(CoverageAssuranceEvent).filter(
        CoverageAssuranceEvent.coverage_assurance_event_id__parent == parent_id
    )
    q = q.order_by(CoverageAssuranceEvent.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _Domain_inject_exipring_days(
    ctx: "ApiContext", q, expiring_days: int, order: bool = False
):
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


def get__Domain__count(
    ctx: "ApiContext",
    expiring_days: Optional[int] = None,
    active_only: Optional[bool] = False,
) -> int:
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
    ctx: "ApiContext",
    expiring_days: Optional[int] = None,
    eagerload_web: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
    active_certs_only: Optional[bool] = None,
) -> List[Domain]:
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


def _get__Domain__core(q, preload: bool = False, eagerload_web: bool = False):
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


def get__Domain__by_id(
    ctx: "ApiContext",
    domain_id: int,
    preload: bool = False,
    eagerload_web: bool = False,
) -> Optional[Domain]:
    q = ctx.dbSession.query(Domain).filter(Domain.id == domain_id)
    if preload:
        q = _get__Domain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


def get__Domain__by_name(
    ctx: "ApiContext",
    domain_name: str,
    preload: bool = False,
    eagerload_web: bool = False,
    active_only: bool = False,
) -> Optional[Domain]:
    q = ctx.dbSession.query(Domain).filter(
        sqlalchemy.func.lower(Domain.domain_name) == sqlalchemy.func.lower(domain_name)
    )
    if preload:
        q = _get__Domain__core(q, preload=preload, eagerload_web=eagerload_web)
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__Domains_challenged__core(ctx: "ApiContext"):
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
            ),
        )
    )
    return q


def get__Domains_challenged__count(ctx: "ApiContext") -> int:
    q = _get__Domains_challenged__core(ctx)
    counted = q.count()
    return counted


def get__Domains_challenged__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[Domain]:
    q = _get__Domains_challenged__core(ctx)
    q = q.order_by(sqlalchemy.func.lower(Domain.domain_name).asc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get__Domains_authz_potential__core(ctx: "ApiContext"):
    q = (
        ctx.dbSession.query(Domain)
        # domain joins on everything
        .join(
            AcmeAuthorizationPotential,
            Domain.id == AcmeAuthorizationPotential.domain_id,
        )
    )
    return q


def get__Domains_authz_potential__count(ctx: "ApiContext") -> int:
    q = _get__Domains_authz_potential__core(ctx)
    counted = q.count()
    return counted


def get__Domains_authz_potential__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[Domain]:
    q = _get__Domains_authz_potential__core(ctx)
    q = q.order_by(sqlalchemy.func.lower(Domain.domain_name).asc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__DomainAutocert__by_blockingDomainId(
    ctx: "ApiContext", domain_id: int
) -> Optional[DomainAutocert]:
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


def get__DomainAutocert__count(ctx: "ApiContext") -> int:
    q = ctx.dbSession.query(DomainAutocert)
    counted = q.count()
    return counted


def get__DomainAutocert__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[DomainAutocert]:
    q = (
        ctx.dbSession.query(DomainAutocert)
        .order_by(DomainAutocert.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__DomainAutocert__by_DomainId__count(ctx: "ApiContext", domain_id: int) -> int:
    counted = (
        ctx.dbSession.query(DomainAutocert)
        .filter(DomainAutocert.domain_id == domain_id)
        .count()
    )
    return counted


def get__DomainAutocert__by_DomainId__paginated(
    ctx: "ApiContext", domain_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[DomainAutocert]:
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


def get__DomainBlocklisted__by_name(
    ctx: "ApiContext", domain_name: str
) -> Optional[DomainBlocklisted]:
    q = ctx.dbSession.query(DomainBlocklisted).filter(
        sqlalchemy.func.lower(DomainBlocklisted.domain_name)
        == sqlalchemy.func.lower(domain_name)
    )
    item = q.first()
    return item


def get__DomainBlocklisted__count(ctx: "ApiContext") -> int:
    q = ctx.dbSession.query(DomainBlocklisted)
    counted = q.count()
    return counted


def get__DomainBlocklisted__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[DomainBlocklisted]:
    q = (
        ctx.dbSession.query(DomainBlocklisted)
        .order_by(sqlalchemy.func.lower(DomainBlocklisted.domain_name).asc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__OperationsObjectEvent__count(ctx: "ApiContext") -> int:
    q = ctx.dbSession.query(OperationsObjectEvent)
    counted = q.count()
    return counted


def get__OperationsObjectEvent__paginated(
    ctx: "ApiContext", limit: Optional[int] = None, offset: int = 0
) -> List[OperationsObjectEvent]:
    q = (
        ctx.dbSession.query(OperationsObjectEvent)
        .order_by(OperationsObjectEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__OperationsObjectEvent__by_id(
    ctx: "ApiContext", event_id: int, eagerload_log: bool = False
) -> Optional[OperationsObjectEvent]:
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


def get__OperationsEvent__count(
    ctx: "ApiContext",
    event_type_ids: Optional[Iterable[int]] = None,
) -> int:
    q = ctx.dbSession.query(OperationsEvent)
    if event_type_ids is not None:
        q = q.filter(OperationsEvent.operations_event_type_id.in_(event_type_ids))
    items_count = q.count()
    return items_count


def get__OperationsEvent__paginated(
    ctx: "ApiContext",
    event_type_ids: Optional[Iterable[int]] = None,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[OperationsEvent]:
    q = ctx.dbSession.query(OperationsEvent)
    if event_type_ids is not None:
        q = q.filter(OperationsEvent.operations_event_type_id.in_(event_type_ids))
    items_paged = (
        q.order_by(OperationsEvent.id.desc()).limit(limit).offset(offset).all()
    )
    return items_paged


def get__OperationsEvent__by_id(
    ctx: "ApiContext", event_id: int, eagerload_log: bool = False
) -> Optional[OperationsEvent]:
    q = ctx.dbSession.query(OperationsEvent).filter(OperationsEvent.id == event_id)
    if eagerload_log:
        q = q.options(
            subqueryload(OperationsEvent.object_events).options(
                joinedload(OperationsObjectEvent.domain),
            ),
            subqueryload(OperationsEvent.children),
            subqueryload(OperationsEvent.parent),
        )
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__PrivateKey__count(
    ctx: "ApiContext", active_usage_only: Optional[bool] = None
) -> int:
    q = ctx.dbSession.query(PrivateKey)
    if active_usage_only:
        q = q.filter(PrivateKey.count_active_certificates >= 1)
    counted = q.count()
    return counted


def get__PrivateKey__paginated(
    ctx: "ApiContext",
    limit: Optional[int] = None,
    offset: int = 0,
    active_usage_only: Optional[bool] = None,
) -> List[PrivateKey]:
    q = ctx.dbSession.query(PrivateKey)
    if active_usage_only:
        q = q.filter(PrivateKey.count_active_certificates >= 1)
    q = q.order_by(PrivateKey.id.desc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__PrivateKey__by_id(
    ctx: "ApiContext", key_id: int, eagerload_web: Optional[bool] = False
) -> Optional[PrivateKey]:
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


def get__PrivateKey_CurrentWeek_Global(ctx: "ApiContext") -> Optional[PrivateKey]:
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


def get__PrivateKey_CurrentDay_Global(ctx: "ApiContext") -> Optional[PrivateKey]:
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


def get__PrivateKey_CurrentWeek_AcmeAccount(
    ctx: "ApiContext", acme_account_id: int
) -> Optional[PrivateKey]:
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


def get__PrivateKey_CurrentDay_AcmeAccount(
    ctx: "ApiContext", acme_account_id: int
) -> Optional[PrivateKey]:
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


def get__PrivateKey__by_pemMd5(
    ctx: "ApiContext", pem_md5: str, is_active: bool = True
) -> Optional[PrivateKey]:
    q = ctx.dbSession.query(PrivateKey).filter(PrivateKey.key_pem_md5 == pem_md5)
    if is_active:
        q = q.filter(PrivateKey.is_active.is_(True))
    item = q.first()
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__PrivateKey__by_AcmeAccountIdOwner__count(
    ctx: "ApiContext", acme_account_id: int
) -> int:
    counted = (
        ctx.dbSession.query(PrivateKey)
        .filter(PrivateKey.acme_account_id__owner == acme_account_id)
        .count()
    )
    return counted


def get__PrivateKey__by_AcmeAccountIdOwner__paginated(
    ctx: "ApiContext",
    acme_account_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[PrivateKey]:
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


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__RenewalConfiguration__by_id(
    ctx: "ApiContext",
    id_: int,
) -> Optional[RenewalConfiguration]:
    q = ctx.dbSession.query(RenewalConfiguration).filter(RenewalConfiguration.id == id_)
    item = q.first()
    return item


def get__RenewalConfiguration__count(
    ctx: "ApiContext",
    active_status: Optional[bool] = None,
) -> int:
    q = ctx.dbSession.query(RenewalConfiguration)
    if active_status in (True, False):
        q = q.filter(RenewalConfiguration.is_active == active_status)
    counted = q.count()
    return counted


def get__RenewalConfiguration__paginated(
    ctx: "ApiContext",
    active_status: Optional[bool] = None,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[RenewalConfiguration]:
    q = ctx.dbSession.query(RenewalConfiguration)
    if active_status in (True, False):
        q = q.filter(RenewalConfiguration.is_active == active_status)
    q = q.order_by(RenewalConfiguration.id.asc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__RenewalConfigurations__by_AcmeAccountId__count(
    ctx: "ApiContext",
    acme_account_id: int,
) -> int:
    q = ctx.dbSession.query(RenewalConfiguration).filter(
        RenewalConfiguration.acme_account_id == acme_account_id
    )
    counted = q.count()
    return counted


def get__RenewalConfigurations__by_AcmeAccountId__paginated(
    ctx: "ApiContext",
    acme_account_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[RenewalConfiguration]:
    q = ctx.dbSession.query(RenewalConfiguration).filter(
        RenewalConfiguration.acme_account_id == acme_account_id
    )
    q = q.order_by(RenewalConfiguration.id.asc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__RenewalConfiguration__by_UniquelyChallengedFQDNSetId__count(
    ctx: "ApiContext",
    unique_challenged_fqdn_set_id: int,
) -> int:
    q = ctx.dbSession.query(RenewalConfiguration).filter(
        RenewalConfiguration.unique_challenged_fqdn_set_id
        == unique_challenged_fqdn_set_id
    )
    counted = q.count()
    return counted


def get__RenewalConfiguration__by_UniquelyChallengedFQDNSetId__paginated(
    ctx: "ApiContext",
    unique_challenged_fqdn_set_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[RenewalConfiguration]:
    q = ctx.dbSession.query(RenewalConfiguration).filter(
        RenewalConfiguration.unique_challenged_fqdn_set_id
        == unique_challenged_fqdn_set_id
    )
    q = q.order_by(RenewalConfiguration.id.asc()).limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__RootStore__count(ctx: "ApiContext") -> int:
    q = ctx.dbSession.query(RootStore)
    counted = q.count()
    return counted


def get__RootStore__paginated(
    ctx: "ApiContext", limit: Optional[int] = None, offset: int = 0
) -> List[RootStore]:
    q = (
        ctx.dbSession.query(RootStore)
        .order_by(sqlalchemy.func.lower(RootStore.name).asc())
        .limit(limit)
        .offset(offset)
    )
    items_paged = q.all()
    return items_paged


def get__RootStore__by_id(ctx: "ApiContext", root_store_id: int) -> Optional[RootStore]:
    item = ctx.dbSession.query(RootStore).filter(RootStore.id == root_store_id).first()
    return item


def get__RootStoreVersion__by_id(
    ctx: "ApiContext", root_store_version_id: int
) -> Optional[RootStoreVersion]:
    item = (
        ctx.dbSession.query(RootStoreVersion)
        .filter(RootStoreVersion.id == root_store_version_id)
        .first()
    )
    return item


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def get__UniqueFQDNSet__count(ctx: "ApiContext") -> int:
    q = ctx.dbSession.query(UniqueFQDNSet)
    counted = q.count()
    return counted


def get__UniqueFQDNSet__paginated(
    ctx: "ApiContext",
    eagerload_web: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[UniqueFQDNSet]:
    q = ctx.dbSession.query(UniqueFQDNSet)
    if eagerload_web:
        q = q.options(
            joinedload(UniqueFQDNSet.to_domains).joinedload(UniqueFQDNSet2Domain.domain)
        )
    q = q.order_by(UniqueFQDNSet.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__UniqueFQDNSet__by_id(
    ctx: "ApiContext", set_id: int
) -> Optional[UniqueFQDNSet]:
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


def get__UniqueFQDNSet__by_DomainId__count(ctx: "ApiContext", domain_id: int) -> int:
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


def get__UniqueFQDNSet__by_DomainId__paginated(
    ctx: "ApiContext", domain_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[UniqueFQDNSet]:
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


def get__UniquelyChallengedFQDNSet__count(ctx: "ApiContext") -> int:
    q = ctx.dbSession.query(UniquelyChallengedFQDNSet)
    counted = q.count()
    return counted


def get__UniquelyChallengedFQDNSet__paginated(
    ctx: "ApiContext",
    eagerload_web: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[UniquelyChallengedFQDNSet]:
    q = ctx.dbSession.query(UniquelyChallengedFQDNSet)
    if eagerload_web:
        q = q.options(
            joinedload(UniquelyChallengedFQDNSet.to_domains).joinedload(
                UniquelyChallengedFQDNSet2Domain.domain
            )
        )
    q = q.order_by(UniquelyChallengedFQDNSet.id.desc())
    q = q.limit(limit).offset(offset)
    items_paged = q.all()
    return items_paged


def get__UniquelyChallengedFQDNSet__by_id(
    ctx: "ApiContext", set_id: int
) -> Optional[UniquelyChallengedFQDNSet]:
    item = (
        ctx.dbSession.query(UniquelyChallengedFQDNSet)
        .filter(UniquelyChallengedFQDNSet.id == set_id)
        .options(
            subqueryload(UniquelyChallengedFQDNSet.to_domains).joinedload(
                UniquelyChallengedFQDNSet2Domain.domain
            )
        )
        .first()
    )
    return item


def get__UniquelyChallengedFQDNSet__by_DomainId__count(
    ctx: "ApiContext", domain_id: int
) -> int:
    counted = (
        ctx.dbSession.query(UniquelyChallengedFQDNSet)
        .join(
            UniquelyChallengedFQDNSet2Domain,
            UniquelyChallengedFQDNSet.id
            == UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id,
        )
        .filter(UniquelyChallengedFQDNSet2Domain.domain_id == domain_id)
        .count()
    )
    return counted


def get__UniquelyChallengedFQDNSet__by_DomainId__paginated(
    ctx: "ApiContext", domain_id: int, limit: Optional[int] = None, offset: int = 0
) -> List[UniquelyChallengedFQDNSet]:
    items_paged = (
        ctx.dbSession.query(UniquelyChallengedFQDNSet)
        .join(
            UniquelyChallengedFQDNSet2Domain,
            UniquelyChallengedFQDNSet.id
            == UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id,
        )
        .filter(UniquelyChallengedFQDNSet2Domain.domain_id == domain_id)
        .order_by(UniquelyChallengedFQDNSet.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged


def get__UniquelyChallengedFQDNSet__by_UniqueFQDNSetId__count(
    ctx: "ApiContext", unique_fqdn_set_id: int
) -> int:
    counted = (
        ctx.dbSession.query(UniquelyChallengedFQDNSet)
        .filter(UniquelyChallengedFQDNSet.unique_fqdn_set_id == unique_fqdn_set_id)
        .count()
    )
    return counted


def get__UniquelyChallengedFQDNSet__by_UniqueFQDNSetId__paginated(
    ctx: "ApiContext",
    unique_fqdn_set_id: int,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[UniquelyChallengedFQDNSet]:
    items_paged = (
        ctx.dbSession.query(UniquelyChallengedFQDNSet)
        .filter(UniquelyChallengedFQDNSet.unique_fqdn_set_id == unique_fqdn_set_id)
        .order_by(UniquelyChallengedFQDNSet.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return items_paged
