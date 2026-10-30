# srdlib
import logging
from typing import Iterable
from typing import Optional
from typing import TYPE_CHECKING

# pypi
import sqlalchemy
import tldextract

# localapp
from .get import get__AcmeDnsServerAccount__by_DomainId
from .get import get__Domain__by_name
from .get import get__DomainBlocklisted__by_name
from .. import errors
from ...model import utils as model_utils

if TYPE_CHECKING:
    from ..context import ApiContext
    from ...model.objects import AcmeOrder
    from ...model.objects import PrivateKey

# ==============================================================================

log = logging.getLogger("peter_sslers.lib.db")

# ------------------------------------------------------------------------------


def validate_domain_names(
    ctx: "ApiContext",
    domain_names: Iterable[str],
    allow_blocklisted_domains: bool = False,
) -> bool:
    # check for invalid and blocklists here
    # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
    _invalid_domain_names = []
    for _domain_name in domain_names:
        if not tldextract.extract(_domain_name).suffix:
            _invalid_domain_names.append(_domain_name)
    if _invalid_domain_names:
        raise errors.AcmeDomainsInvalid(_invalid_domain_names)

    if not allow_blocklisted_domains:
        _blocklisted_domain_names = []
        for _domain_name in domain_names:
            _dbDomainBlocklisted = get__DomainBlocklisted__by_name(ctx, _domain_name)
            if _dbDomainBlocklisted:
                _blocklisted_domain_names.append(_domain_name)
        if _blocklisted_domain_names:
            raise errors.AcmeDomainsBlocklisted(_blocklisted_domain_names)

    return True


def ensure_domains_dns01(
    ctx: "ApiContext",
    domain_names: Iterable[str],
) -> bool:
    # this may raise errors.AcmeDomainsRequireConfigurationAcmeDNS
    _unconfigured_domain_names = []
    for _domain_name in domain_names:
        _dbDomain = get__Domain__by_name(ctx, _domain_name)
        if not _dbDomain:
            # if the domain is not in the system, it definitely does not
            # have an acme-dns configuration
            _unconfigured_domain_names.append(_domain_name)
            continue
        _dbAcmeDnsServerAccount = get__AcmeDnsServerAccount__by_DomainId(
            ctx, _dbDomain.id
        )
        if not _dbAcmeDnsServerAccount:
            # this domain is in the system, but does not have an acme-dns configuration
            _unconfigured_domain_names.append(_domain_name)
            continue
    if _unconfigured_domain_names:
        raise errors.AcmeDomainsRequireConfigurationAcmeDNS(_unconfigured_domain_names)
    return True


def validate_private_key_for_order(
    ctx: "ApiContext",
    key: "PrivateKey",
    account_id: int,
    *,
    order: Optional["AcmeOrder"] = None,
    allow_yearly_reuse: bool = False,
) -> None:
    """Enforce ownership and single-use policy even when forms are bypassed."""
    from ...model.objects import AcmeOrder
    from ...model.objects import X509Certificate

    if key.id == 0:
        raise errors.InvalidRequest("A placeholder cannot sign a certificate")
    if not key.is_key_usable:
        raise errors.InvalidRequest("The private key is inactive or compromised")
    if (
        key.acme_account_id__owner is not None
        and key.acme_account_id__owner != account_id
    ):
        raise errors.InvalidRequest(
            "The private key belongs to a different ACME account"
        )
    key_type = key.private_key_type_id
    if (
        key_type not in model_utils.PrivateKey_Type._mapping
        or key_type == model_utils.PrivateKey_Type.PLACEHOLDER
    ):
        raise errors.InvalidRequest("Unknown or placeholder private-key policy")
    if (
        key.key_technology_id
        not in model_utils.KeyTechnology._options_AcmeAccount_order_default_id
    ):
        raise errors.InvalidRequest("A concrete signing-key technology is required")
    if (
        key_type
        in (
            model_utils.PrivateKey_Type.ACCOUNT_DAILY,
            model_utils.PrivateKey_Type.ACCOUNT_WEEKLY,
        )
        and key.acme_account_id__owner != account_id
    ):
        raise errors.InvalidRequest(
            "An account-scoped key must have the matching owner"
        )
    if (
        key_type
        in (
            model_utils.PrivateKey_Type.GLOBAL_DAILY,
            model_utils.PrivateKey_Type.GLOBAL_WEEKLY,
        )
        and key.acme_account_id__owner is not None
    ):
        raise errors.InvalidRequest("A global key cannot be account-owned")
    if key_type == model_utils.PrivateKey_Type.SINGLE_USE:
        issued = (
            ctx.dbSession.query(X509Certificate.id)
            .filter(X509Certificate.private_key_id == key.id)
            .first()
        )
        pending = ctx.dbSession.query(AcmeOrder.id).filter(
            AcmeOrder.private_key_id == key.id,
            sqlalchemy.or_(
                AcmeOrder.acme_status_order_id.in_(
                    model_utils.Acme_Status_Order.IDS_active
                ),
                # Remote issuance consumes a single-use key even if its local
                # certificate download has not completed yet.
                AcmeOrder.acme_status_order_id
                == model_utils.Acme_Status_Order.from_string("valid"),
            ),
        )
        if order is not None:
            pending = pending.filter(AcmeOrder.id != order.id)
        if issued is not None or pending.first() is not None:
            raise errors.InvalidRequest(
                "The single-use private key is already used or reserved"
            )
    if key_type == model_utils.PrivateKey_Type.SINGLE_USE__REUSE_1_YEAR:
        if (
            not allow_yearly_reuse
            or order is None
            or order.renewal_configuration_id is None
        ):
            raise errors.InvalidRequest(
                "Yearly-reuse keys are only for renewals of their configuration"
            )
        if key.acme_account_id__owner != account_id:
            raise errors.InvalidRequest(
                "A yearly-reuse key must have the matching account owner"
            )
        import datetime

        if (
            key.timestamp_created <= ctx.timestamp - datetime.timedelta(days=365)
            or key.timestamp_created > ctx.timestamp
        ):
            raise errors.InvalidRequest(
                "The yearly-reuse private key is outside its reuse period"
            )
        other_configuration = (
            ctx.dbSession.query(AcmeOrder.id)
            .filter(
                AcmeOrder.private_key_id == key.id,
                sqlalchemy.or_(
                    AcmeOrder.renewal_configuration_id.is_(None),
                    AcmeOrder.renewal_configuration_id
                    != order.renewal_configuration_id,
                ),
            )
            .first()
        )
        if other_configuration is not None:
            raise errors.InvalidRequest(
                "The yearly-reuse key belongs to another renewal configuration"
            )
