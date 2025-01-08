# stdlib
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi

# localapp
from .create import create__AcmeDnsServerAccount
from .get import get__AcmeDnsServerAccount__by_AcmeDnsServerId_DomainId
from .getcreate import getcreate__Domain__by_domainName
from ...lib import acmedns as lib_acmedns
from ...model.objects import AcmeOrder

if TYPE_CHECKING:
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeDnsServerAccount
    from ...model.objects import Domain
    from ...model.objects import RenewalConfiguration
    from ..utils import ApiContext


# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

TYPE_DomainName_2_DomainObject = Dict[str, "Domain"]
TYPE_DomainName_2_AcmeDnsServerAccount = Dict[str, "AcmeDnsServerAccount"]


def ensure_domain_names_to_acmeDnsServer(
    ctx: "ApiContext",
    domain_names: List[str],
    dbAcmeDnsServer: "AcmeDnsServer",
    discovery_type: str,
) -> Tuple[TYPE_DomainName_2_DomainObject, TYPE_DomainName_2_AcmeDnsServerAccount]:
    client = lib_acmedns.new_client(dbAcmeDnsServer.root_url)
    domainObjectsMap: TYPE_DomainName_2_DomainObject = {}
    accountObjectsMap: TYPE_DomainName_2_AcmeDnsServerAccount = {}
    for _domain_name in domain_names:
        _dbAcmeDnsServerAccount = None
        # _is_created__account = None
        (
            _dbDomain,
            _is_created__domain,
        ) = getcreate__Domain__by_domainName(
            ctx,
            _domain_name,
            discovery_type=discovery_type,
        )
        if not _is_created__domain:
            _dbAcmeDnsServerAccount = (
                get__AcmeDnsServerAccount__by_AcmeDnsServerId_DomainId(
                    ctx,
                    acme_dns_server_id=dbAcmeDnsServer.id,
                    domain_id=_dbDomain.id,
                )
            )
        if not _dbAcmeDnsServerAccount:
            try:
                account = client.register_account(None)  # arg = allowlist ips
            except Exception as exc:  # noqa: F841
                raise ValueError("error registering an account with AcmeDns")
            _dbAcmeDnsServerAccount = create__AcmeDnsServerAccount(
                ctx,
                dbAcmeDnsServer=dbAcmeDnsServer,
                dbDomain=_dbDomain,
                username=account["username"],
                password=account["password"],
                fulldomain=account["fulldomain"],
                subdomain=account["subdomain"],
                allowfrom=account["allowfrom"],
            )

        # stash it
        domainObjectsMap[_domain_name] = _dbDomain
        accountObjectsMap[_domain_name] = _dbAcmeDnsServerAccount
    return (domainObjectsMap, accountObjectsMap)


def check_competing_orders_RenewalConfiguration(
    ctx: "ApiContext",
    dbRenewalConfiguration: "RenewalConfiguration",
) -> Optional[AcmeOrder]:
    dbAcmeOrder = (
        ctx.dbSession.query(AcmeOrder)
        .filter(
            AcmeOrder.renewal_configuration_id == dbRenewalConfiguration.id,
            AcmeOrder.is_processing.is_(True),
        )
        .first()
    )
    return dbAcmeOrder
