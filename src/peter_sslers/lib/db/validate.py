# srdlib
import logging
from typing import Iterable
from typing import TYPE_CHECKING

# pypi
import tldextract

# localapp
from .get import get__AcmeDnsServerAccount__by_DomainId
from .get import get__Domain__by_name
from .get import get__DomainBlocklisted__by_name
from .. import errors

if TYPE_CHECKING:
    from ..context import ApiContext

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
