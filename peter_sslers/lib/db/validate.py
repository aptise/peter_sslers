# logging
import logging

log = logging.getLogger(__name__)

# localapp
from .. import errors

from .get import get__AcmeDnsServerAccount__by_DomainId
from .get import get__Domain__by_name
from .get import get__DomainBlocklisted__by_name

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def validate_domain_names(ctx, domain_names):
    # check for blocklists here
    # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
    _blocklisted_domain_names = []
    for _domain_name in domain_names:
        _dbDomainBlocklisted = get__DomainBlocklisted__by_name(ctx, _domain_name)
        if _dbDomainBlocklisted:
            _blocklisted_domain_names.append(_domain_name)
    if _blocklisted_domain_names:
        raise errors.AcmeDomainsBlocklisted(_blocklisted_domain_names)
    return True


def ensure_domains_dns01(ctx, domain_names):
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
