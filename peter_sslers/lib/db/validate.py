# logging
import logging

log = logging.getLogger(__name__)

# localapp
from ...lib import errors
from .get import get__DomainBlacklisted__by_name


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def validate_domain_names(ctx, domain_names):
    # check for blacklists here
    # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
    _blacklisted_domain_names = []
    for _domain_name in domain_names:
        _dbDomainBlacklisted = get__DomainBlacklisted__by_name(
            ctx, _domain_name
        )
        if _dbDomainBlacklisted:
            _blacklisted_domain_names.append(_domain_name)
    if _blacklisted_domain_names:
        raise errors.AcmeBlacklistedDomains(_blacklisted_domain_names)
    return True