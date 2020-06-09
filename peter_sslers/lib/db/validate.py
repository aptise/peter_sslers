# logging
import logging

log = logging.getLogger(__name__)

# localapp
from ...lib import errors
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
        raise errors.AcmeBlocklistedDomains(_blocklisted_domain_names)
    return True
