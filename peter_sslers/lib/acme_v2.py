from __future__ import print_function

import logging

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# ==============================================================================


_DEFAULT_CA = "https://acme-staging-v02.api.letsencrypt.org/directory"
CERTIFICATE_AUTHORITY = _DEFAULT_CA
CERTIFICATE_AUTHORITY_AGREEMENT = None
TESTING_ENVIRONMENT = False


# ==============================================================================


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ()
