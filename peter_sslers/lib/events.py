import logging

from ..models import *
from .. import lib

# setup logging
log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# ==============================================================================

# TODO - actual event subscribers

# certificate should have a "latest fqdn"
# issuing a cert should remove any similar fqdns from the queue

def CertificateIssued(dbSession, certificateObject):
    pass

def CertificateRenewed(dbSession, certificateObject):
    pass

def CertificateExpired(dbSession, certificateObject):
    pass
