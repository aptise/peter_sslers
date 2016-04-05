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

def Certificate_issued(dbSession, serverCertificate, operationsEvent=None):
    pass


def Certificate_renewed(dbSession, serverCertificate, operationsEvent=None):
    pass


def Certificate_expired(dbSession, serverCertificate, operationsEvent=None):
    pass


def Certificate_deactivated(dbSession, serverCertificate, operationsEvent=None):
    # ok. so let's find out the fqdn...
    requeue = False
    dbLatestActiveCert = lib.db.get__LetsencryptServerCertificate__by_LetsencryptUniqueFQDNSetId__latest_active(
        dbSession,
        serverCertificate.letsencrypt_unique_fqdn_set_id,
    )
    if not dbLatestActiveCert:
        requeue = True
    if requeue:
        dbQuque = lib.db.create__LetsencryptRenewalQueue(
            DBSession,
            serverCertificate,
            letsencrypt_operations_event_id__child_of = operationsEvent.id,
        )
