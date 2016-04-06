# stdlib
import datetime
import logging
import math

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

def _handle_certificate_deactivated(dbSession, serverCertificate, operationsEvent=None):
    # ok. so let's find out the fqdn...
    requeue = False
    dbLatestActiveCert = lib.db.get__LetsencryptServerCertificate__by_LetsencryptUniqueFQDNSetId__latest_active(
        dbSession,
        serverCertificate.letsencrypt_unique_fqdn_set_id,
    )
    if not dbLatestActiveCert:
        requeue = True
    if requeue:
        dbQuque = lib.db.create__LetsencryptQueueRenewal(
            DBSession,
            serverCertificate,
            letsencrypt_operations_event_id__child_of = operationsEvent.id,
        )
        return True
    return False


def _handle_certificate_activated(dbSession, serverCertificate, operationsEvent=None):
    dbActiveQueues = lib.db.get__LetsencryptQueueRenewal__by_LetsencryptUniqueFQDNSetId__active(
        dbSession,
        serverCertificate.letsencrypt_unique_fqdn_set_id,
    )
    if dbActiveQueues:
        tnow = datetime.datetime.utcnow()
        for q in dbActiveQueues:
            q.timestamp_processed = tnow
            q.process_result = True
        dbSession.flush()
        return True
    return False


def Certificate_issued(dbSession, serverCertificate, operationsEvent=None):
    _handle_certificate_activated(dbSession, serverCertificate, operationsEvent=operationsEvent)


def Certificate_renewed(dbSession, serverCertificate, operationsEvent=None):
    _handle_certificate_activated(dbSession, serverCertificate, operationsEvent=operationsEvent)


def Certificate_expired(dbSession, serverCertificate, operationsEvent=None):
    _handle_certificate_deactivated(dbSession, serverCertificate, operationsEvent=operationsEvent)


def Certificate_deactivated(dbSession, serverCertificate, operationsEvent=None):
    _handle_certificate_deactivated(dbSession, serverCertificate, operationsEvent=operationsEvent)


def PrivateKey_compromised(dbSession, privateKey, operationsEvent=None):
    # mark every certificate signed by this key compromised
    
    # create a dict of cert_id:fqdn_set_id
    revoked_certificates = {'inactive': {},
                            'active': {},
                            }
    revoked_fqdn_ids_2_certs = {}
    items_count = lib.db.get__LetsencryptServerCertificate__by_LetsencryptPrivateKeyId__count(
        dbSession,
        privateKey.id
    )
    if items_count:
        batch_size = 20
        batches = int(math.ceil(items_count/float(batch_size)))
        for i in range(0, batches):
            offset = i * batch_size
            items_paginated = lib.db.get__LetsencryptServerCertificate__by_LetsencryptPrivateKeyId__paginated(
                dbSession,
                privateKey.id,
                limit = batch_size,
                offset = offset
            )
            for cert in items_paginated:
                if cert.is_active:
                    revoked_certificates['active'][cert.id] = cert.letsencrypt_unique_fqdn_set_id
                    cert.is_active = False
                    if cert.letsencrypt_unique_fqdn_set_id not in revoked_fqdn_ids_2_certs:
                        revoked_fqdn_ids_2_certs[cert.letsencrypt_unique_fqdn_set_id] = []
                    revoked_fqdn_ids_2_certs[cert.letsencrypt_unique_fqdn_set_id].append(cert.id)
                else:
                    revoked_certificates['inactive'][cert.id] = cert.letsencrypt_unique_fqdn_set_id
                cert.is_revoked = True
                dbSession.flush()

    # handle this in 2 passes
    # first, queue anything that doesn't have an active cert
    # then, we'll pickup any soon-expiring certs by automatic crons
    # TODO there is a SMALL chance that something could deactivate a cert before we renew
    for (fqdn_id, cert_ids_off) in revoked_fqdn_ids_2_certs.items():
        latest_cert = lib.db.get__LetsencryptServerCertificate__by_LetsencryptUniqueFQDNSetId__latest_active(
            dbSession,
            fqdn_id
        )
        if not latest_cert:
            # use the MAX cert as the renewal item
            max_cert_id = max(cert_ids_off)
            serverCertificate = lib.db.get__LetsencryptServerCertificate__by_id(dbSession, max_cert_id)
            dbQueue = lib.db.create__LetsencryptQueueRenewal(
                dbSession, 
                serverCertificate,
                letsencrypt_operations_event_id__child_of = operationsEvent.id
            )
        dbSession.flush()
    
    # okay, now try to requeue items
    revoked_fqdns_ids = revoked_fqdn_ids_2_certs.keys()
    result =  lib.db.queue_renewals__process(
        dbSession,
        letsencrypt_operations_event_id__child_of = operationsEvent.id,
        fqdns_ids_only = revoked_fqdns_ids,
    )

    event_payload = operationsEvent.event_payload_json
    event_payload['revoked.certificates'] = {'active': revoked_certificates['active'].keys(),
                                             'inactive': revoked_certificates['inactive'].keys(),
                                             }
    event_payload['revoked.fqdns_ids'] = revoked_fqdns_ids
    operationsEvent.set_event_payload(event_payload)
    dbSession.flush()

    return True

