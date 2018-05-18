# logging
import logging
log = logging.getLogger(__name__)

# localapp
from ...models import models
from .. import utils


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def log__SslOperationsEvent(
    ctx,
    event_type_id,
    event_payload_dict = None,
    dbOperationsEvent_child_of=None,
    timestamp_event=None,
):
    """
    creates a SslOperationsEvent instance
    if needed, registers it into the ctx
    """
    # defaults
    # timestamp overwrite?
    timestamp_event = timestamp_event or ctx.timestamp
    # if we didn't pass in an explicit dbOperationsEvent_child_of, use the global
    dbOperationsEvent_child_of = dbOperationsEvent_child_of or ctx.dbOperationsEvent

    if event_payload_dict is None:
        event_payload_dict = utils.new_event_payload_dict()

    # bookkeeping
    dbOperationsEvent = models.SslOperationsEvent()
    dbOperationsEvent.ssl_operations_event_type_id = event_type_id
    dbOperationsEvent.timestamp_event = timestamp_event
    dbOperationsEvent.set_event_payload(event_payload_dict)
    if dbOperationsEvent_child_of:
        dbOperationsEvent.ssl_operations_event_id__child_of = dbOperationsEvent_child_of.id
    ctx.dbSession.add(dbOperationsEvent)
    ctx.dbSession.flush(objects=[dbOperationsEvent, ])

    # shortcut!
    # if there isn't a global dbOperationsEvent, set it!
    if not ctx.dbOperationsEvent:
        ctx.dbOperationsEvent = dbOperationsEvent

    return dbOperationsEvent


def _log_object_event(
    ctx,
    dbOperationsEvent=None,
    event_status_id=None,
    dbAcmeAccountKey=None,
    dbCACertificate=None,
    dbDomain=None,
    dbPrivateKey=None,
    dbServerCertificate=None,
    dbUniqueFQDNSet=None,
    dbCertificateRequest=None,
    dbQueueRenewal=None,
    dbQueueDomain=None,
):
    """additional logging for objects"""
    dbOperationsObjectEvent = models.SslOperationsObjectEvent()
    dbOperationsObjectEvent.ssl_operations_event_id = dbOperationsEvent.id
    dbOperationsObjectEvent.ssl_operations_object_event_status_id = event_status_id

    if dbAcmeAccountKey:
        dbOperationsObjectEvent.ssl_acme_account_key_id = dbAcmeAccountKey.id
    elif dbCACertificate:
        dbOperationsObjectEvent.ssl_ca_certificate_id = dbCACertificate.id
    elif dbDomain:
        dbOperationsObjectEvent.ssl_domain_id = dbDomain.id
    elif dbPrivateKey:
        dbOperationsObjectEvent.ssl_private_key_id = dbPrivateKey.id
    elif dbServerCertificate:
        dbOperationsObjectEvent.ssl_server_certificate_id = dbServerCertificate.id
    elif dbUniqueFQDNSet:
        dbOperationsObjectEvent.ssl_unique_fqdn_set_id = dbUniqueFQDNSet.id
    elif dbCertificateRequest:
        dbOperationsObjectEvent.ssl_certificate_request_id = dbCertificateRequest.id
    elif dbQueueRenewal:
        dbOperationsObjectEvent.ssl_queue_renewal_id = dbQueueRenewal.id
    elif dbQueueDomain:
        dbOperationsObjectEvent.ssl_queue_domain_id = dbQueueDomain.id

    ctx.dbSession.add(dbOperationsObjectEvent)
    ctx.dbSession.flush(objects=[dbOperationsObjectEvent, ])

    return dbOperationsObjectEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ('log__SslOperationsEvent',
           '_log_object_event',
           )
