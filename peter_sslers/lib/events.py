# stdlib
import datetime
import logging
import math

# setup logging
log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# local
from .. import lib


# ==============================================================================

# TODO - actual event subscribers

# certificate should have a "latest fqdn"
# issuing a cert should remove any similar fqdns from the queue


def _handle_certificate_deactivated(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    # ok. so let's find out the fqdn...
    requeue = False
    dbLatestActiveCert = lib.db.get.get__ServerCertificate__by_UniqueFQDNSetId__latest_active(
        ctx, serverCertificate.unique_fqdn_set_id
    )
    if not dbLatestActiveCert:
        requeue = True
    if requeue:
        dbQuque = lib.db.create._create__QueueRenewal(ctx, serverCertificate)
        return True
    return False


def _handle_certificate_activated(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    dbActiveQueues = lib.db.get.get__QueueRenewal__by_UniqueFQDNSetId__active(
        ctx, serverCertificate.unique_fqdn_set_id
    )
    if dbActiveQueues:
        tnow = datetime.datetime.utcnow()
        for q in dbActiveQueues:
            q.timestamp_processed = tnow
            q.timestamp_process_attempt = tnow
            q.process_result = True
            ctx.dbSession.flush(objects=[q])
        return True
    return False


def Certificate_issued(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_certificate_activated(ctx, serverCertificate)


def Certificate_renewed(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_certificate_activated(ctx, serverCertificate)


def Certificate_expired(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_certificate_deactivated(ctx, serverCertificate)


def Certificate_deactivated(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_certificate_deactivated(ctx, serverCertificate)


def PrivateKey_compromised(ctx, privateKey, dbOperationsEvent=None):
    """
    mark every certificate signed by this key compromised

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param privateKey: (required) A :class:`model.objects.PrivateKey` object
    :param dbOperationsEvent:
    """

    # create a dict of cert_id:fqdn_set_id
    revoked_certificates = {"inactive": {}, "active": {}}
    revoked_fqdn_ids_2_certs = {}
    items_count = lib.db.get.get__ServerCertificate__by_PrivateKeyId__count(
        ctx, privateKey.id
    )
    if items_count:
        batch_size = 20
        batches = int(math.ceil(items_count / float(batch_size)))
        for i in range(0, batches):
            offset = i * batch_size
            items_paginated = lib.db.get.get__ServerCertificate__by_PrivateKeyId__paginated(
                ctx, privateKey.id, limit=batch_size, offset=offset
            )
            for dbServerCertificate in items_paginated:
                if dbServerCertificate.is_active:
                    revoked_certificates["active"][
                        dbServerCertificate.id
                    ] = dbServerCertificate.unique_fqdn_set_id
                    dbServerCertificate.is_active = False
                    if (
                        dbServerCertificate.unique_fqdn_set_id
                        not in revoked_fqdn_ids_2_certs
                    ):
                        revoked_fqdn_ids_2_certs[
                            dbServerCertificate.unique_fqdn_set_id
                        ] = []
                    revoked_fqdn_ids_2_certs[
                        dbServerCertificate.unique_fqdn_set_id
                    ].append(dbServerCertificate.id)
                else:
                    revoked_certificates["inactive"][
                        dbServerCertificate.id
                    ] = dbServerCertificate.unique_fqdn_set_id
                dbServerCertificate.is_revoked = True
                ctx.dbSession.flush(objects=[dbServerCertificate])

    # handle this in 2 passes
    # first, queue anything that doesn't have an active cert
    # then, we'll pickup any soon-expiring certs by automatic crons
    # TODO there is a SMALL chance that something could deactivate a cert before we renew
    for (fqdn_id, cert_ids_off) in revoked_fqdn_ids_2_certs.items():
        latest_cert = lib.db.get.get__ServerCertificate__by_UniqueFQDNSetId__latest_active(
            ctx, fqdn_id
        )
        if not latest_cert:
            # use the MAX cert as the renewal item
            max_cert_id = max(cert_ids_off)
            serverCertificate = lib.db.get.get__ServerCertificate__by_id(
                ctx, max_cert_id
            )
            dbQueue = lib.db.create._create__QueueRenewal(ctx, serverCertificate)

    # okay, now try to requeue items
    revoked_fqdns_ids = list(revoked_fqdn_ids_2_certs.keys())
    result = lib.db.queues.queue_renewals__update(ctx, fqdns_ids_only=revoked_fqdns_ids)

    event_payload = dbOperationsEvent.event_payload_json
    event_payload["revoked.certificates"] = {
        "active": list(revoked_certificates["active"].keys()),
        "inactive": list(revoked_certificates["inactive"].keys()),
    }
    event_payload["revoked.fqdns_ids"] = revoked_fqdns_ids
    dbOperationsEvent.set_event_payload(event_payload)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "Certificate_issued",
    "Certificate_renewed",
    "Certificate_expired",
    "Certificate_deactivated",
    "PrivateKey_compromised",
)
