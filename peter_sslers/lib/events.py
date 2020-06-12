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
from ..model import utils as model_utils
from .db import create as db_create
from .db import get as db_get
from .db import update as db_update


# ==============================================================================


# certificate should have a "latest fqdn"
# issuing a cert should remove any similar fqdns from the queue


def _handle_Certificate_unactivated(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    # ok. so let's find out the fqdn...
    dbLatestActiveCert = lib.db.get.get__ServerCertificate__by_UniqueFQDNSetId__latest_active(
        ctx, serverCertificate.unique_fqdn_set_id
    )
    requeue = None
    if not dbLatestActiveCert:
        if serverCertificate.acme_account:
            requeue = True
        else:
            requeue = False
    if requeue:
        dbQueue = lib.db.create.create__QueueCertificate(
            ctx,
            dbAcmeAccount=serverCertificate.acme_account,
            dbPrivateKey=serverCertificate.private_key,
            dbServerCertificate=serverCertificate,
            private_key_cycle_id__renewal=serverCertificate.renewal__private_key_cycle_id,
            private_key_strategy_id__requested=serverCertificate.renewal__private_key_strategy_id,
        )
    return requeue


def _handle_Certificate_new(ctx, serverCertificate):
    """
    Database cleanup and reconciliation when a Certificate is issued:
    * issued directly
    * issued via a renewal

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    dbActiveQueues = lib.db.get.get__QueueCertificate__by_UniqueFQDNSetId__active(
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
    Database cleanup and reconciliation when a Certificate is issued (new).

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_Certificate_new(ctx, serverCertificate)


def Certificate_renewed(ctx, serverCertificate):
    """
    Database cleanup and reconciliation when a Certificate is issued (renewal).

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_Certificate_new(ctx, serverCertificate)


def Certificate_expired(ctx, serverCertificate):
    """
    Database cleanup and reconciliation when a Certificate is expired.

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_Certificate_unactivated(ctx, serverCertificate)


def Certificate_unactivated(ctx, serverCertificate):
    """
    Database cleanup and reconciliation when a Certificate is unactivated.

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_Certificate_unactivated(ctx, serverCertificate)


def PrivateKey_compromised(ctx, privateKeyCompromised, dbOperationsEvent=None):
    """
    * Marks every ServerCertificate signed by this PrivateKey as compromised.
      Removes the ServerCertificates from the pool of valid ServerCertificates.
    * Queues a new ServerCertificate

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param privateKeyCompromised: (required) A :class:`model.objects.PrivateKey` object
    :param dbOperationsEvent:
    """
    dbCoverageAssuranceEvent = db_create.create__CoverageAssuranceEvent(
        ctx,
        coverage_assurance_event_type_id=model_utils.CoverageAssuranceEventType.from_string(
            "PrivateKey_compromised_mark"
        ),
        coverage_assurance_event_status_id=model_utils.CoverageAssuranceEventStatus.from_string(
            "reported+deactivated"
        ),
        dbPrivateKey=privateKeyCompromised,
    )

    # create a dict of cert_id:fqdn_set_id
    pkey_certificates = {
        "active": [],
        "inactive": [],
        # "not_renewable": [],
        "*data": {},  # k(Cerfiticate.id): v(tuple(fqdn_id, acme_order_id, acme_account_id))
    }

    # does this PrivateKey have certificates?
    items_count = lib.db.get.get__ServerCertificate__by_PrivateKeyId__count(
        ctx, privateKeyCompromised.id
    )
    if not items_count:
        return None

    # loop through all the ServerCertificates for this PrivateKey
    # log CoverageAssuranceEvents for them
    batch_size = 20
    batches = int(math.ceil(items_count / float(batch_size)))
    child_events = []
    for i in range(0, batches):
        offset = i * batch_size
        items_paginated = lib.db.get.get__ServerCertificate__by_PrivateKeyId__paginated(
            ctx, privateKeyCompromised.id, limit=batch_size, offset=offset
        )
        for _dbServerCertificate in items_paginated:
            _certificate_id = _dbServerCertificate.id
            pkey_certificates["*data"][_certificate_id] = (
                _dbServerCertificate.unique_fqdn_set_id,
                _dbServerCertificate.acme_order.id
                if _dbServerCertificate.acme_order
                else None,
                _dbServerCertificate.acme_order.acme_account_id
                if _dbServerCertificate.acme_order
                else None,
            )
            if _dbServerCertificate.is_active:
                pkey_certificates["active"].append(_certificate_id)
            else:
                pkey_certificates["inactive"].append(_certificate_id)
            db_update.update_ServerCertificate__mark_compromised(
                ctx, _dbServerCertificate, via_PrivateKey_compromised=True
            )
            ctx.dbSession.flush(objects=[_dbServerCertificate])

            _cae_certificate = db_create.create__CoverageAssuranceEvent(
                ctx,
                coverage_assurance_event_type_id=model_utils.CoverageAssuranceEventType.from_string(
                    "PrivateKey_compromised_mark"
                ),
                coverage_assurance_event_status_id=model_utils.CoverageAssuranceEventStatus.from_string(
                    "reported+deactivated"
                ),
                dbPrivateKey=privateKeyCompromised,
                dbServerCertificate=_dbServerCertificate,
                dbCoverageAssuranceEvent_parent=dbCoverageAssuranceEvent,
            )
            child_events.append(_cae_certificate)

    event_payload = dbOperationsEvent.event_payload_json
    event_payload["coverage_assurance_event.id"] = dbCoverageAssuranceEvent.id
    event_payload["coverage_assurance_event__children.id"] = [
        e.id for e in child_events
    ]
    event_payload["server_certificates.revoked"] = {
        "active": list(pkey_certificates["active"]),
        "inactive": list(pkey_certificates["inactive"]),
    }
    dbOperationsEvent.set_event_payload(event_payload)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "Certificate_issued",
    "Certificate_renewed",
    "Certificate_expired",
    "Certificate_unactivated",
    "PrivateKey_compromised",
)
