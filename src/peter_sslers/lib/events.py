# stdlib
import datetime
import logging
import math
from typing import Dict
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union


# local
from .db import create as db_create
from .db import update as db_update
from .. import lib
from ..model import utils as model_utils

# from .db import get as db_get

if TYPE_CHECKING:
    from .utils import ApiContext
    from ..model.objects import CertificateSigned
    from ..model.objects import OperationsEvent
    from ..model.objects import PrivateKey

# ==============================================================================

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# ------------------------------------------------------------------------------

# certificate should have a "latest fqdn"
# issuing a cert should remove any similar fqdns from the queue


def _handle_Certificate_unactivated(
    ctx: "ApiContext",
    serverCertificate: "CertificateSigned",
) -> Optional[bool]:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.CertificateSigned` object
    """
    # ok. so let's find out the fqdn...
    dbLatestActiveCert = (
        lib.db.get.get__CertificateSigned__by_UniqueFQDNSetId__latest_active(
            ctx, serverCertificate.unique_fqdn_set_id
        )
    )
    requeue = None
    if not dbLatestActiveCert:
        if serverCertificate.acme_account:
            requeue = True
        else:
            requeue = False
    if requeue:
        dbQueue = lib.db.create.create__QueueCertificate(  # noqa: F841
            ctx,
            dbAcmeAccount=serverCertificate.acme_account,
            dbPrivateKey=serverCertificate.private_key,
            dbCertificateSigned=serverCertificate,
            private_key_cycle_id__renewal=serverCertificate.renewal__private_key_cycle_id,
            private_key_strategy_id__requested=serverCertificate.renewal__private_key_strategy_id,
        )
    return requeue


def _handle_Certificate_new(
    ctx: "ApiContext",
    serverCertificate: "CertificateSigned",
) -> bool:
    """
    Database cleanup and reconciliation when a Certificate is issued:
    * issued directly
    * issued via a renewal

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.CertificateSigned` object
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


def Certificate_issued(
    ctx: "ApiContext",
    serverCertificate: "CertificateSigned",
):
    """
    Database cleanup and reconciliation when a Certificate is issued (new).

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.CertificateSigned` object
    """
    _handle_Certificate_new(ctx, serverCertificate)


def Certificate_renewed(ctx: "ApiContext", serverCertificate: "CertificateSigned"):
    """
    Database cleanup and reconciliation when a Certificate is issued (renewal).

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.CertificateSigned` object
    """
    _handle_Certificate_new(ctx, serverCertificate)


def Certificate_expired(ctx: "ApiContext", serverCertificate: "CertificateSigned"):
    """
    Database cleanup and reconciliation when a Certificate is expired.

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.CertificateSigned` object
    """
    _handle_Certificate_unactivated(ctx, serverCertificate)


def Certificate_unactivated(ctx: "ApiContext", serverCertificate: "CertificateSigned"):
    """
    Database cleanup and reconciliation when a Certificate is unactivated.

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.CertificateSigned` object
    """
    _handle_Certificate_unactivated(ctx, serverCertificate)


def PrivateKey_compromised(
    ctx: "ApiContext",
    privateKeyCompromised: "PrivateKey",
    dbOperationsEvent: "OperationsEvent",
) -> Optional[bool]:
    """
    * Marks every CertificateSigned signed by this PrivateKey as compromised.
      Removes the CertificateSigneds from the pool of valid CertificateSigneds.
    * Queues a new CertificateSigned

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
    pkey_certificates: Dict[str, Union[List, Dict]] = {
        "active": [],
        "inactive": [],
        # "not_renewable": [],
        "*data": {},  # k(Cerfiticate.id): v(tuple(fqdn_id, acme_order_id, acme_account_id))
    }

    # does this PrivateKey have certificates?
    items_count = lib.db.get.get__CertificateSigned__by_PrivateKeyId__count(
        ctx, privateKeyCompromised.id
    )
    if not items_count:
        return None

    # loop through all the CertificateSigneds for this PrivateKey
    # log CoverageAssuranceEvents for them
    batch_size = 20
    batches = int(math.ceil(items_count / float(batch_size)))
    child_events = []
    for i in range(0, batches):
        offset = i * batch_size
        items_paginated = lib.db.get.get__CertificateSigned__by_PrivateKeyId__paginated(
            ctx, privateKeyCompromised.id, limit=batch_size, offset=offset
        )
        for _dbCertificateSigned in items_paginated:
            _certificate_id = _dbCertificateSigned.id
            pkey_certificates["*data"][_certificate_id] = (
                _dbCertificateSigned.unique_fqdn_set_id,
                _dbCertificateSigned.acme_order.id
                if _dbCertificateSigned.acme_order
                else None,
                _dbCertificateSigned.acme_order.acme_account_id
                if _dbCertificateSigned.acme_order
                else None,
            )
            if _dbCertificateSigned.is_active:
                pkey_certificates["active"].append(_certificate_id)  # type: ignore[union-attr]
            else:
                pkey_certificates["inactive"].append(_certificate_id)  # type: ignore[union-attr]
            db_update.update_CertificateSigned__mark_compromised(
                ctx, _dbCertificateSigned, via_PrivateKey_compromised=True
            )
            ctx.dbSession.flush(objects=[_dbCertificateSigned])

            _cae_certificate = db_create.create__CoverageAssuranceEvent(
                ctx,
                coverage_assurance_event_type_id=model_utils.CoverageAssuranceEventType.from_string(
                    "PrivateKey_compromised_mark"
                ),
                coverage_assurance_event_status_id=model_utils.CoverageAssuranceEventStatus.from_string(
                    "reported+deactivated"
                ),
                dbPrivateKey=privateKeyCompromised,
                dbCertificateSigned=_dbCertificateSigned,
                dbCoverageAssuranceEvent_parent=dbCoverageAssuranceEvent,
            )
            child_events.append(_cae_certificate)

    event_payload = dbOperationsEvent.event_payload_json
    event_payload["coverage_assurance_event.id"] = dbCoverageAssuranceEvent.id
    event_payload["coverage_assurance_event__children.id"] = [
        e.id for e in child_events
    ]
    event_payload["certificate_signeds.revoked"] = {
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
