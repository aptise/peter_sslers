# stdlib
import logging
import math
from typing import Dict
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union

# import datetime

# local
from .db import actions as db_actions
from .db import create as db_create
from .db import update as db_update
from .. import lib
from ..model import utils as model_utils

if TYPE_CHECKING:
    from .context import ApiContext
    from ..model.objects import OperationsEvent
    from ..model.objects import PrivateKey
    from ..model.objects import X509Certificate

# from .db import get as db_get

# ==============================================================================

log = logging.getLogger("peter_sslers.lib")

# ------------------------------------------------------------------------------

# certificate should have a "latest fqdn"
# issuing a cert should remove any similar fqdns from the queue


def _handle_Certificate_unactivated(
    ctx: "ApiContext",
    dbX509Certificate: "X509Certificate",
) -> Optional[bool]:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbX509Certificate: (required) A :class:`model.objects.X509Certificate` object
    """
    operations_event = db_actions.operations_update_recents__domains(  # noqa: F841
        ctx,
        dbUniqueFQDNSets=[
            dbX509Certificate.unique_fqdn_set,
        ],
    )
    return True


def _handle_Certificate_new(
    ctx: "ApiContext",
    dbX509Certificate: "X509Certificate",
) -> bool:
    """
    Database cleanup and reconciliation when a Certificate is issued:
    * issued directly
    * issued via a renewal

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbX509Certificate: (required) A :class:`model.objects.X509Certificate` object
    """
    operations_event = db_actions.operations_update_recents__domains(  # noqa: F841
        ctx,
        dbUniqueFQDNSets=[
            dbX509Certificate.unique_fqdn_set,
        ],
    )
    return True


def Certificate_issued(
    ctx: "ApiContext",
    dbX509Certificate: "X509Certificate",
):
    """
    Database cleanup and reconciliation when a Certificate is issued (new).

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbX509Certificate: (required) A :class:`model.objects.X509Certificate` object
    """
    _handle_Certificate_new(ctx, dbX509Certificate)


def Certificate_renewed(ctx: "ApiContext", dbX509Certificate: "X509Certificate"):
    """
    Database cleanup and reconciliation when a Certificate is issued (renewal).

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbX509Certificate: (required) A :class:`model.objects.X509Certificate` object
    """
    _handle_Certificate_new(ctx, dbX509Certificate)


def Certificate_expired(ctx: "ApiContext", dbX509Certificate: "X509Certificate"):
    """
    Database cleanup and reconciliation when a Certificate is expired.

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbX509Certificate: (required) A :class:`model.objects.X509Certificate` object
    """
    _handle_Certificate_unactivated(ctx, dbX509Certificate)


def Certificate_unactivated(ctx: "ApiContext", dbX509Certificate: "X509Certificate"):
    """
    Database cleanup and reconciliation when a Certificate is unactivated.

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbX509Certificate: (required) A :class:`model.objects.X509Certificate` object
    """
    _handle_Certificate_unactivated(ctx, dbX509Certificate)


def PrivateKey_compromised(
    ctx: "ApiContext",
    privateKeyCompromised: "PrivateKey",
    dbOperationsEvent: "OperationsEvent",
) -> Optional[bool]:
    """
    * Marks every X509Certificate signed by this PrivateKey as compromised.
      Removes the X509Certificates from the pool of valid X509Certificates.
    * Queues a new X509Certificate

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
        # optionals
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
    items_count = lib.db.get.get__X509Certificate__by_PrivateKeyId__count(
        ctx, privateKeyCompromised.id
    )
    if not items_count:
        return None

    # loop through all the X509Certificates for this PrivateKey
    # log CoverageAssuranceEvents for them
    batch_size = 20
    batches = int(math.ceil(items_count / float(batch_size)))
    child_events = []
    for i in range(0, batches):
        offset = i * batch_size
        items_paginated = lib.db.get.get__X509Certificate__by_PrivateKeyId__paginated(
            ctx, privateKeyCompromised.id, limit=batch_size, offset=offset
        )
        for _dbX509Certificate in items_paginated:
            _certificate_id = _dbX509Certificate.id
            pkey_certificates["*data"][_certificate_id] = (
                _dbX509Certificate.unique_fqdn_set_id,
                (
                    _dbX509Certificate.acme_order.id
                    if _dbX509Certificate.acme_order
                    else None
                ),
                (
                    _dbX509Certificate.acme_order.acme_account_id
                    if _dbX509Certificate.acme_order
                    else None
                ),
            )
            if _dbX509Certificate.is_active:
                pkey_certificates["active"].append(_certificate_id)  # type: ignore[union-attr]
            else:
                pkey_certificates["inactive"].append(_certificate_id)  # type: ignore[union-attr]
            db_update.update_X509Certificate__mark_compromised(
                ctx, _dbX509Certificate, via_PrivateKey_compromised=True
            )
            ctx.dbSession.flush(objects=[_dbX509Certificate])

            _cae_certificate = db_create.create__CoverageAssuranceEvent(
                ctx,
                coverage_assurance_event_type_id=model_utils.CoverageAssuranceEventType.from_string(
                    "PrivateKey_compromised_mark"
                ),
                coverage_assurance_event_status_id=model_utils.CoverageAssuranceEventStatus.from_string(
                    "reported+deactivated"
                ),
                # optionals
                dbPrivateKey=privateKeyCompromised,
                dbX509Certificate=_dbX509Certificate,
                dbCoverageAssuranceEvent_parent=dbCoverageAssuranceEvent,
            )
            child_events.append(_cae_certificate)

    event_payload = dbOperationsEvent.event_payload_json
    event_payload["coverage_assurance_event.id"] = dbCoverageAssuranceEvent.id
    event_payload["coverage_assurance_event__children.id"] = [
        e.id for e in child_events
    ]
    event_payload["x509_certificates.revoked"] = {
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
