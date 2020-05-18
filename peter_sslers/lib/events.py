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
from .db import get as db_get
from .db import update as db_update


# ==============================================================================

# TODO - actual event subscribers

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
        if serverCertificate.acme_account_key:
            requeue = True
        else:
            requeue = False
    if requeue:
        dbQueue = lib.db.create.create__QueueCertificate(
            ctx,
            dbAcmeAccountKey=serverCertificate.acme_account_key,
            dbPrivateKey=serverCertificate.private_key,
            dbServerCertificate=serverCertificate,
            private_key_cycle_id__renewal=serverCertificate.renewal__private_key_cycle_id,
            private_key_strategy_id__requested=serverCertificate.renewal__private_key_strategy_id,
        )
        return True
    return False


def _handle_certificate_activated(ctx, serverCertificate):
    """
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
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_certificate_activated(ctx, serverCertificate)


def Certificate_renewed(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_certificate_activated(ctx, serverCertificate)


def Certificate_expired(ctx, serverCertificate):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param serverCertificate: (required) A :class:`model.objects.ServerCertificate` object
    """
    _handle_Certificate_unactivated(ctx, serverCertificate)


def Certificate_unactivated(ctx, serverCertificate):
    """
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

    # create a dict of cert_id:fqdn_set_id
    revoked_certificates = {
        "active": [],
        "inactive": [],
        "not_renewable": [],
        "*data": {},
    }
    dbAcmeAccountKey__GlobalDefault = db_get.get__AcmeAccountKey__GlobalDefault(ctx)
    dbPrivateKey_placeholder = db_get.get__PrivateKey__by_id(ctx, 0)
    items_count = lib.db.get.get__ServerCertificate__by_PrivateKeyId__count(
        ctx, privateKeyCompromised.id
    )
    if items_count:
        batch_size = 20
        batches = int(math.ceil(items_count / float(batch_size)))
        for i in range(0, batches):
            offset = i * batch_size
            items_paginated = lib.db.get.get__ServerCertificate__by_PrivateKeyId__paginated(
                ctx, privateKeyCompromised.id, limit=batch_size, offset=offset
            )
            for _dbServerCertificate in items_paginated:
                _certificate_id = _dbServerCertificate.id
                if _dbServerCertificate.is_active:
                    revoked_certificates["active"].append(_certificate_id)
                else:
                    revoked_certificates["inactive"].append(_certificate_id)
                db_update.update_ServerCertificate__mark_compromised(
                    ctx,
                    _dbServerCertificate,
                )
                revoked_certificates["*data"][_certificate_id] = (
                    _dbServerCertificate.acme_order.id
                    if _dbServerCertificate.acme_order
                    else None,
                    _dbServerCertificate.acme_order.acme_account_key_id
                    if _dbServerCertificate.acme_order
                    else None,
                    _dbServerCertificate.unique_fqdn_set_id,
                )
                ctx.dbSession.flush(objects=[_dbServerCertificate])

                # do we need to replace the certificate?
                # for now, YES
                # it doesn't matter what auto-renew says; we are doing triage!
                
                _dbUniqueFQDNSet = _dbServerCertificate.unique_fqdn_set
                _dbPrivateKey = dbPrivateKey_placeholder
                _private_key_cycle_id__renewal = None
                private_key_strategy_id__requested = None
                
                raise ValueError("ACTIVE WORKING")

                if _dbServerCertificate.renewals_managed_by == "AcmeOrder":
                    _dbAcmeAccountKey = dbServerCertificate.acme_order.acme_account_key
                    if not _dbAcmeAccountKey or not _dbAcmeAccountKey.is_active:
                        revoked_certificates["not_renewable"].append(_certificate_id)
                        continue
                    _private_key_cycle_id__renewal = dbServerCertificate.acme_order.private_key_cycle_id__renewal
                    
                    
                    
                    _private_key_strategy__requested = model_utils.PrivateKeyCycle_2_PrivateKeyStrategy[dbServerCertificate.acme_order.private_key_cycle__renewal]
                    _private_key_strategy_id__requested = model_utils.PrivateKeyStrategy.from_string(_private_key_strategy__requested)
                elif _dbServerCertificate.renewals_managed_by == "ServerCertificate":


                else:
                    raise ValueError('not possible')




                # queue a new certificate
                 if (dbServerCertificate.acme_order and dbServerCertificate.acme_order.acme_account_key.is_active) else dbAcmeAccountKey__GlobalDefault
                if not _dbAcmeAccountKey:
                    revoked_certificates["not_renewable"].append(_certificate_id)
                    continue

                dbQueueCertificate = lib_db.create.create__QueueCertificate(
                    self.request.api_context,
                    dbAcmeAccountKey=_dbAcmeAccountKey,
                    dbPrivateKey=dbPrivateKey_placeholder,
                    dbUniqueFQDNSet=_dbServerCertificate.unique_fqdn_set,
                    private_key_cycle_id__renewal=private_key_cycle_id__renewal,
                    private_key_strategy_id__requested=privateKeySelection.private_key_strategy_id__requested,
                )                

                result = lib.db.queues.queue_certificates__via_fqdns(
                    ctx,
                    dbAcmeAccountKey=dbAcmeAccountKey,
                    dbPrivateKey=dbPrivateKeyNew,
                    unique_fqdn_set_ids=queue_unique_fqdn_set_ids,
                )



        #  make a new PrivateKey
        # this should REPLACE the previous
        raise ValueError("todo")
        dbPrivateKeyNew = lib.db.create.create__PrivateKey(
            ctx,
            # bits=4096,
            private_key_source_id=model_utils.PrivateKeySource.from_string("generated"),
            private_key_type_id=model_utils.PrivateKeyType.from_string("global_weekly"),
        )

        account_2_cert_data = {}
        for certificate_id in revoked_certificates["*data"].keys():
            acme_account_key_id, unique_fqdn_set_id = revoked_certificates["*data"][
                certificate_id
            ]
            if acme_account_key_id not in account_2_cert_data:
                account_2_cert_data[acme_account_key_id] = []
            account_2_cert_data[acme_account_key_id].append(
                (certificate_id, unique_fqdn_set_id,)
            )
        for account_key_id in account_2_cert_data.keys():
            queue_unique_fqdn_set_ids = []
            for (certificate_id, unique_fqdn_set_id) in account_2_cert_data[
                account_key_id
            ]:
                if certificate_id in revoked_certificates["active"]:
                    queue_unique_fqdn_set_ids.append(unique_fqdn_set_id)
            if queue_unique_fqdn_set_ids:
                dbAcmeAccountKey = lib.db.get.get__AcmeAccountKey__by_id(
                    ctx, account_key_id
                )
                if not dbAcmeAccountKey or not dbAcmeAccountKey.is_active:
                    # we can't queue these
                    not_renewable.extend(queue_unique_fqdn_set_ids)
                    continue
                raise ValueError("TODO")
                result = lib.db.queues.queue_certificates__via_fqdns(
                    ctx,
                    dbAcmeAccountKey=dbAcmeAccountKey,
                    dbPrivateKey=dbPrivateKeyNew,
                    unique_fqdn_set_ids=queue_unique_fqdn_set_ids,
                )

    event_payload = dbOperationsEvent.event_payload_json
    event_payload["certificates.revoked"] = {
        "active": list(revoked_certificates["active"]),
        "inactive": list(revoked_certificates["inactive"]),
    }
    event_payload["certificates.not_renewable"] = revoked_certificates["not_renewable"]
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
