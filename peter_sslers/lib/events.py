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
    if serverCertificate.acme_order:
        private_key_cycle_id__renewal = (
            serverCertificate.acme_order.private_key_cycle__renewal
        )
    else:
        private_key_cycle_id__renewal = model_utils.PrivateKeyCycle.from_string(
            model_utils.PrivateKeyCycle._DEFAULT_system_renewal
        )
    if not dbLatestActiveCert:
        if serverCertificate.acme_account_key:
            requeue = True
        else:
            requeue = False
    if requeue:
        dbQuque = lib.db.create.create__QueueCertificate(
            ctx,
            dbAcmeAccountKey=serverCertificate.acme_account_key,
            dbPrivateKey=serverCertificate.private_key,
            dbServerCertificate=serverCertificate,
            private_key_cycle_id__renewal=private_key_cycle_id__renewal,
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
        "*data": {},
    }
    certificates_not_renewable = []
    revoked_fqdn_ids_2_certs = {}
    items_count = lib.db.get.get__ServerCertificate__by_PrivateKeyId__count(
        ctx, privateKeyCompromised.id
    )
    if items_count and False:

        batch_size = 20
        batches = int(math.ceil(items_count / float(batch_size)))
        for i in range(0, batches):
            offset = i * batch_size
            items_paginated = lib.db.get.get__ServerCertificate__by_PrivateKeyId__paginated(
                ctx, privateKeyCompromised.id, limit=batch_size, offset=offset
            )
            for dbServerCertificate in items_paginated:
                dbServerCertificate.is_compromised_private_key = True
                dbServerCertificate.is_revoked = True
                revoked_certificates["*data"][dbServerCertificate.id] = (
                    dbServerCertificate.acme_order.acme_account_key_id
                    if dbServerCertificate.acme_order
                    else None,
                    dbServerCertificate.unique_fqdn_set_id,
                )
                if dbServerCertificate.is_active:
                    revoked_certificates["active"].append(dbServerCertificate.id)
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
                    revoked_certificates["inactive"].append(dbServerCertificate.id)
                ctx.dbSession.flush(objects=[dbServerCertificate])

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
                    certificates_not_renewable.extend(queue_unique_fqdn_set_ids)
                    continue
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
    event_payload["certificates.not_renewable"] = certificates_not_renewable
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
