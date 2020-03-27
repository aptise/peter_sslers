# logging
import logging

log = logging.getLogger(__name__)


# stdlib
import datetime

# pypi
import transaction

# localapp
from ... import lib
from .. import errors
from .. import utils
from ...model import utils as model_utils
from ...model import objects as model_objects

# local
from .logger import log__OperationsEvent
from .logger import _log_object_event


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def dequeue_QueuedDomain(
    ctx,
    dbQueueDomain,
    dbOperationsEvent=None,
    event_status="QueueDomain__mark__cancelled",
    action="de-queued",
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbQueueDomain: (required) The :class:`model.objects.QueueDomain`
    :param dbOperationsEvent:
    :param event_status:
    :param action:
    """
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["queue_domain.id"] = dbQueueDomain.id
    event_payload_dict["action"] = action

    dbQueueDomain.is_active = None
    dbQueueDomain.timestamp_processed = ctx.timestamp
    ctx.dbSession.flush(objects=[dbQueueDomain])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            event_status
        ),
        dbQueueDomain=dbQueueDomain,
    )
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_domains__add(ctx, domain_names):
    """
    Adds domains to the queue if needed

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain names:
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("QueueDomain__add"),
        event_payload_dict,
    )

    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for domain_name in domain_names:
        _dbDomain = lib.db.get.get__Domain__by_name(
            ctx, domain_name, preload=False, active_only=False
        )
        _result = None
        _logger_args = {"event_status_id": None}
        if _dbDomain:
            if not _dbDomain.is_active:
                # set this active
                _dbDomain.is_active = True

                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "QueueDomain__add__already_exists_activate"
                )
                _logger_args["dbDomain"] = _dbDomain
                _result = "exists"

            else:
                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "QueueDomain__add__already_exists"
                )
                _logger_args["dbDomain"] = _dbDomain
                _result = "exists"

        elif not _dbDomain:
            _dbQueueDomain = lib.db.get.get__QueueDomain__by_name__single(
                ctx, domain_name
            )
            _create_new = True
            if _dbQueueDomain:
                if _dbQueueDomain.is_active:
                    _create_new = False
                    _logger_args[
                        "event_status_id"
                    ] = model_utils.OperationsObjectEventStatus.from_string(
                        "QueueDomain__add__already_queued"
                    )
                    _logger_args["dbQueueDomain"] = _dbQueueDomain
                    _result = "already_queued"
                else:
                    # the domain exists, but was removed. so add a new one.
                    pass

            if _create_new:
                _dbQueueDomain = model_objects.QueueDomain()
                _dbQueueDomain.domain_name = domain_name
                _dbQueueDomain.is_active = True
                _dbQueueDomain.timestamp_entered = _timestamp
                _dbQueueDomain.operations_event_id__created = dbOperationsEvent.id
                ctx.dbSession.add(_dbQueueDomain)
                ctx.dbSession.flush(objects=[_dbQueueDomain])

                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "QueueDomain__add__success"
                )
                _logger_args["dbQueueDomain"] = _dbQueueDomain
                _result = "queued"

        # note result
        results[domain_name] = _result

        # log request
        _log_object_event(ctx, dbOperationsEvent=dbOperationsEvent, **_logger_args)

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _get_default_AccountKey(ctx):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    # raises an error if we fail
    dbAcmeAccountKey_GlobalDefault = lib.db.get.get__AcmeAccountKey__GlobalDefault(
        ctx, active_only=True
    )
    if not dbAcmeAccountKey_GlobalDefault:
        raise ValueError("Could not load a default AccountKey.")
    return dbAcmeAccountKey_GlobalDefault


def _get_default_PrivateKey(ctx):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    # raises an error if we fail
    # which private-key should we use?

    if not ctx.request:
        # ToDo: refactor `ctx.request.registry.settings`
        raise ValueError("must be invoked within Pyramid")

    use_weekly_key = ctx.request.registry.settings["queue_domains_use_weekly_key"]
    if use_weekly_key:
        dbPrivateKey = lib.db.get.get__PrivateKey__current_week(ctx)
        if not dbPrivateKey:
            dbPrivateKey = lib.db.create.create__PrivateKey(
                ctx, bits=4096, is_autogenerated=True
            )
    else:
        dbPrivateKey = lib.db.get.get__PrivateKey__GlobalDefault(ctx, active_only=True)
    if not dbPrivateKey:
        raise errors.DisplayableError("Could not load a default PrivateKey")
    return dbPrivateKey


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_domains__process(
    ctx, dbAcmeAccountKey=None, dbPrivateKey=None, max_domains_per_certificate=50
):
    """
    This endpoint should pull `1-100[configurable]` domains from the queue, and create a certificate for them

    * if there are more than 100, should we process them, or return that info in json?

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccountKey:
    :param dbPrivateKey:
    """
    if not ctx.request:
        # ToDo: refactor `ctx.request.registry.settings`
        raise ValueError("must be invoked within Pyramid")

    if not all((dbAcmeAccountKey, dbPrivateKey)):
        raise ValueError("must be invoked with dbAcmeAccountKey, dbPrivateKey")

    try:
        min_domains = ctx.request.registry.settings["queue_domains_min_per_cert"]
        _max_max_domains = ctx.request.registry.settings["queue_domains_max_per_cert"]
        max_domains_per_certificate = (
            _max_max_domains
            if max_domains_per_certificate > _max_max_domains
            else max_domains_per_certificate
        )

        items_paged = lib.db.get.get__QueueDomain__paginated(
            ctx, unprocessed_only=True, limit=max_domains_per_certificate, offset=0
        )
        if len(items_paged) < min_domains:
            raise errors.DisplayableError(
                "Not enough domains to issue. Only found `%s`, need `%s`."
                % (len(items_paged), min_domains)
            )

        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict["batch_size"] = len(items_paged)
        event_payload_dict["status"] = "attempt"
        event_payload_dict["queue_domain_ids"] = ",".join(
            [str(d.id) for d in items_paged]
        )
        dbOperationsEvent = log__OperationsEvent(
            ctx,
            model_utils.OperationsEventType.from_string("QueueDomain__process"),
            event_payload_dict,
        )

        _timestamp = ctx.timestamp
        for qDomain in items_paged:
            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsEventType.from_string(
                    "QueueDomain__process"
                ),
                dbQueueDomain=qDomain,
            )

        # commit this so we have the attempt recorded.
        ctx.pyramid_transaction_commit()

        # exit out
        if not items_paged:
            raise errors.DisplayableError("No items in queue")

        # generate domains
        domainObjects = []
        for qDomain in items_paged:
            (
                domainObject,
                _is_created,
            ) = lib.db.getcreate.getcreate__Domain__by_domainName(
                ctx, qDomain.domain_name, is_from_queue_domain=True
            )
            domainObjects.append(domainObject)
            qDomain.domain_id = domainObject.id
            qDomain.is_active = False
            ctx.dbSession.flush(objects=[qDomain])

        # create a dbUniqueFQDNSet for this.
        # TODO - should we delete this if we fail? or keep for the CSR record
        #      - rationale is that on another pass, we would have a different fqdn set
        (
            dbUniqueFQDNSet,
            _is_created,
        ) = lib.db.getcreate.getcreate__UniqueFQDNSet__by_domainObjects(
            ctx, domainObjects
        )

        # update the event
        event_payload_dict["unique_fqdn_set_id"] = dbUniqueFQDNSet.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        # do commit, just because we may have created a private key
        ctx.pyramid_transaction_commit()

        dbServerCertificate = None
        try:
            domain_names = [d.domain_name for d in domainObjects]

            # processing_strategy: AcmeOrder_ProcessingStrategy('create_order', 'process_single', 'process_multi')
            (
                dbAcmeOrder,
                result,
            ) = lib.db.actions_acme.do__AcmeV2_AcmeOrder__automated(
                ctx,
                acme_order_type_id=model_utils.AcmeOrderType.QUEUE_DOMAINS,
                domain_names=domain_names,
                processing_strategy="create_order",
                dbAcmeAccountKey=dbAcmeAccountKey,
                dbPrivateKey=dbPrivateKey,
            )
            for qdomain in items_paged:
                # this may have committed
                qdomain.timestamp_processed = _timestamp
                ctx.dbSession.flush(objects=[qdomain])

            event_payload_dict["status"] = "success"
            event_payload_dict["acme_order.id"] = dbAcmeOrder.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

        except (errors.AcmeOrderFatal, errors.DomainVerificationError) as exc:
            if isinstance(exc, errors.AcmeOrderFatal):
                event_payload_dict["status"] = "error - AcmeOrderFatal"
            else:
                event_payload_dict["status"] = "error - DomainVerificationError"
            event_payload_dict["error"] = str(exc)
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _timestamp = ctx.timestamp
            for qd in items_paged:
                _log_object_event(
                    ctx,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status_id=model_utils.OperationsEventType.from_string(
                        "QueueDomain__process__fail"
                    ),
                    dbQueueDomain=qd,
                )
            raise

        _timestamp = ctx.timestamp
        for qd in items_paged:
            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsEventType.from_string(
                    "QueueDomain__process__success"
                ),
                dbQueueDomain=qd,
            )

        return True

    except Exception as exc:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_certificates__via_fqdns(
    ctx, dbAcmeAccountKey=None, dbPrivateKey=None, unique_fqdn_set_ids=None,
):
    """
    Inserts a new :class:`model.objects.QueueCertificate` for each unique_fqdn_set_id
    
    invoked when a :class:`model.objects.PrivateKey` is marked as compromised.
    
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param unique_fqdn_set_ids: only insert records for these items
    """
    try:
        renewals = []
        event_type = model_utils.OperationsEventType.from_string(
            "QueueCertificate__batch"
        )
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(ctx, event_type, event_payload_dict)
        unique_fqdn_set_ids__bad = []
        for fqdns_id in unique_fqdn_set_ids:
            dbUniqueFQDNSet = lib.db.get.get__UniqueFQDNSet__by_id(ctx, fqdns_id)
            if not dbUniqueFQDNSet:
                unique_fqdn_set_ids__bad.append(fqdns_id)
                continue
            dbQueueCertificate = lib.db.create.create__QueueCertificate(
                ctx,
                dbAcmeAccountKey=None,
                dbPrivateKey=None,
                dbUniqueFQDNSet=dbUniqueFQDNSet,
            )
            renewals.append(dbQueueCertificate)
        event_payload_dict["unique_fqdn_set-queued.ids"] = [
            str(sid) for sid in unique_fqdn_set_ids
        ]
        event_payload_dict["unique_fqdn_set-bad.ids"] = unique_fqdn_set_ids__bad
        event_payload_dict["queue_certificates.ids"] = [str(c.id) for c in renewals]
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        return True

    except Exception as exc:
        raise


def queue_certificates__update(ctx):
    """
    Inspects the database for expiring :class:`model.objects.AcmeOrders`
    inserts a new :class:`model.objects.QueueCertificate` for each one.
    
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param unique_fqdn_set_ids: only insert records for these items

    Invoked by:
        admin:api:queue_certificates:update
        admin:api:queue_certificates:update|json
    """
    renewals = []
    results = []
    try:
        #
        event_type = model_utils.OperationsEventType.from_string(
            "QueueCertificate__update"
        )
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(ctx, event_type, event_payload_dict)

        _expiring_days = 28
        _until = ctx.timestamp + datetime.timedelta(days=_expiring_days)
        _subquery_already_queued = (
            ctx.dbSession.query(model_objects.QueueCertificate.acme_order_id__source)
            .filter(
                model_objects.QueueCertificate.acme_order_id__source.op("IS NOT")(None),
                model_objects.QueueCertificate.timestamp_processed.op("IS")(None),
                model_objects.QueueCertificate.process_result.op("IS NOT")(
                    None
                ),  # True/False were attempted
            )
            .subquery()
        )
        _core_query = (
            ctx.dbSession.query(model_objects.AcmeOrder)
            .join(
                model_objects.ServerCertificate,
                model_objects.AcmeOrder.server_certificate_id
                == model_objects.ServerCertificate.id,
            )
            .filter(
                model_objects.AcmeOrder.id.notin_(_subquery_already_queued),
                model_objects.AcmeOrder.server_certificate_id.op("IS NOT")(None),
                model_objects.AcmeOrder.is_auto_renew.op("IS")(True),
                model_objects.AcmeOrder.is_renewed.op("IS NOT")(True),
                model_objects.ServerCertificate.timestamp_expires <= _until,
            )
        )
        results = _core_query.all()
        for dbAcmeOrder in results:
            # this will call `_log_object_event` as needed
            dbQueueCertificate = lib.db.create.create__QueueCertificate(
                ctx,
                dbAcmeAccountKey=dbAcmeOrder.acme_account_key,
                dbPrivateKey=dbAcmeOrder.private_key,
                dbAcmeOrder=dbAcmeOrder,
            )
            renewals.append(dbQueueCertificate)
        event_payload_dict["server_certificate-queued.ids"] = ",".join(
            [str(c.id) for c in results]
        )

        event_payload_dict["queue_certificates.ids"] = ",".join(
            [str(c.id) for c in renewals]
        )
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        return True

    except Exception as exc:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_certificates__process(ctx):
    """
    process the queue
    in order to best deal with transactions, we do 1 queue item at a time and redirect to process more

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    rval = {
        "count_total": None,
        "count_success": 0,
        "count_fail": 0,
        "count_remaining": 0,
        "failures": {},
    }
    event_type = model_utils.OperationsEventType.from_string(
        "QueueCertificate__process"
    )
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(ctx, event_type, event_payload_dict)
    items_count = lib.db.get.get__QueueCertificate__count(ctx, unprocessed_only=True)
    rval["count_total"] = items_count
    rval["count_remaining"] = items_count
    if items_count:
        items_paged = lib.db.get.get__QueueCertificate__paginated(
            ctx, unprocessed_only=True, limit=1, offset=0, eagerload_renewal=True
        )

        dbAcmeAccountKey_GlobalDefault = None
        _need_default_AccountKey = False
        for dbQueueCertificate in items_paged:
            if (
                (not dbQueueCertificate.server_certificate)
                or (not dbQueueCertificate.server_certificate.acme_account_key_id)
                or (
                    not dbQueueCertificate.server_certificate.acme_account_key.is_active
                )
            ):
                _need_default_AccountKey = True
                break

        dbPrivateKey_GlobalDefault = None
        _need_default_PrivateKey = False
        for dbQueueCertificate in items_paged:
            if (
                (not dbQueueCertificate.server_certificate)
                or (not dbQueueCertificate.server_certificate.private_key_id)
                or (not dbQueueCertificate.server_certificate.private_key.is_active)
            ):
                _need_default_PrivateKey = True
                break

        if _need_default_AccountKey:
            # raises an error if we fail
            dbAcmeAccountKey_GlobalDefault = _get_default_AccountKey(ctx)

        if _need_default_PrivateKey:
            # raises an error if we fail
            dbPrivateKey_GlobalDefault = _get_default_PrivateKey(ctx)

        for dbQueueCertificate in items_paged:
            if dbQueueCertificate not in ctx.dbSession:
                dbQueueCertificate = ctx.dbSession.merge(dbQueueCertificate)

            if dbAcmeAccountKey_GlobalDefault:
                if dbAcmeAccountKey_GlobalDefault not in ctx.dbSession:
                    dbAcmeAccountKey_GlobalDefault = ctx.dbSession.merge(
                        dbAcmeAccountKey_GlobalDefault
                    )
            if ctx.dbOperationsEvent not in ctx.dbSession:
                ctx.dbOperationsEvent = ctx.dbSession.merge(ctx.dbOperationsEvent)
            if dbOperationsEvent not in ctx.dbSession:
                dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)

            dbServerCertificate = None
            _dbAcmeAccountKey = (
                dbQueueCertificate.renewal_AccountKey or dbAcmeAccountKey_GlobalDefault
            )
            _dbPrivateKey = (
                dbQueueCertificate.renewal_PrivateKey or dbPrivateKey_GlobalDefault
            )
            try:
                timestamp_attempt = datetime.datetime.utcnow()
                raise ValueError("this changed a lot")
                (
                    dbAcmeOrder,
                    result,
                ) = lib.db.actions_acme.do__AcmeV2_AcmeOrder__automated(
                    ctx,
                    acme_order_type_id=model_utils.AcmeOrderType.QUEUE_RENEWAL,
                    domain_names=dbQueueCertificate.domains_as_list,
                    dbAcmeAccountKey=_dbAcmeAccountKey,
                    dbPrivateKey=_dbPrivateKey,
                    dbServerCertificate__renewal_of=dbQueueCertificate.server_certificate,
                    dbQueueCertificate__of=dbQueueCertificate,
                )
                if dbServerCertificate:
                    _log_object_event(
                        ctx,
                        dbOperationsEvent=dbOperationsEvent,
                        event_status_id=model_utils.OperationsEventType.from_string(
                            "QueueCertificate__process__success"
                        ),
                        dbQueueCertificate=dbQueueCertificate,
                    )
                    rval["count_success"] += 1
                    rval["count_remaining"] -= 1
                    dbQueueCertificate.process_result = True
                    dbQueueCertificate.timestamp_process_attempt = timestamp_attempt
                    dbQueueCertificate.server_certificate_id__renewed = (
                        dbServerCertificate.id
                    )
                    ctx.dbSession.flush(objects=[dbQueueCertificate])

                else:
                    raise ValueError("what happened?")

            except Exception as exc:

                # except (errors.AcmeOrderFatal, errors.DomainVerificationError) as exc:

                if dbOperationsEvent not in ctx.dbSession:
                    dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
                if dbQueueCertificate not in ctx.dbSession:
                    dbQueueCertificate = ctx.dbSession.merge(dbQueueCertificate)
                dbQueueCertificate.process_result = False
                dbQueueCertificate.timestamp_process_attempt = timestamp_attempt
                ctx.dbSession.flush(objects=[dbQueueCertificate])

                _log_object_event(
                    ctx,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status_id=model_utils.OperationsEventType.from_string(
                        "QueueCertificate__process__fail"
                    ),
                    dbQueueCertificate=dbQueueCertificate,
                )
                rval["count_fail"] += 1
                if isinstance(exc, errors.DomainVerificationError):
                    rval["failures"][dbQueueCertificate.id] = str(exc)
                elif isinstance(exc, errors.DomainVerificationError):
                    rval["failures"][dbQueueCertificate.id] = str(exc)
                else:
                    raise
        event_payload_dict["rval"] = rval
        if dbOperationsEvent not in ctx.dbSession:
            dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])
    return rval


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "dequeue_QueuedDomain",
    "queue_domains__add",
    "queue_domains__process",
    "queue_certificates__update",
    "queue_certificates__process",
)
