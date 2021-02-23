# logging
import logging

log = logging.getLogger(__name__)


# stdlib
import datetime
import pdb

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


def queue_domains__add(ctx, domain_names):
    """
    Adds domains to the queue if needed

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_names: a Python `list` of domains names
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("QueueDomain__add"),
        event_payload_dict,
    )

    # this function checks the domain names match a simple regex
    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for domain_name in domain_names:
        # scoping
        _result = None
        _logger_args = {"event_status_id": None}

        # step 1 - is this blocklisted?
        _dbDomainBlocklisted = lib.db.get.get__DomainBlocklisted__by_name(
            ctx, domain_name
        )
        if _dbDomainBlocklisted:
            # no need to update `_logger_args`, just exit out fast
            results[domain_name] = "blocklisted"
            continue

        # step 2 - is this known?
        _dbDomain = lib.db.get.get__Domain__by_name(
            ctx, domain_name, preload=False, active_only=False
        )
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
                _dbQueueDomain.timestamp_created = _timestamp
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


def queue_domains__process(
    ctx,
    dbAcmeAccount=None,
    dbPrivateKey=None,
    max_domains_per_certificate=50,
    processing_strategy=None,
    private_key_cycle__renewal=None,
    private_key_strategy__requested=None,
):
    """
    This endpoint should pull `1-100[configurable]` domains from the queue, and create a certificate for them

    * if there are more than 100, should we process them, or return that info in json?

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param max_domains_per_certificate: (required) int The maximum number of domains to be put on each Certificate.
    :param private_key_strategy__requested: (required)  A value from :class:`model.utils.PrivateKeyStrategy`
    :param private_key_cycle__renewal: (required)  A value from :class:`model.utils.PrivateKeyCycle`
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    """
    if (
        processing_strategy
        in model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_REQUIRE_PYRAMID
    ):
        if not ctx.request:
            raise ValueError("must be invoked within Pyramid")

    if not all((dbAcmeAccount, dbPrivateKey)):
        raise ValueError("must be invoked with dbAcmeAccount, dbPrivateKey")

    min_domains = ctx.request.registry.settings["app_settings"][
        "queue_domains_min_per_cert"
    ]
    _max_max_domains = ctx.request.registry.settings["app_settings"][
        "queue_domains_max_per_cert"
    ]
    if (max_domains_per_certificate < min_domains) or (
        max_domains_per_certificate > _max_max_domains
    ):
        raise ValueError(
            "invalid `max_domains_per_certificate`: %s" % max_domains_per_certificate
        )

    try:
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

        # create a dbUniqueFQDNSet for this
        # Note: we will not fail on deletion, so we can keep the CSR and FQDN set for error reporting
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

        dbCertificateSigned = None
        try:
            domain_names = [d.domain_name for d in domainObjects]

            domains_challenged = model_utils.DomainsChallenged.new_http01(domain_names)

            # processing_strategy: AcmeOrder_ProcessingStrategy('create_order', 'process_single', 'process_multi')
            try:
                dbAcmeOrder = lib.db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    acme_order_type_id=model_utils.AcmeOrderType.QUEUE_DOMAINS,
                    domains_challenged=domains_challenged,
                    private_key_cycle__renewal=private_key_cycle__renewal,
                    private_key_strategy__requested=private_key_strategy__requested,
                    processing_strategy=processing_strategy,
                    dbAcmeAccount=dbAcmeAccount,
                    dbPrivateKey=dbPrivateKey,
                )
            except Exception as exc:
                # unpack a `errors.AcmeOrderCreatedError` to local vars
                if isinstance(exc, errors.AcmeOrderCreatedError):
                    dbAcmeOrder = exc.acme_order
                    exc = exc.original_exception
                raise

            for qdomain in items_paged:
                # this may have committed
                qdomain.timestamp_processed = _timestamp
                ctx.dbSession.flush(objects=[qdomain])

            event_payload_dict["status"] = "success"
            event_payload_dict["acme_order.id"] = dbAcmeOrder.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

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

            ctx.pyramid_transaction_commit()
            return dbAcmeOrder

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

    except Exception as exc:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


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
                model_objects.CertificateSigned,
                model_objects.AcmeOrder.certificate_signed_id
                == model_objects.CertificateSigned.id,
            )
            .filter(
                model_objects.AcmeOrder.id.notin_(_subquery_already_queued),
                model_objects.AcmeOrder.certificate_signed_id.op("IS NOT")(None),
                model_objects.AcmeOrder.is_auto_renew.op("IS")(True),
                model_objects.AcmeOrder.is_renewed.op("IS NOT")(True),
                model_objects.CertificateSigned.timestamp_not_after <= _until,
            )
        )
        results = _core_query.all()
        for dbAcmeOrder in results:
            raise ValueError("TODO: This feature has not been ported yet")
            # this will call `_log_object_event` as needed
            dbQueueCertificate = lib.db.create.create__QueueCertificate(
                ctx,
                dbAcmeAccount=dbAcmeOrder.acme_account,
                dbPrivateKey=dbAcmeOrder.private_key,
                dbAcmeOrder=dbAcmeOrder,
                private_key_cycle_id__renewal=FOO,
                private_key_strategy_id__requested=FOO,
            )
            renewals.append(dbQueueCertificate)
        event_payload_dict["certificate_signed-queued.ids"] = ",".join(
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

        # first step is to see if we need the global AcmeAccountKey
        # and cache it for later.
        # if we do and it is missing...
        # just error on the Queue item, not globally
        dbAcmeAccount_GlobalDefault = None
        _need_default_AcmeAccount = None
        for dbQueueCertificate in items_paged:
            # check the Account and AccountKey are both active
            if not dbQueueCertificate.acme_account.is_usable:
                _need_default_AcmeAccount = True
                break
        if _need_default_AcmeAccount:
            dbAcmeAccount_GlobalDefault = lib.db.get.get__AcmeAccount__GlobalDefault(
                ctx, active_only=True
            )
            # if we don't have an Active Account, create a CoverageAssuranceEvent for the certs that need it

        for dbQueueCertificate in items_paged:
            timestamp_loop = datetime.datetime.utcnow()

            try:
                _dbAcmeAccount = (
                    dbQueueCertificate.acme_account
                    if dbQueueCertificate.acme_account.is_usable
                    else dbAcmeAccount_GlobalDefault
                )
                if not _dbAcmeAccount:
                    raise errors.QueueProcessingError("QueueCertificate_no_account_key")
                _dbPrivateKey = dbQueueCertificate.private_key  # this can auto-heal

            except errors.QueueProcessingError as exc:
                # create a CoverageAssuranceEvent
                rval["count_fail"] += 1
                dbCoverageAssuranceEvent = lib.db.create.create__CoverageAssuranceEvent(
                    ctx,
                    coverage_assurance_event_type_id=model_utils.CoverageAssuranceEventType.from_string(
                        "QueueCertificate_no_account_key"
                    ),
                    coverage_assurance_event_status_id=model_utils.CoverageAssuranceEventStatus.from_string(
                        "reported"
                    ),
                    dbQueueCertificate=dbQueueCertificate,
                )
                continue
            try:
                dbAcmeOrder = lib.db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    acme_order_type_id=model_utils.AcmeOrderType.QUEUE_CERTIFICATE,
                    processing_strategy="create_order",
                    private_key_cycle__renewal=dbQueueCertificate.private_key_cycle__renewal,
                    private_key_strategy__requested=dbQueueCertificate.private_key_strategy__requested,
                    dbQueueCertificate__of=dbQueueCertificate,
                )
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

            except Exception as exc:
                # unpack a `errors.AcmeOrderCreatedError` to local vars
                if isinstance(exc, errors.AcmeOrderCreatedError):
                    # this is technically a success, at least for now
                    dbAcmeOrder = exc.acme_order
                    exc = exc.original_exception
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
                else:
                    _log_object_event(
                        ctx,
                        dbOperationsEvent=dbOperationsEvent,
                        event_status_id=model_utils.OperationsEventType.from_string(
                            "QueueCertificate__process__fail"
                        ),
                        dbQueueCertificate=dbQueueCertificate,
                    )
                    rval["count_fail"] += 1
                raise

        event_payload_dict["rval"] = rval
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])
    return rval


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "queue_domains__add",
    "queue_domains__process",
    "queue_certificates__update",
    "queue_certificates__process",
)
