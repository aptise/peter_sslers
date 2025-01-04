# stdlib
import datetime
import logging
from typing import Dict
from typing import Iterable
from typing import Optional
from typing import TYPE_CHECKING

# pypi
import cert_utils

# local
from .logger import _log_object_event
from .logger import log__OperationsEvent
from .. import errors
from .. import utils
from ... import lib
from ...lib.db import get as _get  # noqa: F401
from ...model import objects as model_objects
from ...model import utils as model_utils

if TYPE_CHECKING:
    from ...model.objects import AcmeOrder
    from ...model.objects import AcmeAccount
    from ...model.objects import PrivateKey
    from ..utils import ApiContext

# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


def queue_domains__add(
    ctx: "ApiContext",
    domain_names: Iterable[str],
) -> Dict:
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
    domain_names = cert_utils.utils.domains_from_list(domain_names)
    results: Dict = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for domain_name in domain_names:
        # scoping
        _result = None
        _logger_args: Dict = {"event_status_id": None}

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

                _logger_args["event_status_id"] = (
                    model_utils.OperationsObjectEventStatus.from_string(
                        "QueueDomain__add__already_exists_activate"
                    )
                )
                _logger_args["dbDomain"] = _dbDomain
                _result = "exists"

            else:
                _logger_args["event_status_id"] = (
                    model_utils.OperationsObjectEventStatus.from_string(
                        "QueueDomain__add__already_exists"
                    )
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
                    _logger_args["event_status_id"] = (
                        model_utils.OperationsObjectEventStatus.from_string(
                            "QueueDomain__add__already_queued"
                        )
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

                _logger_args["event_status_id"] = (
                    model_utils.OperationsObjectEventStatus.from_string(
                        "QueueDomain__add__success"
                    )
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
    ctx: "ApiContext",
    dbAcmeAccount: Optional["AcmeAccount"] = None,
    dbPrivateKey: Optional["PrivateKey"] = None,
    max_domains_per_certificate: int = 50,
    processing_strategy: Optional[str] = None,
    private_key_cycle: Optional[str] = None,
    private_key_strategy__requested: Optional[str] = None,
) -> "AcmeOrder":
    """
    This endpoint should pull `1-100[configurable]` domains from the queue, and create a certificate for them

    * if there are more than 100, should we process them, or return that info in json?

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param max_domains_per_certificate: (required) int The maximum number of domains to be put on each Certificate.
    :param private_key_strategy__requested: (required)  A value from :class:`model.utils.PrivateKeyStrategy`
    :param private_key_cycle: (required)  A value from :class:`model.utils.PrivateKeyCycle`
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

    assert ctx.request
    assert ctx.request.registry
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
                ctx,
                qDomain.domain_name,
                discovery_type="via queue_domains__process",
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

        try:
            domain_names = [d.domain_name for d in domainObjects]

            domains_challenged = model_utils.DomainsChallenged.new_http01(domain_names)

            # processing_strategy: AcmeOrder_ProcessingStrategy('create_order', 'process_single', 'process_multi')
            try:
                dbAcmeOrder = lib.db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    acme_order_type_id=model_utils.AcmeOrderType.QUEUE_DOMAINS,
                    domains_challenged=domains_challenged,
                    private_key_cycle=private_key_cycle,
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

    except Exception as exc:  # noqa: F841
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "queue_domains__add",
    "queue_domains__process",
)
