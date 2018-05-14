# logging
import logging
log = logging.getLogger(__name__)


# stdlib
import datetime

# pypi
import transaction

# localapp
from ...models import models
from ... import lib
from .. import errors
from .. import utils

# local
from .logger import log__SslOperationsEvent
from .logger import _log_object_event


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def dequeue_QueuedDomain(ctx, dbQueueDomain, dbOperationsEvent=None, event_status='queue_domain__mark__cancelled', action='de-queued'):
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict['ssl_queue_domain.id'] = dbQueueDomain.id
    event_payload_dict['action'] = action
    dbQueueDomain.is_active = False
    dbQueueDomain.timestamp_processed = ctx.timestamp
    ctx.dbSession.flush(objects=[dbQueueDomain, ])

    _log_object_event(ctx,
                      dbOperationsEvent=dbOperationsEvent,
                      event_status_id=models.SslOperationsObjectEventStatus.from_string(event_status),
                      dbQueueDomain=dbQueueDomain,
                      )
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_domains__add(ctx, domain_names):
    """
    Adds domains to the queue if needed
    2016.06.04 - dbOperationsEvent compliant
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                models.SslOperationsEventType.from_string('queue_domain__add'),
                                                event_payload_dict,
                                                )

    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for domain_name in domain_names:
        _dbDomain = lib.db.get.get__SslDomain__by_name(ctx, domain_name, preload=False, active_only=False)
        _result = None
        _logger_args = {'event_status_id': None, }
        if _dbDomain:
            if not _dbDomain.is_active:
                # set this active
                _dbDomain.is_active = True

                _logger_args['event_status_id'] = models.SslOperationsObjectEventStatus.from_string('queue_domain__add__already_exists_activate')
                _logger_args['dbDomain'] = _dbDomain
                _result = 'exists'

            else:
                _logger_args['event_status_id'] = models.SslOperationsObjectEventStatus.from_string('queue_domain__add__already_exists')
                _logger_args['dbDomain'] = _dbDomain
                _result = 'exists'

        elif not _dbDomain:
            _dbQueueDomain = lib.db.get.get__SslQueueDomain__by_name(ctx, domain_name)
            if _dbQueueDomain:
                _logger_args['event_status_id'] = models.SslOperationsObjectEventStatus.from_string('queue_domain__add__already_queued')
                _logger_args['dbQueueDomain'] = _dbQueueDomain
                _result = 'already_queued'

            else:
                _dbQueueDomain = models.SslQueueDomain()
                _dbQueueDomain.domain_name = domain_name
                _dbQueueDomain.timestamp_entered = _timestamp
                _dbQueueDomain.ssl_operations_event_id__created = dbOperationsEvent.id
                ctx.dbSession.add(_dbQueueDomain)
                ctx.dbSession.flush(objects=[_dbQueueDomain, ])

                _logger_args['event_status_id'] = models.SslOperationsObjectEventStatus.from_string('queue_domain__add__success')
                _logger_args['dbQueueDomain'] = _dbQueueDomain
                _result = 'queued'

        # note result
        results[domain_name] = _result

        # log request
        _log_object_event(ctx,
                          dbOperationsEvent=dbOperationsEvent,
                          **_logger_args
                          )

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_domains__process(
    ctx,
    dbAccountKey=None,
    dbPrivateKey=None,
):
    raise errors.OperationsContextError("Not Finished Yet")
    """
    This endpoint should pull `1-100[configurable]` domains from the queue, and create a certificate for them

    * if there are more than 100, should we process them, or return that info in json?

    """

    try:
        items_paged = lib.db.get.get__SslQueueDomain__paginated(
            ctx,
            show_processed=False,
            limit=100,
            offset=0
        )
        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict['batch_size'] = len(items_paged)
        event_payload_dict['status'] = 'attempt'
        event_payload_dict['queue_domain_ids'] = ','.join([str(d.id) for d in items_paged])
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    models.SslOperationsEventType.from_string('queue_domain__process'),
                                                    event_payload_dict,
                                                    )

        _timestamp = ctx.timestamp
        for qDomain in items_paged:
            _log_object_event(ctx,
                              dbOperationsEvent=dbOperationsEvent,
                              event_status_id=models.SslOperationsEventType.from_string('queue_domain__process'),
                              dbQueueDomain=qDomain,
                              )

        # commit this so we have the attempt recorded.
        transaction.commit()

        # exit out
        if not items_paged:
            raise errors.DisplayableError("No items in queue")

        # cache the timestamp
        timestamp_transaction = datetime.datetime.utcnow()

        # generate domains
        domainObjects = []
        for qDomain in items_paged:
            domainObject, _is_created = lib.db.getcreate.getcreate__SslDomain__by_domainName(
                ctx,
                qDomain.domain_name,
                is_from_queue_domain=True,
            )
            domainObjects.append(domainObject)
            qDomain.ssl_domain_id = domainObject.id
            ctx.dbSession.flush(objects=[qDomain, ])

        # create a dbUniqueFqdnSet for this.
        # TODO - should we delete this if we fail? or keep for the CSR record
        #      - rationale is that on another pass, we would have a different fqdn set
        dbUniqueFqdnSet, is_created = lib.db.getcreate.getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, domainObjects)

        # update the event
        event_payload_dict['ssl_unique_fqdn_set_id'] = dbUniqueFqdnSet.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent, ])
        transaction.commit()

        if dbAccountKey is None:
            dbAccountKey = lib.db.get.get__SslLetsEncryptAccountKey__default(ctx)
            if not dbAccountKey:
                raise ValueError("Could not grab an AccountKey")

        if dbPrivateKey is None:
            dbPrivateKey = lib.db.get.get__SslPrivateKey__current_week(ctx)
            if not dbPrivateKey:
                dbPrivateKey = lib.db.create.create__SslPrivateKey__autogenerated(ctx)
            if not dbPrivateKey:
                raise ValueError("Could not grab a PrivateKey")

        # do commit, just because we may have created a private key
        transaction.commit()

        dbServerCertificate = None
        try:
            domain_names = [d.domain_name for d in domainObjects]
            dbServerCertificate = lib.db.do__CertificateRequest__AcmeAutomated(
                ctx,
                domain_names,
                dbAccountKey=dbAccountKey,
                dbPrivateKey=dbPrivateKey,
            )
            for qdomain in items_paged:
                # this may have committed
                qdomain.timestamp_processed = timestamp_transaction
                ctx.dbSession.flush(objects=[qdomain, ])

            event_payload_dict['status'] = 'success'
            event_payload_dict['certificate.id'] = dbServerCertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent, ])

        except errors.DomainVerificationError as e:
            event_payload_dict['status'] = 'error - DomainVerificationError'
            event_payload_dict['error'] = e.message
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent, ])

            _timestamp = ctx.timestamp
            for qd in items_paged:
                _log_object_event(ctx,
                                  dbOperationsEvent=dbOperationsEvent,
                                  event_status_id=models.SslOperationsEventType.from_string('queue_domain__process__fail'),
                                  dbQueueDomain=qd,
                                  )
            raise

        _timestamp = ctx.timestamp
        for qd in items_paged:
            _log_object_event(ctx,
                              dbOperationsEvent=dbOperationsEvent,
                              event_status_id=models.SslOperationsEventType.from_string('queue_domain__process__success'),
                              dbQueueDomain=qd,
                              )

        return True

    except Exception as exc:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_renewals__update(
    ctx,
    fqdns_ids_only = None,
):
    try:
        if fqdns_ids_only:
            raise NotImplemented()

        event_type = models.SslOperationsEventType.from_string('queue_renewal__update')
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                    event_type,
                                                    event_payload_dict,
                                                    )

        _expiring_days = 28
        _until = ctx.timestamp + datetime.timedelta(days=_expiring_days)

        _subquery_already_queued = ctx.dbSession.query(models.SslQueueRenewal.ssl_server_certificate_id)\
            .filter(models.SslQueueRenewal.timestamp_processed.op('IS')(None),
                    models.SslQueueRenewal.process_result.op('IS NOT')(True),
                    )\
            .subquery()

        _core_query = ctx.dbSession.query(models.SslServerCertificate)\
            .filter(models.SslServerCertificate.is_active.op('IS')(True),
                    models.SslServerCertificate.is_auto_renew.op('IS')(True),
                    models.SslServerCertificate.is_renewed.op('IS NOT')(True),
                    models.SslServerCertificate.timestamp_expires <= _until,
                    models.SslServerCertificate.id.notin_(_subquery_already_queued),
                    )
        results = _core_query.all()

        renewals = []
        for cert in results:
            # this will call `_log_object_event` as needed
            dbQueueRenewal = lib.db.create._create__SslQueueRenewal(ctx, cert, )
            renewals.append(dbQueueRenewal)
        event_payload_dict['ssl_certificate-queued.ids'] = ','.join([str(c.id) for c in results])
        event_payload_dict['sql_queue_renewals.ids'] = ','.join([str(c.id) for c in renewals])
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent, ])

        return True

    except Exception as exc:
        raise


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def queue_renewals__process(ctx):
    rval = {'count_total': None,
            'count_success': 0,
            'count_fail': 0,
            'failures': {},
            }
    event_type = models.SslOperationsEventType.from_string('queue_renewal__process')
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(ctx,
                                                event_type,
                                                event_payload_dict,
                                                )
    items_count = lib.db.get.get__SslQueueRenewal__count(ctx, show_all=False)
    rval['count_total'] = items_count
    if items_count:
        items_paged = lib.db.get.get__SslQueueRenewal__paginated(ctx, show_all=False, limit=10, offset=0, eagerload_renewal=True)

        _need_default_key = False
        for dbQueueRenewal in items_paged:
            if (not dbQueueRenewal.server_certificate.ssl_letsencrypt_account_key_id) or (not dbQueueRenewal.server_certificate.letsencrypt_account_key.is_active):
                _need_default_key = True
                break
        if _need_default_key:
            dbAccountKeyDefault = lib.db.get.get__SslLetsEncryptAccountKey__default(ctx, active_only=True)
            if not dbAccountKeyDefault:
                raise ValueError("Could not load a default AccountKey for renewal")

        for dbQueueRenewal in items_paged:
            if dbQueueRenewal not in ctx.dbSession:
                dbQueueRenewal = ctx.dbSession.merge(dbQueueRenewal)
            if dbAccountKeyDefault:
                if dbAccountKeyDefault not in ctx.dbSession:
                    dbAccountKeyDefault = ctx.dbSession.merge(dbAccountKeyDefault)
            if ctx.dbOperationsEvent not in ctx.dbSession:
                ctx.dbOperationsEvent = ctx.dbSession.merge(ctx.dbOperationsEvent)
            if dbOperationsEvent not in ctx.dbSession:
                dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)

            dbServerCertificate = None
            try:
                dbServerCertificate = lib.db.do__CertificateRequest__AcmeAutomated(
                    ctx,
                    dbQueueRenewal.server_certificate.domains_as_list,
                    dbAccountKey=dbQueueRenewal.server_certificate.letsencrypt_account_key or dbAccountKeyDefault,
                    dbPrivateKey=dbQueueRenewal.server_certificate.private_key,
                    dbServerCertificate__renewal_of=dbQueueRenewal.server_certificate,
                    dbQueueRenewal__of=dbQueueRenewal
                )
                if dbServerCertificate:
                    _log_object_event(ctx,
                                      dbOperationsEvent=dbOperationsEvent,
                                      event_status_id=models.SslOperationsEventType.from_string('queue_renewal__process__success'),
                                      dbQueueRenewal=dbQueueRenewal,
                                      )
                    rval['count_success'] += 1
                    dbQueueRenewal.process_result = True
                    ctx.dbSession.flush(objects=[dbQueueRenewal, ])
                else:
                    raise ValueError("what happened?")
            except Exception as e:
                if dbOperationsEvent not in ctx.dbSession:
                    dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
                if dbQueueRenewal not in ctx.dbSession:
                    dbQueueRenewal = ctx.dbSession.merge(dbQueueRenewal)
                dbQueueRenewal.process_result = False
                ctx.dbSession.flush(objects=[dbQueueRenewal, ])

                _log_object_event(ctx,
                                  dbOperationsEvent=dbOperationsEvent,
                                  event_status_id=models.SslOperationsEventType.from_string('queue_renewal__process__fail'),
                                  dbQueueRenewal=dbQueueRenewal,
                                  )
                rval['count_fail'] += 1
                if isinstance(e, errors.DomainVerificationError):
                    rval['failures'][dbQueueRenewal.id] = e.message
                else:
                    raise
        event_payload_dict['rval'] = rval
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent, ])
    return rval


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ('dequeue_QueuedDomain',
           'queue_domains__add',
           'queue_domains__process',
           'queue_renewals__update',
           'queue_renewals__process',
           )
