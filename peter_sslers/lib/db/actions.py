# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime
import pdb

# pypi
from dateutil import parser as dateutil_parser
import sqlalchemy
import transaction

# localapp
from ... import lib  # here for `lib.db`
from ...model import utils as model_utils
from ...model import objects as model_objects
from .. import acme_v2
from .. import cert_utils
from .. import letsencrypt_info
from .. import events
from .. import errors
from .. import utils
from .. import utils_certbot as utils_certbot
from . import actions_acme
from . import update

# local
from .logger import AcmeLogger
from .logger import log__OperationsEvent
from .logger import _log_object_event


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def ca_certificate_probe(ctx):
    """
    Probes the LetsEncrypt Certificate Authority for new certificates

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """

    # create a bookkeeping object
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("CaCertificate__probe")
    )

    certs = letsencrypt_info.probe_letsencrypt_certificates()
    certs_discovered = []
    certs_modified = []
    for c in certs:
        _is_created = False
        dbCACertificate = lib.db.get.get__CACertificate__by_pem_text(ctx, c["cert_pem"])
        if not dbCACertificate:
            (
                dbCACertificate,
                _is_created,
            ) = lib.db.getcreate.getcreate__CACertificate__by_pem_text(
                ctx, c["cert_pem"], ca_chain_name=c["name"]
            )
            if _is_created:
                certs_discovered.append(dbCACertificate)
        if "is_ca_certificate" in c:
            if dbCACertificate.is_ca_certificate != c["is_ca_certificate"]:
                dbCACertificate.is_ca_certificate = c["is_ca_certificate"]
                if dbCACertificate not in certs_discovered:
                    certs_modified.append(dbCACertificate)
        else:
            attrs = (
                "le_authority_name",
                "is_authority_certificate",
                "is_cross_signed_authority_certificate",
            )
            for _k in attrs:
                if getattr(dbCACertificate, _k) is None:
                    setattr(dbCACertificate, _k, c[_k])
                    if dbCACertificate not in certs_discovered:
                        certs_modified.append(dbCACertificate)

    # bookkeeping update
    event_payload_dict["is_certificates_discovered"] = (
        True if certs_discovered else False
    )
    event_payload_dict["is_certificates_updated"] = True if certs_modified else False
    event_payload_dict["ids_discovered"] = [c.id for c in certs_discovered]
    event_payload_dict["ids_modified"] = [c.id for c in certs_modified]

    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return dbOperationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_expired(ctx):
    """
    deactivates expired certificates automatically

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    # create an event first
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["count_deactivated"] = 0
    operationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "ServerCertificate__deactivate_expired"
        ),
        event_payload_dict,
    )

    # update the recents, this will automatically create a subevent
    subevent = operations_update_recents(ctx)

    # okay, go!

    # deactivate expired certificates
    expired_certs = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(
            model_objects.ServerCertificate.is_active.is_(True),
            model_objects.ServerCertificate.timestamp_expires < ctx.timestamp,
        )
        .all()
    )
    for c in expired_certs:
        c.is_active = False
        ctx.dbSession.flush(objects=[c])
        events.Certificate_expired(ctx, c)

    # update the event
    if len(expired_certs):
        event_payload_dict["count_deactivated"] = len(expired_certs)
        event_payload_dict["server_certificate.ids"] = [c.id for c in expired_certs]
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_duplicates(ctx, ran_operations_update_recents=None):
    """
    this is kind of weird.
    because we have multiple domains, it is hard to figure out which certs we should use
    the simplest approach is this:

    1. cache the most recent certs via `operations_update_recents`
    2. find domains that have multiple active certs
    3. don't turn off any certs that are a latest_single or latest_multi

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param ran_operations_update_recents: (optional) Default = `None`
    """
    raise ValueError("Don't run this. It's not needed anymore")
    raise errors.InvalidRequest("Not Compliant")

    if ran_operations_update_recents is not True:
        raise ValueError("MUST run `operations_update_recents` first")

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["count_deactivated"] = 0
    operationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("deactivate_duplicate"),
        event_payload_dict,
    )

    _q_ids__latest_single = (
        ctx.dbSession.query(model_objects.Domain.server_certificate_id__latest_single)
        .distinct()
        .filter(
            model_objects.Domain.server_certificate_id__latest_single != None  # noqa
        )
        .subquery()
    )
    _q_ids__latest_multi = (
        ctx.dbSession.query(model_objects.Domain.server_certificate_id__latest_multi)
        .distinct()
        .filter(
            model_objects.Domain.server_certificate_id__latest_single != None  # noqa
        )
        .subquery()
    )

    # now grab the domains with many certs...
    q_inner = (
        ctx.dbSession.query(
            model_objects.UniqueFQDNSet2Domain.domain_id,
            sqlalchemy.func.count(model_objects.UniqueFQDNSet2Domain.domain_id).label(
                "counted"
            ),
        )
        .join(
            model_objects.ServerCertificate,
            model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id
            == model_objects.ServerCertificate.unique_fqdn_set_id,
        )
        .filter(model_objects.ServerCertificate.is_active.is_(True))
        .group_by(model_objects.UniqueFQDNSet2Domain.domain_id)
    )
    q_inner = q_inner.subquery()
    q_domains = ctx.dbSession.query(q_inner).filter(q_inner.c.counted >= 2)
    result = q_domains.all()
    domain_ids_with_multiple_active_certs = [i.domain_id for i in result]

    if False:
        _turned_off = []
        for _domain_id in domain_ids_with_multiple_active_certs:
            domain_certs = (
                ctx.dbSession.query(model_objects.ServerCertificate)
                .join(
                    model_objects.UniqueFQDNSet2Domain,
                    model_objects.ServerCertificate.unique_fqdn_set_id
                    == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
                )
                .filter(
                    model_objects.ServerCertificate.is_active.is_(True),
                    model_objects.UniqueFQDNSet2Domain.domain_id == _domain_id,
                    model_objects.ServerCertificate.id.notin_(_q_ids__latest_single),
                    model_objects.ServerCertificate.id.notin_(_q_ids__latest_multi),
                )
                .order_by(model_objects.ServerCertificate.timestamp_expires.desc())
                .all()
            )
            if len(domain_certs) > 1:
                for cert in domain_certs[1:]:
                    cert.is_active = False
                    _turned_off.append(cert)
                    events.Certificate_unactivated(ctx, cert)

    # update the event
    if len(_turned_off):
        event_payload_dict["count_deactivated"] = len(_turned_off)
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_update_recents(ctx):
    """
    updates all the objects to their most-recent relations

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    # first the single
    # _t_domain = model_objects.Domain.__table__.alias('domain')

    _q_sub = (
        ctx.dbSession.query(model_objects.ServerCertificate.id)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.ServerCertificate.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.ServerCertificate.is_active.is_(True),
            model_objects.ServerCertificate.is_single_domain_cert.is_(True),
            model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
        )
        .order_by(model_objects.ServerCertificate.timestamp_expires.desc())
        .limit(1)
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )

    ctx.dbSession.execute(
        model_objects.Domain.__table__.update().values(
            server_certificate_id__latest_single=_q_sub
        )
    )

    # then the multiple
    # _t_domain = model_objects.Domain.__table__.alias('domain')
    _q_sub = (
        ctx.dbSession.query(model_objects.ServerCertificate.id)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.ServerCertificate.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.ServerCertificate.is_active.is_(True),
            model_objects.ServerCertificate.is_single_domain_cert.is_(False),
            model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
        )
        .order_by(model_objects.ServerCertificate.timestamp_expires.desc())
        .limit(1)
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.Domain.__table__.update().values(
            server_certificate_id__latest_multi=_q_sub
        )
    )

    # update the count of active certs
    ServerCertificate1 = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    ServerCertificate2 = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    _q_sub = (
        ctx.dbSession.query(sqlalchemy.func.count(model_objects.Domain.id))
        .outerjoin(
            ServerCertificate1,
            model_objects.Domain.server_certificate_id__latest_single
            == ServerCertificate1.id,
        )
        .outerjoin(
            ServerCertificate2,
            model_objects.Domain.server_certificate_id__latest_multi
            == ServerCertificate2.id,
        )
        .filter(
            sqlalchemy.or_(
                model_objects.CACertificate.id
                == ServerCertificate1.ca_certificate_id__upchain,
                model_objects.CACertificate.id
                == ServerCertificate2.ca_certificate_id__upchain,
            )
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.CACertificate.__table__.update().values(
            count_active_certificates=_q_sub
        )
    )

    # update the count of active PrivateKeys
    ServerCertificate1 = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    ServerCertificate2 = sqlalchemy.orm.aliased(model_objects.ServerCertificate)
    _q_sub = (
        ctx.dbSession.query(sqlalchemy.func.count(model_objects.Domain.id))
        .outerjoin(
            ServerCertificate1,
            model_objects.Domain.server_certificate_id__latest_single
            == ServerCertificate1.id,
        )
        .outerjoin(
            ServerCertificate2,
            model_objects.Domain.server_certificate_id__latest_multi
            == ServerCertificate2.id,
        )
        .filter(
            sqlalchemy.or_(
                model_objects.PrivateKey.id == ServerCertificate1.private_key_id,
                model_objects.PrivateKey.id == ServerCertificate2.private_key_id,
            )
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.PrivateKey.__table__.update().values(
            count_active_certificates=_q_sub
        )
    )

    # the following works, but this is currently tracked
    """
        # update the counts on Acme Account Keys
        _q_sub_req = ctx.dbSession.query(sqlalchemy.func.count(model_objects.CertificateRequest.id))\
            .filter(model_objects.CertificateRequest.acme_account_id == model_objects.AcmeAccount.id,
                    )\
            .subquery().as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
        ctx.dbSession.execute(model_objects.AcmeAccount.__table__
                              .update()
                              .values(count_certificate_requests=_q_sub_req,
                                      # count_certificates_issued=_q_sub_iss,
                                      )
                              )
        # update the counts on Private Keys
        _q_sub_req = ctx.dbSession.query(sqlalchemy.func.count(model_objects.CertificateRequest.id))\
            .filter(model_objects.CertificateRequest.private_key_id == model_objects.PrivateKey.id,
                    )\
            .subquery().as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
        _q_sub_iss = ctx.dbSession.query(sqlalchemy.func.count(model_objects.ServerCertificate.id))\
            .filter(model_objects.ServerCertificate.private_key_id == model_objects.PrivateKey.id,
                    )\
            .subquery().as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`

        ctx.dbSession.execute(model_objects.PrivateKey.__table__
                              .update()
                              .values(count_certificate_requests=_q_sub_req,
                                      count_certificates_issued=_q_sub_iss,
                                      )
                              )
    """

    # should we do the timestamps?
    """
    UPDATE acme_account SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM certificate_request
    WHERE certificate_request.acme_account_id = acme_account.id);

    UPDATE acme_account SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM server_certificate
    WHERE server_certificate.acme_account_id = acme_account.id);

    UPDATE private_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM certificate_request
    WHERE certificate_request.private_key_id = private_key.id);

    UPDATE private_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM server_certificate
    WHERE server_certificate.private_key_id = private_key.id);
    """

    # bookkeeping, doing this will mark the session as changed!
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("operations__update_recents"),
    )

    return dbOperationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__enable(ctx, domain_names):
    """
    this is just a proxy around queue_domains__add

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_names: (required) a list of domain names
    """

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("ApiDomains__enable"),
        event_payload_dict,
    )
    results = lib.db.queues.queue_domains__add(ctx, domain_names)
    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__disable(ctx, domain_names):
    """
    disables `domain_names` from the system

    * If the `domain_name` represents a `Domain`, it is marked inactive
    * If the `domain_name` represents a `QueueDomain`, it is removed from the queue

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_names: (required) a list of domain names
    """
    # this function checks the domain names match a simple regex
    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("ApiDomains__disable"),
        event_payload_dict,
    )

    for domain_name in domain_names:
        _dbDomain = lib.db.get.get__Domain__by_name(
            ctx, domain_name, preload=False, active_only=False
        )
        if _dbDomain:
            if _dbDomain.is_active:
                update.update_Domain_disable(
                    ctx,
                    _dbDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="Domain__mark__inactive",
                    action="deactivated",
                )
                results[domain_name] = "deactivated"
            else:
                results[domain_name] = "already deactivated"
        elif not _dbDomain:
            _dbQueueDomain = lib.db.get.get__QueueDomain__by_name__single(
                ctx, domain_name
            )
            if _dbQueueDomain:
                lib.db.update.update_QueuedDomain_dequeue(
                    ctx,
                    _dbQueueDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="QueueDomain__mark__cancelled",
                    action="de-queued",
                )
                results[domain_name] = "de-queued"
            else:
                results[domain_name] = "not active or in queue"

    event_payload_dict["results"] = results
    # dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__certificate_if_needed(
    ctx,
    domain_names,
    processing_strategy=None,
    private_key_cycle__renewal=None,
    private_key_strategy__requested=None,
    dbAcmeAccount=None,
    dbPrivateKey=None,
):
    """
    Adds Domains if needed

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_names: (required) An iteratble list of domain names
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param private_key_cycle__renewal: (required)  A value from :class:`model.utils.PrivateKeyCycle`
    :param private_key_strategy__requested: (required)  A value from :class:`model.utils.PrivateKeyStrategy`
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param dbPrivateKey: (required) A :class:`model.objects.PrivateKey` object used to sign the request.

    results will be a dict:

        {%DOMAIN_NAME%: {'domain': # active, activated, new, FAIL
                         'certificate':  # active, new, FAIL

    logging codes
        2010: 'ApiDomains__certificate_if_needed',
        2011: 'ApiDomains__certificate_if_needed__domain_exists',
        2012: 'ApiDomains__certificate_if_needed__domain_activate',
        2013: 'ApiDomains__certificate_if_needed__domain_new',
        2015: 'ApiDomains__certificate_if_needed__certificate_exists',
        2016: 'ApiDomains__certificate_if_needed__certificate_new_success',
        2017: 'ApiDomains__certificate_if_needed__certificate_new_fail',
    """
    # validate this first!
    acme_order_processing_strategy_id = model_utils.AcmeOrder_ProcessingStrategy.from_string(
        processing_strategy
    )
    private_key_cycle_id__renewal = model_utils.PrivateKeyCycle.from_string(
        private_key_cycle__renewal
    )
    private_key_strategy_id__requested = model_utils.PrivateKeyStrategy.from_string(
        private_key_strategy__requested
    )

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "ApiDomains__certificate_if_needed"
        ),
        event_payload_dict,
    )

    if dbAcmeAccount is None:
        raise errors.DisplayableError("missing AcmeAccount")
    if not dbAcmeAccount.is_active:
        raise errors.DisplayableError("AcmeAccount is not active")

    if not dbPrivateKey:
        raise errors.DisplayableError("missing PrivateKey")

    # this function checks the domain names match a simple regex
    domain_names = utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for _domain_name in domain_names:
        # scoping
        _logger_args = {"event_status_id": None}
        _result = {
            "domain.status": None,
            "domain.id": None,
            "server_certificate.id": None,
            "server_certificate.status": None,
            "acme_order.id": None,
        }
        _dbQueueDomain = None

        # Step 1- is the domain_name blocklisted?
        _dbDomainBlocklisted = lib.db.get.get__DomainBlocklisted__by_name(
            ctx, _domain_name
        )
        if _dbDomainBlocklisted:
            _result["domain.status"] = "blocklisted"
            continue

        # Step 2- is the domain_name a Domain or QueueDomain?
        _dbDomain = lib.db.get.get__Domain__by_name(
            ctx, _domain_name, preload=False, active_only=False
        )
        if _dbDomain:
            _result["domain.id"] = _dbDomain.id

            if not _dbDomain.is_active:
                _result["domain.status"] = "existing.activated"
                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "ApiDomains__certificate_if_needed__domain_activate"
                )
                _logger_args["dbDomain"] = _dbDomain

                # set this active
                lib.db.update.update_Domain_enable(
                    ctx, _dbDomain, dbOperationsEvent=dbOperationsEvent
                )
            else:
                _result["domain.status"] = "existing.active"

                _logger_args[
                    "event_status_id"
                ] = model_utils.OperationsObjectEventStatus.from_string(
                    "ApiDomains__certificate_if_needed__domain_exists"
                )
                _logger_args["dbDomain"] = _dbDomain

        elif not _dbDomain:

            _dbDomain = lib.db.getcreate.getcreate__Domain__by_domainName(
                ctx, _domain_name
            )[
                0
            ]  # (dbDomain, _is_created)
            _result["domain.status"] = "new"
            _result["domain.id"] = _dbDomain.id
            _logger_args[
                "event_status_id"
            ] = model_utils.OperationsObjectEventStatus.from_string(
                "ApiDomains__certificate_if_needed__domain_new"
            )
            _logger_args["dbDomain"] = _dbDomain

        # log Domain event
        _log_object_event(ctx, dbOperationsEvent=dbOperationsEvent, **_logger_args)

        # do commit, just because we may have created a domain; also, logging!
        ctx.pyramid_transaction_commit()

        # go for the certificate
        _logger_args = {"event_status_id": None}
        _dbServerCertificate = lib.db.get.get__ServerCertificate__by_DomainId__latest(
            ctx, _dbDomain.id
        )
        if _dbServerCertificate:
            _result["server_certificate.status"] = "exists"
            _result["server_certificate.id"] = _dbServerCertificate.id
            _logger_args[
                "event_status_id"
            ] = model_utils.OperationsObjectEventStatus.from_string(
                "ApiDomains__certificate_if_needed__certificate_exists"
            )
            _logger_args["dbServerCertificate"] = _dbServerCertificate
        else:
            try:
                dbAcmeOrder = actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_NEW__CIN,
                    domain_names=domain_names,
                    private_key_cycle__renewal=private_key_cycle__renewal,
                    private_key_strategy__requested=private_key_strategy__requested,
                    processing_strategy=processing_strategy,
                    dbAcmeAccount=dbAcmeAccount,
                    dbPrivateKey=dbPrivateKey,
                )

                _logger_args["dbAcmeOrder"] = dbAcmeOrder
                _result["acme_order.id"] = dbAcmeOrder.id
                if dbAcmeOrder.server_certificate_id:
                    _result["server_certificate.status"] = "new"
                    _result["server_certificate.id"] = dbAcmeOrder.server_certificate_id
                    _logger_args[
                        "event_status_id"
                    ] = model_utils.OperationsObjectEventStatus.from_string(
                        "ApiDomains__certificate_if_needed__certificate_new_success"
                    )
                    _logger_args["dbServerCertificate"] = dbAcmeOrder.server_certificate
                else:
                    _result["error"] = "AcmeOrder did not generate a ServerCertificate"
                    _result["server_certificate.status"] = "fail"
                    _logger_args[
                        "event_status_id"
                    ] = model_utils.OperationsObjectEventStatus.from_string(
                        "ApiDomains__certificate_if_needed__certificate_new_fail"
                    )

            except Exception as exc:

                # unpack a `errors.AcmeOrderCreatedError` to local vars
                if isinstance(exc, errors.AcmeOrderCreatedError):
                    dbAcmeOrder = exc.acme_order
                    exc = exc.original_exception

                    _logger_args["dbAcmeOrder"] = dbAcmeOrder
                    _result["acme_order.id"] = dbAcmeOrder.id

                if isinstance(exc, errors.AcmeError):
                    _result["error"] = "Could not process AcmeOrder, %s" % str(exc)
                    _result["server_certificate.status"] = "fail"
                    _logger_args[
                        "event_status_id"
                    ] = model_utils.OperationsObjectEventStatus.from_string(
                        "ApiDomains__certificate_if_needed__certificate_new_fail"
                    )
                else:
                    raise

        # log domain event
        _log_object_event(ctx, dbOperationsEvent=dbOperationsEvent, **_logger_args)

        # do commit, just because THE LOGGGING
        ctx.pyramid_transaction_commit()

        # remove from queue if it exists
        if _result["server_certificate.status"] in ("new", "exists"):
            _dbQueueDomain = lib.db.get.get__QueueDomain__by_name__single(
                ctx, _domain_name
            )
            if _dbQueueDomain:
                lib.db.update.update_QueuedDomain_dequeue(
                    ctx,
                    _dbQueueDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="QueueDomain__mark__already_processed",
                    action="already_processed",
                )

        # do commit, just because THE LOGGGING
        ctx.pyramid_transaction_commit()

        # note result
        results[_domain_name] = _result

    event_payload_dict["results"] = results
    # dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def upload__CACertificateBundle__by_pem_text(ctx, bundle_data):
    """
    Uploads a bundle of CACertificates

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param bundle_data: (required) a compliant payload
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("CaCertificate__upload_bundle"),
        event_payload_dict,
    )
    results = {}
    for cert_pem in bundle_data.keys():
        if cert_pem[-4:] != "_pem":
            raise ValueError("key does not end in `_pem`")
        cert_base = cert_pem[:-4]
        cert_pem_text = bundle_data[cert_pem]
        cert_name = None
        le_authority_name = None
        is_authority_certificate = None
        is_cross_signed_authority_certificate = None
        for c in letsencrypt_info.CA_CERTS_DATA:
            if cert_base == c["formfield_base"]:
                cert_name = c["name"]
                if "le_authority_name" in c:
                    le_authority_name = c["le_authority_name"]
                if "is_authority_certificate" in c:
                    is_authority_certificate = c["is_authority_certificate"]
                if "is_cross_signed_authority_certificate" in c:
                    is_cross_signed_authority_certificate = c[
                        "is_cross_signed_authority_certificate"
                    ]
                break

        (
            dbCACertificate,
            is_created,
        ) = lib.db.getcreate.getcreate__CACertificate__by_pem_text(
            ctx,
            cert_pem_text,
            ca_chain_name=cert_name,
            le_authority_name=None,
            is_authority_certificate=None,
            is_cross_signed_authority_certificate=None,
        )
        if not is_created:
            if dbCACertificate.name in ("unknown", "manual upload") and cert_name:
                dbCACertificate.name = cert_name
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.le_authority_name = le_authority_name
            if dbCACertificate.is_authority_certificate is None:
                dbCACertificate.is_authority_certificate = is_authority_certificate
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.is_cross_signed_authority_certificate = (
                    is_cross_signed_authority_certificate
                )

        results[cert_pem] = (dbCACertificate, is_created)

    ids_created = [i[0].id for i in results.values() if i[1]]
    ids_updated = [i[0].id for i in results.values() if not i[1]]
    event_payload_dict["ids_created"] = ids_created
    event_payload_dict["ids_updated"] = ids_updated
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])
    return results
