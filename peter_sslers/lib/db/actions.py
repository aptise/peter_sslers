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
from zope.sqlalchemy import mark_changed

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
from . import actions_acme
from . import update

# local
from .logger import AcmeLogger
from .logger import log__OperationsEvent
from .logger import _log_object_event


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def certificate_ca_download(ctx):
    """
    Downloads from the LetsEncrypt Certificate Authority

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """

    # create a bookkeeping object
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("CaCertificate__letsencrypt_sync"),
    )

    certs = letsencrypt_info.download_letsencrypt_certificates()
    certs_discovered = []
    certs_modified = []

    for cert_id, cert_data in certs.items():
        _is_created = False
        dbCertificateCA = lib.db.get.get__CertificateCA__by_pem_text(
            ctx, cert_data["cert_pem"]
        )
        if not dbCertificateCA:
            (
                dbCertificateCA,
                _is_created,
            ) = lib.db.getcreate.getcreate__CertificateCA__by_pem_text(
                ctx, cert_data["cert_pem"], ca_chain_name=cert_data["display_name"]
            )
            if _is_created:
                certs_discovered.append(dbCertificateCA)
        if "is_trusted_root" in cert_data:
            if dbCertificateCA.is_trusted_root != cert_data["is_trusted_root"]:
                dbCertificateCA.is_trusted_root = cert_data["is_trusted_root"]
                if dbCertificateCA not in certs_discovered:
                    certs_modified.append(dbCertificateCA)
        else:
            attrs = ("display_name",)
            for _k in attrs:
                if getattr(dbCertificateCA, _k) is None:
                    setattr(dbCertificateCA, _k, cert_data[_k])
                    if dbCertificateCA not in certs_discovered:
                        certs_modified.append(dbCertificateCA)

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
            "CertificateSigned__deactivate_expired"
        ),
        event_payload_dict,
    )

    # update the recents, this will automatically create a subevent
    subevent = operations_update_recents__global(ctx)

    # okay, go!

    # deactivate expired certificates
    expired_certs = (
        ctx.dbSession.query(model_objects.CertificateSigned)
        .filter(
            model_objects.CertificateSigned.is_active.is_(True),
            model_objects.CertificateSigned.timestamp_not_after < ctx.timestamp,
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
        event_payload_dict["certificate_signed.ids"] = [c.id for c in expired_certs]
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_duplicates(ctx, ran_operations_update_recents__global=None):
    """
    this is kind of weird.
    because we have multiple domains, it is hard to figure out which certs we should use
    the simplest approach is this:

    1. cache the most recent certs via `operations_update_recents__global`
    2. find domains that have multiple active certs
    3. don't turn off any certs that are a latest_single or latest_multi

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param ran_operations_update_recents__global: (optional) Default = `None`
    """
    raise ValueError("Don't run this. It's not needed anymore")
    raise errors.InvalidRequest("Not Compliant")

    if ran_operations_update_recents__global is not True:
        raise ValueError("MUST run `operations_update_recents__global` first")

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["count_deactivated"] = 0
    operationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("deactivate_duplicate"),
        event_payload_dict,
    )

    _q_ids__latest_single = (
        ctx.dbSession.query(model_objects.Domain.certificate_signed_id__latest_single)
        .distinct()
        .filter(
            model_objects.Domain.certificate_signed_id__latest_single != None  # noqa
        )
        .subquery()
    )
    _q_ids__latest_multi = (
        ctx.dbSession.query(model_objects.Domain.certificate_signed_id__latest_multi)
        .distinct()
        .filter(
            model_objects.Domain.certificate_signed_id__latest_single != None  # noqa
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
            model_objects.CertificateSigned,
            model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id
            == model_objects.CertificateSigned.unique_fqdn_set_id,
        )
        .filter(model_objects.CertificateSigned.is_active.is_(True))
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
                ctx.dbSession.query(model_objects.CertificateSigned)
                .join(
                    model_objects.UniqueFQDNSet2Domain,
                    model_objects.CertificateSigned.unique_fqdn_set_id
                    == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
                )
                .filter(
                    model_objects.CertificateSigned.is_active.is_(True),
                    model_objects.UniqueFQDNSet2Domain.domain_id == _domain_id,
                    model_objects.CertificateSigned.id.notin_(_q_ids__latest_single),
                    model_objects.CertificateSigned.id.notin_(_q_ids__latest_multi),
                )
                .order_by(model_objects.CertificateSigned.timestamp_not_after.desc())
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


def operations_update_recents__domains(ctx, dbDomains=None, dbUniqueFQDNSets=None):
    """
    updates A SINGLE dbDomain record with recent values

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomains: (required) A list of :class:`model.objects.Domain` instances
    :param dbUniqueFQDNSets: (optional) A list of :class:`model.objects.UniqueFQDNSet` instances
    """
    # we need a list of domain ids
    _domain_ids = [i.id for i in dbDomains] if dbDomains else []
    _unique_fqdn_set_ids = [i.id for i in dbUniqueFQDNSets] if dbUniqueFQDNSets else []

    domain_ids = set(_domain_ids)
    if dbUniqueFQDNSets:
        for _dbUniqueFQDNSet in dbUniqueFQDNSets:
            for _domain in _dbUniqueFQDNSet.domains:
                domain_ids.add(_domain.id)
    domain_ids = list(domain_ids)
    if not domain_ids:
        raise ValueError("no Domains specified")

    #
    # Step1:
    # Update the cached `certificate_signed_id__latest_single` data for each Domain
    _q_sub = (
        ctx.dbSession.query(model_objects.CertificateSigned.id)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.CertificateSigned.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.CertificateSigned.is_active.is_(True),
            model_objects.CertificateSigned.is_single_domain_cert.is_(True),
            model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
            model_objects.Domain.id.in_(domain_ids),
        )
        .order_by(model_objects.CertificateSigned.timestamp_not_after.desc())
        .limit(1)
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.Domain.__table__.update()
        .values(certificate_signed_id__latest_single=_q_sub)
        .where(model_objects.Domain.__table__.c.id.in_(domain_ids))
    )

    #
    # Step2:
    # Update the cached `certificate_signed_id__latest_multi` data for each Domain
    _q_sub = (
        ctx.dbSession.query(model_objects.CertificateSigned.id)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.CertificateSigned.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.CertificateSigned.is_active.is_(True),
            model_objects.CertificateSigned.is_single_domain_cert.is_(False),
            model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
            model_objects.Domain.id.in_(domain_ids),
        )
        .order_by(model_objects.CertificateSigned.timestamp_not_after.desc())
        .limit(1)
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.Domain.__table__.update()
        .values(certificate_signed_id__latest_multi=_q_sub)
        .where(model_objects.Domain.__table__.c.id.in_(domain_ids))
    )

    # bookkeeping, doing this will mark the session as changed!
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["domain.ids"] = _domain_ids
    event_payload_dict["unique_fqdn_set.ids"] = _unique_fqdn_set_ids
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "operations__update_recents__domains"
        ),
        event_payload_dict,
    )

    return dbOperationsEvent


def operations_update_recents__global(ctx):
    """
    updates all the objects to their most-recent relations

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    #
    # Step1:
    # Update the cached `certificate_signed_id__latest_single` data for each Domain
    # _t_domain = model_objects.Domain.__table__.alias('domain')
    _q_sub = (
        ctx.dbSession.query(model_objects.CertificateSigned.id)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.CertificateSigned.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.CertificateSigned.is_active.is_(True),
            model_objects.CertificateSigned.is_single_domain_cert.is_(True),
            model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
        )
        .order_by(model_objects.CertificateSigned.timestamp_not_after.desc())
        .limit(1)
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.Domain.__table__.update().values(
            certificate_signed_id__latest_single=_q_sub
        )
    )

    #
    # Step2:
    # Update the cached `certificate_signed_id__latest_multi` data for each Domain
    # _t_domain = model_objects.Domain.__table__.alias('domain')
    _q_sub = (
        ctx.dbSession.query(model_objects.CertificateSigned.id)
        .join(
            model_objects.UniqueFQDNSet2Domain,
            model_objects.CertificateSigned.unique_fqdn_set_id
            == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
        )
        .filter(
            model_objects.CertificateSigned.is_active.is_(True),
            model_objects.CertificateSigned.is_single_domain_cert.is_(False),
            model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
        )
        .order_by(model_objects.CertificateSigned.timestamp_not_after.desc())
        .limit(1)
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.Domain.__table__.update().values(
            certificate_signed_id__latest_multi=_q_sub
        )
    )

    #
    # Step3:
    # update the count of active cert for each CA Certificate
    CertificateSigned1 = sqlalchemy.orm.aliased(model_objects.CertificateSigned)
    CertificateSigned2 = sqlalchemy.orm.aliased(model_objects.CertificateSigned)
    _q_sub = (
        ctx.dbSession.query(sqlalchemy.func.count(model_objects.Domain.id))
        .outerjoin(
            CertificateSigned1,
            model_objects.Domain.certificate_signed_id__latest_single
            == CertificateSigned1.id,
        )
        .outerjoin(
            CertificateSigned2,
            model_objects.Domain.certificate_signed_id__latest_multi
            == CertificateSigned2.id,
        )
        .filter(
            sqlalchemy.or_(
                model_objects.CertificateCA.id
                == CertificateSigned1.certificate_ca_id__upchain,
                model_objects.CertificateCA.id
                == CertificateSigned2.certificate_ca_id__upchain,
            )
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.CertificateCA.__table__.update().values(
            count_active_certificates=_q_sub
        )
    )

    #
    # Step4:
    # update the count of certificates/orders for each PrivateKey
    # this is done automatically, but a periodic update is a good idea
    # 4.A - PrivateKey.count_acme_orders
    _q_sub = (
        ctx.dbSession.query(
            sqlalchemy.func.count(model_objects.AcmeOrder.private_key_id),
        )
        .filter(
            model_objects.AcmeOrder.private_key_id == model_objects.PrivateKey.id,
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.PrivateKey.__table__.update().values(count_acme_orders=_q_sub)
    )
    # 4.b - PrivateKey.count_certificate_signeds
    _q_sub = (
        ctx.dbSession.query(
            sqlalchemy.func.count(model_objects.CertificateSigned.private_key_id),
        )
        .filter(
            model_objects.CertificateSigned.private_key_id
            == model_objects.PrivateKey.id,
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.PrivateKey.__table__.update().values(
            count_certificate_signeds=_q_sub
        )
    )

    #
    # Step5:
    # update the counts for each AcmeAccount
    # 5.a - AcmeAccount.count_acme_orders
    _q_sub = (
        ctx.dbSession.query(
            sqlalchemy.func.count(model_objects.AcmeOrder.acme_account_id),
        )
        .filter(
            model_objects.AcmeOrder.acme_account_id == model_objects.AcmeAccount.id,
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.AcmeAccount.__table__.update().values(count_acme_orders=_q_sub)
    )
    # 5.b - AcmeAccount.count_certificate_signeds
    _q_sub = (
        ctx.dbSession.query(
            sqlalchemy.func.count(model_objects.AcmeOrder.certificate_signed_id),
        )
        .filter(
            model_objects.AcmeOrder.acme_account_id == model_objects.AcmeAccount.id,
            model_objects.AcmeOrder.certificate_signed_id.op("IS NOT")(None),
        )
        .subquery()
        .as_scalar()  # TODO: SqlAlchemy 1.4.0 - this becomes `scalar_subquery`
    )
    ctx.dbSession.execute(
        model_objects.AcmeAccount.__table__.update().values(
            count_certificate_signeds=_q_sub
        )
    )

    # should we do the timestamps?
    """
    UPDATE acme_account SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_created) FROM certificate_request
    WHERE certificate_request.acme_account_id = acme_account.id);

    UPDATE acme_account SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_created) FROM certificate_signed
    WHERE certificate_signed.acme_account_id = acme_account.id);

    UPDATE private_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_created) FROM certificate_request
    WHERE certificate_request.private_key_id = private_key.id);

    UPDATE private_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_created) FROM certificate_signed
    WHERE certificate_signed.private_key_id = private_key.id);
    """

    # bookkeeping, doing this will mark the session as changed!
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "operations__update_recents__global"
        ),
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
    domains_challenged,
    processing_strategy=None,
    private_key_cycle__renewal=None,
    private_key_strategy__requested=None,
    dbAcmeAccount=None,
    dbPrivateKey=None,
):
    """
    Adds Domains if needed

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domains_challenged: (required) An dict of ACME challenge types (keys) matched to a list of domain names
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
    acme_order_processing_strategy_id = (
        model_utils.AcmeOrder_ProcessingStrategy.from_string(processing_strategy)
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
    domain_names = domains_challenged.domains_as_list
    results = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for _domain_name in domain_names:
        # scoping
        _logger_args = {"event_status_id": None}
        _result = {
            "domain.status": None,
            "domain.id": None,
            "certificate_signed.id": None,
            "certificate_signed.status": None,
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
        _dbCertificateSigned = lib.db.get.get__CertificateSigned__by_DomainId__latest(
            ctx, _dbDomain.id
        )
        if _dbCertificateSigned:
            _result["certificate_signed.status"] = "exists"
            _result["certificate_signed.id"] = _dbCertificateSigned.id
            _logger_args[
                "event_status_id"
            ] = model_utils.OperationsObjectEventStatus.from_string(
                "ApiDomains__certificate_if_needed__certificate_exists"
            )
            _logger_args["dbCertificateSigned"] = _dbCertificateSigned
        else:
            try:
                _domains_challenged__single = model_utils.DomainsChallenged.new_http01(
                    [
                        _domain_name,
                    ]
                )
                dbAcmeOrder = actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_NEW__CIN,
                    domains_challenged=_domains_challenged__single,
                    private_key_cycle__renewal=private_key_cycle__renewal,
                    private_key_strategy__requested=private_key_strategy__requested,
                    processing_strategy=processing_strategy,
                    dbAcmeAccount=dbAcmeAccount,
                    dbPrivateKey=dbPrivateKey,
                )

                _logger_args["dbAcmeOrder"] = dbAcmeOrder
                _result["acme_order.id"] = dbAcmeOrder.id
                if dbAcmeOrder.certificate_signed_id:
                    _result["certificate_signed.status"] = "new"
                    _result["certificate_signed.id"] = dbAcmeOrder.certificate_signed_id
                    _logger_args[
                        "event_status_id"
                    ] = model_utils.OperationsObjectEventStatus.from_string(
                        "ApiDomains__certificate_if_needed__certificate_new_success"
                    )
                    _logger_args["dbCertificateSigned"] = dbAcmeOrder.certificate_signed
                else:
                    _result["error"] = "AcmeOrder did not generate a CertificateSigned"
                    _result["certificate_signed.status"] = "fail"
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
                    _result["certificate_signed.status"] = "fail"
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
        if _result["certificate_signed.status"] in ("new", "exists"):
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


def upload__CertificateCABundle__by_pem_text(ctx, bundle_data):
    """
    Uploads a bundle of CertificateCAs

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
        display_name = None
        is_trusted_root = None
        for c in list(letsencrypt_info.CA_CERTS_DATA.keys()):
            if cert_base == letsencrypt_info.CA_CERTS_DATA[c]["formfield_base"]:
                cert_name = letsencrypt_info.CA_CERTS_DATA[c]["name"]
                if "display_name" in letsencrypt_info.CA_CERTS_DATA[c]:
                    display_name = letsencrypt_info.CA_CERTS_DATA[c]["display_name"]
                if "is_trusted_root" in letsencrypt_info.CA_CERTS_DATA[c]:
                    is_trusted_root = letsencrypt_info.CA_CERTS_DATA[c][
                        "is_trusted_root"
                    ]
                break

        (
            dbCertificateCA,
            is_created,
        ) = lib.db.getcreate.getcreate__CertificateCA__by_pem_text(
            ctx,
            cert_pem_text,
            ca_chain_name=cert_name,
            display_name=None,
            is_trusted_root=is_trusted_root,
        )
        if not is_created:
            if dbCertificateCA.name in ("unknown", "manual upload") and cert_name:
                dbCertificateCA.name = cert_name
            if dbCertificateCA.display_name is None:
                dbCertificateCA.display_name = display_name

        results[cert_pem] = (dbCertificateCA, is_created)

    ids_created = [i[0].id for i in results.values() if i[1]]
    ids_updated = [i[0].id for i in results.values() if not i[1]]
    event_payload_dict["ids_created"] = ids_created
    event_payload_dict["ids_updated"] = ids_updated
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])
    return results
