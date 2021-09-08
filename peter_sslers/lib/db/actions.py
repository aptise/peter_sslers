# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import pdb

# pypi
import requests
import sqlalchemy

# from zope.sqlalchemy import mark_changed

# localapp
from ... import lib
from .. import errors
from .. import events
from ...model import utils as model_utils
from ...model import objects as model_objects
from . import actions_acme
from . import getcreate
from . import update

# local
from .logger import AcmeLogger
from .logger import log__OperationsEvent
from .logger import _log_object_event


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

"""
TODO: sqlalchemy 1.4 rename
* ``isnot`` is now ``is_not``
* ``notin_`` is now ``not_in``
"""


_SA_VERSION = None  # parsed version
_SA_1_4 = None  # Boolean


def scalar_subquery(query):
    global _SA_VERSION
    global _SA_1_4
    if _SA_VERSION is None:
        _SA_VERSION = tuple(int(i) for i in sqlalchemy.__version__.split("."))
        if _SA_VERSION >= (1, 4, 0):
            _SA_1_4 = True
        else:
            _SA_1_4 = False
    if _SA_1_4:
        return query.scalar_subquery()
    return query.subquery().as_scalar()


def operations_deactivate_expired(ctx):
    """
    deactivates expired Certificates automatically

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    # create an event first
    event_payload_dict = lib.utils.new_event_payload_dict()
    event_payload_dict["count_deactivated"] = 0
    operationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "CertificateSigned__deactivate_expired"
        ),
        event_payload_dict,
    )

    # update the recents, this will automatically create a subevent
    # this is required, because the following logic depends upon every
    # Domain record being hinted with the id(s) of the latest corresponding
    # Certificate(s)
    subevent = operations_update_recents__global(ctx)

    # Start the Deactivate Logic

    # placeholder
    deactivated_cert_ids = []

    # Step 1: load all the Expired Certificates
    # order them by newest-first
    expired_certs = (
        ctx.dbSession.query(model_objects.CertificateSigned)
        .filter(
            model_objects.CertificateSigned.is_active.is_(True),
            model_objects.CertificateSigned.timestamp_not_after < ctx.timestamp,
        )
        .order_by(model_objects.CertificateSigned.timestamp_not_after.desc())
        .all()
    )
    # Step 2: Analyze
    for cert in expired_certs:
        # the domains for each Certificate require a query
        # Certificate > [[UniqueFQDNSet > UniqueFQDNSet2Domain]] > Domain
        cert_domains = (
            ctx.dbSession.query(model_objects.Domain)
            .join(
                model_objects.UniqueFQDNSet2Domain,
                model_objects.Domain.id == model_objects.UniqueFQDNSet2Domain.domain_id,
                isouter=True,
            )
            .join(
                model_objects.CertificateSigned,
                model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id
                == model_objects.CertificateSigned.unique_fqdn_set_id,
                isouter=True,
            )
            .filter(
                model_objects.CertificateSigned.id == cert.id,
            )
            .all()
        )
        cert_ok = True
        for cert_domain in cert_domains:
            # if this Certificate is the latest Certificate for the domain, we can not turn it off
            if cert.id in (
                cert_domain.certificate_signed_id__latest_single,
                cert_domain.certificate_signed_id__latest_multi,
            ):
                cert_ok = False
        if cert_ok:
            deactivated_cert_ids.append(cert.id)
            cert.is_active = False
            ctx.dbSession.flush(objects=[cert])
            events.Certificate_expired(ctx, cert)

    # update the event
    if len(deactivated_cert_ids):
        event_payload_dict["count_deactivated"] = len(deactivated_cert_ids)
        event_payload_dict["certificate_signed.ids"] = deactivated_cert_ids
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


_header_2_format = {
    "application/pkcs7-mime": "pkcs7",
    "application/pkix-cert": "pkix-cert",
}


def operations_reconcile_cas(ctx):
    """
    tries to reconcile CAs

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    dbCertificateCAs = (
        ctx.dbSession.query(model_objects.CertificateCA)
        .filter(
            model_objects.CertificateCA.cert_issuer_uri.isnot(None),
            model_objects.CertificateCA.cert_issuer__reconciled.isnot(True),
        )
        .all()
    )
    _certificate_ca_ids = []
    for dbCertificateCA in dbCertificateCAs:
        log.debug("Reconciling CA...")
        _certificate_ca_ids.append(dbCertificateCA.id)
        cert_issuer_uri = dbCertificateCA.cert_issuer_uri
        log.debug(dbCertificateCA.cert_subject)
        log.debug(cert_issuer_uri)
        resp = requests.get(cert_issuer_uri)
        if resp.status_code != 200:
            raise ValueError("Could not load certificate")
        content_type = resp.headers.get("content-type")
        filetype = _header_2_format.get(content_type) if content_type else None
        cert_pems = None
        if filetype == "pkcs7":
            cert_pems = lib.cert_utils.convert_pkcs7_to_pems(resp.content)
        elif filetype == "pkix-cert":
            cert_pem = lib.cert_utils.convert_der_to_pem(resp.content)
            cert_pems = [
                cert_pem,
            ]
        else:
            raise ValueError("Not Implemented: %s" % content_type)

        for cert_pem in cert_pems:
            cert_parsed = lib.cert_utils.parse_cert(cert_pem)
            (
                _dbCertificateCAReconciled,
                _is_created,
            ) = getcreate.getcreate__CertificateCA__by_pem_text(ctx, cert_pem)
            # mark the first item as reconciled
            dbCertificateCA.cert_issuer__reconciled = True
            if not dbCertificateCA.cert_issuer__certificate_ca_id:
                dbCertificateCA.cert_issuer__certificate_ca_id = (
                    _dbCertificateCAReconciled.id
                )
            else:
                raise ValueError("Not Implemented: multiple reconciles")
            # mark the second item
            reconciled_uris = _dbCertificateCAReconciled.reconciled_uris
            reconciled_uris = reconciled_uris.split(" ") if reconciled_uris else []
            if cert_issuer_uri not in reconciled_uris:
                reconciled_uris.append(cert_issuer_uri)
                reconciled_uris = " ".join(reconciled_uris)
                _dbCertificateCAReconciled.reconciled_uris = reconciled_uris

            dbCertificateCAReconciliation = model_objects.CertificateCAReconciliation()
            dbCertificateCAReconciliation.timestamp_operation = ctx.timestamp
            dbCertificateCAReconciliation.certificate_ca_id = dbCertificateCA.id
            dbCertificateCAReconciliation.certificate_ca_id__issuer__reconciled = (
                _dbCertificateCAReconciled.id
            )
            dbCertificateCAReconciliation.result = True
            ctx.dbSession.add(dbCertificateCAReconciliation)

    event_payload_dict = lib.utils.new_event_payload_dict()
    event_payload_dict["certificate_ca.ids"] = _certificate_ca_ids
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("operations__reconcile_cas"),
        event_payload_dict,
    )

    return dbOperationsEvent


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
    )
    _q_sub = scalar_subquery(_q_sub)
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
    )
    _q_sub = scalar_subquery(_q_sub)
    ctx.dbSession.execute(
        model_objects.Domain.__table__.update()
        .values(certificate_signed_id__latest_multi=_q_sub)
        .where(model_objects.Domain.__table__.c.id.in_(domain_ids))
    )

    # bookkeeping, doing this will mark the session as changed!
    event_payload_dict = lib.utils.new_event_payload_dict()
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
    )
    _q_sub = scalar_subquery(_q_sub)
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
    )
    _q_sub = scalar_subquery(_q_sub)
    ctx.dbSession.execute(
        model_objects.Domain.__table__.update().values(
            certificate_signed_id__latest_multi=_q_sub
        )
    )

    #
    # Step3:
    # update the count of active cert for each CertificateCA

    CertificateSigned1 = sqlalchemy.orm.aliased(model_objects.CertificateSigned)
    CertificateSigned2 = sqlalchemy.orm.aliased(model_objects.CertificateSigned)

    CertificateSignedChain1 = sqlalchemy.orm.aliased(
        model_objects.CertificateSignedChain
    )
    CertificateSignedChain2 = sqlalchemy.orm.aliased(
        model_objects.CertificateSignedChain
    )

    CertificateCAChain1 = sqlalchemy.orm.aliased(model_objects.CertificateCAChain)
    CertificateCAChain2 = sqlalchemy.orm.aliased(model_objects.CertificateCAChain)

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
        .outerjoin(
            CertificateSignedChain1,
            CertificateSigned1.id == CertificateSignedChain1.certificate_signed_id,
        )
        .outerjoin(
            CertificateSignedChain2,
            CertificateSignedChain2.id == CertificateSignedChain2.certificate_signed_id,
        )
        .outerjoin(
            CertificateCAChain1,
            CertificateSignedChain1.certificate_ca_chain_id
            == CertificateCAChain1.certificate_ca_0_id,
        )
        .outerjoin(
            CertificateCAChain2,
            CertificateSignedChain1.certificate_ca_chain_id
            == CertificateCAChain2.certificate_ca_0_id,
        )
        .filter(
            sqlalchemy.or_(
                model_objects.CertificateCA.id
                == CertificateCAChain1.certificate_ca_0_id,
                model_objects.CertificateCA.id
                == CertificateCAChain2.certificate_ca_0_id,
            )
        )
    )
    _q_sub = scalar_subquery(_q_sub)
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
    _q_sub = ctx.dbSession.query(
        sqlalchemy.func.count(model_objects.AcmeOrder.private_key_id),
    ).filter(
        model_objects.AcmeOrder.private_key_id == model_objects.PrivateKey.id,
    )
    _q_sub = scalar_subquery(_q_sub)
    ctx.dbSession.execute(
        model_objects.PrivateKey.__table__.update().values(count_acme_orders=_q_sub)
    )
    # 4.b - PrivateKey.count_certificate_signeds
    _q_sub = ctx.dbSession.query(
        sqlalchemy.func.count(model_objects.CertificateSigned.private_key_id),
    ).filter(
        model_objects.CertificateSigned.private_key_id == model_objects.PrivateKey.id,
    )
    _q_sub = scalar_subquery(_q_sub)
    ctx.dbSession.execute(
        model_objects.PrivateKey.__table__.update().values(
            count_certificate_signeds=_q_sub
        )
    )

    #
    # Step5:
    # update the counts for each AcmeAccount
    # 5.a - AcmeAccount.count_acme_orders
    _q_sub = ctx.dbSession.query(
        sqlalchemy.func.count(model_objects.AcmeOrder.acme_account_id),
    ).filter(
        model_objects.AcmeOrder.acme_account_id == model_objects.AcmeAccount.id,
    )
    _q_sub = scalar_subquery(_q_sub)
    ctx.dbSession.execute(
        model_objects.AcmeAccount.__table__.update().values(count_acme_orders=_q_sub)
    )
    # 5.b - AcmeAccount.count_certificate_signeds
    _q_sub = ctx.dbSession.query(
        sqlalchemy.func.count(model_objects.AcmeOrder.certificate_signed_id),
    ).filter(
        model_objects.AcmeOrder.acme_account_id == model_objects.AcmeAccount.id,
        model_objects.AcmeOrder.certificate_signed_id.op("IS NOT")(None),
    )
    _q_sub = scalar_subquery(_q_sub)
    ctx.dbSession.execute(
        model_objects.AcmeAccount.__table__.update().values(
            count_certificate_signeds=_q_sub
        )
    )

    # TODO: should we do the timestamps?
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
    event_payload_dict = lib.utils.new_event_payload_dict()
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
    domain_names = lib.utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}

    # bookkeeping
    event_payload_dict = lib.utils.new_event_payload_dict()
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
    event_payload_dict = lib.utils.new_event_payload_dict()
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
