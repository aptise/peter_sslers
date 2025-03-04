# stdlib
import datetime
import logging
import pdb
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
import cert_utils
import requests
import sqlalchemy
from sqlalchemy import and_ as sqlalchemy_and
from sqlalchemy import or_ as sqlalchemy_or
from typing_extensions import Literal

# from zope.sqlalchemy import mark_changed

# localapp
from . import actions_acme
from . import create
from . import get
from . import getcreate
from .logger import _log_object_event
from .logger import log__OperationsEvent
from .. import acme_v2
from .. import errors
from .. import events
from ... import lib
from ...lib import db as lib_db
from ...lib.http import StopableWSGIServer
from ...lib.utils import timedelta_ARI_CHECKS_TIMELY
from ...lib.utils import url_to_server
from ...model import objects as model_objects
from ...model import utils as model_utils
from ...model.objects import AcmeServer
from ...model.objects import AriCheck
from ...model.objects import CertificateSigned
from ...model.utils import AcmeServerInput


if TYPE_CHECKING:
    from ...model.objects import AcmeAccount
    from ...model.objects import Domain
    from ...model.objects import OperationsEvent
    from ...model.objects import PrivateKey
    from ...model.objects import RenewalConfiguration
    from ...model.objects import SystemConfiguration
    from ...model.objects import UniqueFQDNSet
    from ...model.utils import DomainsChallenged
    from ..context import ApiContext


# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

"""
TODO: sqlalchemy 1.4 rename
* ``isnot`` is now ``is_not``
* ``notin_`` is now ``not_in``
"""


_SA_VERSION = None  # parsed version
_SA_1_4 = None  # Boolean

DEBUG_CONCEPT = False


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


def operations_deactivate_expired(
    ctx: "ApiContext",
) -> "OperationsEvent":
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
    subevent = operations_update_recents__global(ctx)  # noqa: F841

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


def operations_reconcile_cas(
    ctx: "ApiContext",
) -> "OperationsEvent":
    """
    Tries to reconcile CAs.
    This involves checking to ensure the cert_issuer_uri is live and valid

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    assert ctx.timestamp
    dbCertificateCAs = (
        ctx.dbSession.query(model_objects.CertificateCA)
        .filter(
            model_objects.CertificateCA.cert_issuer_uri.isnot(None),
            model_objects.CertificateCA.cert_issuer__reconciled.isnot(True),
        )
        .all()
    )
    _certificate_ca_ids = []
    _certificate_ca_ids_fail = []
    for dbCertificateCA in dbCertificateCAs:
        log.debug("Reconciling CA...")
        _certificate_ca_ids.append(dbCertificateCA.id)
        cert_issuer_uri = dbCertificateCA.cert_issuer_uri
        log.debug(dbCertificateCA.cert_subject)
        log.debug(cert_issuer_uri)
        assert cert_issuer_uri
        try:
            resp = requests.get(cert_issuer_uri)
            if resp.status_code != 200:
                raise ValueError("Could not load certificate")
            content_type = resp.headers.get("content-type")
            filetype = _header_2_format.get(content_type) if content_type else None
            cert_pems = None
            if filetype == "pkcs7":
                cert_pems = cert_utils.convert_pkcs7_to_pems(resp.content)
            elif filetype == "pkix-cert":
                cert_pem = cert_utils.convert_der_to_pem(resp.content)
                cert_pems = [
                    cert_pem,
                ]
            else:
                raise ValueError("Not Implemented: %s" % content_type)

            for cert_pem in cert_pems:
                cert_parsed = cert_utils.parse_cert(cert_pem)
                (
                    _dbCertificateCAReconciled,
                    _is_created,
                ) = getcreate.getcreate__CertificateCA__by_pem_text(
                    ctx,
                    cert_pem,
                    discovery_type="reconcile_cas",
                )
                # mark the first item as reconciled
                dbCertificateCA.cert_issuer__reconciled = True
                if not dbCertificateCA.cert_issuer__certificate_ca_id:
                    dbCertificateCA.cert_issuer__certificate_ca_id = (
                        _dbCertificateCAReconciled.id
                    )
                else:
                    raise ValueError("Not Implemented: multiple reconciles")
                # mark the second item
                _reconciled_uris = _dbCertificateCAReconciled.reconciled_uris
                reconciled_uris = (
                    _reconciled_uris.split(" ") if _reconciled_uris else []
                )
                if cert_issuer_uri not in reconciled_uris:
                    reconciled_uris.append(cert_issuer_uri)
                    _reconciled_uris = " ".join(reconciled_uris)
                    _dbCertificateCAReconciled.reconciled_uris = _reconciled_uris

                dbCertificateCAReconciliation = (
                    model_objects.CertificateCAReconciliation()
                )
                dbCertificateCAReconciliation.timestamp_operation = ctx.timestamp
                dbCertificateCAReconciliation.certificate_ca_id = dbCertificateCA.id
                dbCertificateCAReconciliation.certificate_ca_id__issuer__reconciled = (
                    _dbCertificateCAReconciled.id
                )
                dbCertificateCAReconciliation.result = True
                ctx.dbSession.add(dbCertificateCAReconciliation)
        except Exception as exc:
            log.debug("EXCEPTION - could not reconcile CA %s", dbCertificateCA.id)
            _certificate_ca_ids_fail.append(dbCertificateCA.id)

    event_payload_dict = lib.utils.new_event_payload_dict()
    event_payload_dict["certificate_ca.ids"] = _certificate_ca_ids
    if _certificate_ca_ids_fail:
        event_payload_dict["certificate_ca.ids_fail"] = _certificate_ca_ids_fail
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("operations__reconcile_cas"),
        event_payload_dict,
    )

    return dbOperationsEvent


def operations_update_recents__domains(
    ctx: "ApiContext",
    dbDomains: Optional[Iterable["Domain"]] = None,
    dbUniqueFQDNSets: Optional[Iterable["UniqueFQDNSet"]] = None,
) -> "OperationsEvent":
    """
    updates A SINGLE dbDomain record with recent values

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomains: (optional) A list of :class:`model.objects.Domain` instances
    :param dbUniqueFQDNSets: (optional) A list of :class:`model.objects.UniqueFQDNSet` instances
    """
    if (not dbDomains) and (not dbUniqueFQDNSets):
        raise ValueError(
            "must submit at least one of `dbDomains` or `dbUniqueFQDNSets`"
        )
    # we need a list of domain ids
    _domain_ids = [i.id for i in dbDomains] if dbDomains else []
    _unique_fqdn_set_ids = [i.id for i in dbUniqueFQDNSets] if dbUniqueFQDNSets else []

    _domain_ids_set = set(_domain_ids)
    if dbUniqueFQDNSets:
        for _dbUniqueFQDNSet in dbUniqueFQDNSets:
            for _domain in _dbUniqueFQDNSet.domains:
                _domain_ids_set.add(_domain.id)
    domain_ids = list(_domain_ids_set)
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


def operations_update_recents__global(
    ctx: "ApiContext",
) -> "OperationsEvent":
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
        model_objects.AcmeOrder.certificate_signed_id.is_not(None),
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


def api_domains__certificate_if_needed(
    ctx: "ApiContext",
    domains_challenged: "DomainsChallenged",
    # PRIMARY
    dbAcmeAccount__primary: "AcmeAccount",
    dbPrivateKey__primary: Optional["PrivateKey"],
    acme_profile__primary: Optional[str],
    private_key_cycle__primary: str,
    private_key_technology__primary: str,
    # BACKUP
    dbAcmeAccount__backup: Optional["AcmeAccount"],
    dbPrivateKey__backup: Optional["PrivateKey"],
    acme_profile__backup: Optional[str],
    private_key_cycle__backup: Optional[str],
    private_key_technology__backup: Optional[str],
    # SHARED
    note: Optional[str],
    processing_strategy: str,
    dbSystemConfiguration: "SystemConfiguration",
) -> Dict:
    """
    Adds Domains if needed

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domains_challenged: (required) An dict of ACME challenge types (keys) matched to a list of domain names, as instance of :class:`model.utils.DomainsChallenged`.

    :param dbAcmeAccount__primary: (required) A :class:`model.objects.AcmeAccount` object
    :param dbPrivateKey__primary: (required) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param private_key_cycle__primary: (required)  A value from :class:`model.utils.PrivateKeyCycle`
    :param private_key_technology__primary: (required)  A value from :class:`model.utils.PrivateKeyTechnology`
    :param acme_profile__primary: (optional)

    :param dbAcmeAccount__backup: (optional) A :class:`model.objects.AcmeAccount` object
    :param dbPrivateKey__backup: (optional) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param acme_profile__backup: (optional)  str
    :param private_key_cycle__backup: (optional)  A value from :class:`model.utils.PrivateKeyCycle`
    :param private_key_technology__backup: (optional)  A value from :class:`model.utils.PrivateKeyTechnology`

    :param note: (optional)  user note
    :param processing_strategy: (required)  A value from :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param dbSystemConfiguration: (required) The sytem configuration

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
    # dbSystemConfiguration = ctx._load_SystemConfiguration_cin()
    if not dbSystemConfiguration or not dbSystemConfiguration.is_configured:
        raise errors.DisplayableError(
            "the `certificate-if-needed` SystemConfiguration is not configured"
        )

    acme_order_processing_strategy_id = (
        model_utils.AcmeOrder_ProcessingStrategy.from_string(processing_strategy)
    )
    private_key_cycle_id__primary = model_utils.PrivateKeyCycle.from_string(
        private_key_cycle__primary
    )
    private_key_cycle_id__backup: Optional[int] = None
    private_key_technology_id__backup: Optional[int] = None
    if dbAcmeAccount__backup:
        # private_key_cycle__backup and private_key_technology__backup are required
        # acme_profile__backup is not required
        if not private_key_cycle__backup:
            raise errors.DisplayableError("missing `private_key_cycle__backup`")
        if not private_key_technology__backup:
            raise errors.DisplayableError("missing `private_key_technology__backup`")

        private_key_cycle_id__backup = model_utils.PrivateKeyCycle.from_string(
            private_key_cycle__backup
        )
        private_key_technology_id__backup = model_utils.KeyTechnology.from_string(
            private_key_technology__backup
        )
    else:
        acme_profile__backup = None
        private_key_cycle__backup = None
        private_key_technology__backup = None

    if dbAcmeAccount__primary is None:
        raise errors.DisplayableError("missing AcmeAccount[Primary]")
    elif not dbAcmeAccount__primary.is_active:
        raise errors.DisplayableError("AcmeAccount[Primary] is not active")

    if not dbPrivateKey__primary:
        raise errors.DisplayableError("missing PrivateKey[Primary]")

    # bookkeeping
    event_payload_dict = lib.utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "ApiDomains__certificate_if_needed"
        ),
        event_payload_dict,
    )

    # this function checks the domain names match a simple regex
    domain_names = domains_challenged.domains_as_list
    results: Dict = {d: None for d in domain_names}
    # _timestamp = dbOperationsEvent.timestamp_event
    for _domain_name in domain_names:
        # scoping
        _logger_args: Dict = {
            "event_status_id": None,
        }
        _result: Dict = {
            "domain.status": None,
            "domain.id": None,
            "certificate_signed.id": None,
            "certificate_signed.status": None,
            "acme_order.id": None,
        }

        # Step 1- is the domain_name blocklisted?
        _dbDomainBlocklisted = lib.db.get.get__DomainBlocklisted__by_name(
            ctx, _domain_name
        )
        if _dbDomainBlocklisted:
            _result["domain.status"] = "blocklisted"
            continue

        # Step 2- is the domain_name a Domain?
        _dbDomain = lib.db.get.get__Domain__by_name(ctx, _domain_name, preload=False)
        if _dbDomain:
            _result["domain.id"] = _dbDomain.id

            _result["domain.status"] = "existing"

            _logger_args["event_status_id"] = (
                model_utils.OperationsObjectEventStatus.from_string(
                    "ApiDomains__certificate_if_needed__domain_exists"
                )
            )
            _logger_args["dbDomain"] = _dbDomain

        elif not _dbDomain:
            _dbDomain = lib.db.getcreate.getcreate__Domain__by_domainName(
                ctx,
                _domain_name,
                discovery_type="via certificate_if_needed",
            )[
                0
            ]  # (dbDomain, _is_created)
            _result["domain.status"] = "new"
            _result["domain.id"] = _dbDomain.id
            _logger_args["event_status_id"] = (
                model_utils.OperationsObjectEventStatus.from_string(
                    "ApiDomains__certificate_if_needed__domain_new"
                )
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
            _logger_args["event_status_id"] = (
                model_utils.OperationsObjectEventStatus.from_string(
                    "ApiDomains__certificate_if_needed__certificate_exists"
                )
            )
            _logger_args["dbCertificateSigned"] = _dbCertificateSigned
        else:
            try:
                _domains_challenged__single = model_utils.DomainsChallenged.new_http01(
                    [
                        _domain_name,
                    ]
                )

                try:
                    dbRenewalConfiguration = create.create__RenewalConfiguration(
                        ctx,
                        domains_challenged=_domains_challenged__single,
                        # Primary cert
                        dbAcmeAccount__primary=dbAcmeAccount__primary,
                        private_key_technology_id__primary=model_utils.KeyTechnology.from_string(
                            private_key_technology__primary
                        ),
                        private_key_cycle_id__primary=private_key_cycle_id__primary,
                        acme_profile__primary=acme_profile__primary,
                        # Backup cert
                        dbAcmeAccount__backup=dbAcmeAccount__backup,
                        private_key_technology_id__backup=private_key_technology_id__backup,
                        private_key_cycle_id__backup=private_key_cycle_id__backup,
                        acme_profile__backup=acme_profile__backup,
                        # misc
                        note=note,
                        dbSystemConfiguration=dbSystemConfiguration,
                    )
                    is_duplicate_renewal = False
                except errors.DuplicateRenewalConfiguration as exc:
                    is_duplicate_renewal = True
                    # we could raise exc to abort, but this is likely preferred
                    dbRenewalConfiguration = exc.args[0]

                dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    dbRenewalConfiguration=dbRenewalConfiguration,
                    processing_strategy=processing_strategy,
                    acme_order_type_id=model_utils.AcmeOrderType.CERTIFICATE_IF_NEEDED,
                    dbPrivateKey=dbPrivateKey__primary,
                    replaces_type=model_utils.ReplacesType_Enum.AUTOMATIC,
                )

                _logger_args["dbAcmeOrder"] = dbAcmeOrder
                _result["acme_order.id"] = dbAcmeOrder.id
                if dbAcmeOrder.certificate_signed_id:
                    _result["certificate_signed.status"] = "new"
                    _result["certificate_signed.id"] = dbAcmeOrder.certificate_signed_id
                    _logger_args["event_status_id"] = (
                        model_utils.OperationsObjectEventStatus.from_string(
                            "ApiDomains__certificate_if_needed__certificate_new_success"
                        )
                    )
                    _logger_args["dbCertificateSigned"] = dbAcmeOrder.certificate_signed
                else:
                    _result["error"] = "AcmeOrder did not generate a CertificateSigned"
                    _result["certificate_signed.status"] = "fail"
                    _logger_args["event_status_id"] = (
                        model_utils.OperationsObjectEventStatus.from_string(
                            "ApiDomains__certificate_if_needed__certificate_new_fail"
                        )
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
                    _logger_args["event_status_id"] = (
                        model_utils.OperationsObjectEventStatus.from_string(
                            "ApiDomains__certificate_if_needed__certificate_new_fail"
                        )
                    )

                raise

        # log domain event
        if DEBUG_CONCEPT:
            print("=====================")
            print("DEBUGGING CONCEPT")
            print(dbOperationsEvent.__dict__)
            print("-----")
            print(_logger_args)
            print("=====================")
        _log_object_event(ctx, dbOperationsEvent=dbOperationsEvent, **_logger_args)

        # do commit, just because THE LOGGGING
        ctx.pyramid_transaction_commit()

        # note result
        results[_domain_name] = _result

    event_payload_dict["results"] = results
    # dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return results


def refresh_pebble_ca_certs(ctx: "ApiContext") -> bool:
    """
    pebble uses a new ca_cert bundle each time it runs
    """
    log.info("refresh_pebble_ca_certs")

    pebbleServer = (
        ctx.dbSession.query(AcmeServer)
        .filter(
            AcmeServer.name == "pebble",
        )
        .first()
    )
    if not pebbleServer:
        log.info("> refresh_pebble_ca_certs X no pebble")
        return False

    r0 = requests.get("https://127.0.0.1:15000/roots/0", verify=False)
    if r0.status_code != 200:
        raise ValueError("Could not load first root")
    root_pems = [
        r0.text,
    ]
    alternates = acme_v2.get_header_links(r0.headers, "alternate")
    if alternates:
        for _alt in alternates:
            _r = requests.get(_alt, verify=False)
            if _r.status_code != 200:
                raise ValueError("Could not load additional root")
            root_pems.append(_r.text)

    dbCACerts = []
    for _root_pem in root_pems:
        (
            _dbCACert,
            _is_created,
        ) = getcreate.getcreate__CertificateCA__by_pem_text(
            ctx, _root_pem, display_name="Detected Pebble Root", is_trusted_root=True
        )
        dbCACerts.append(_dbCACert)

    # touching this will generate if needed;
    # force_refresh will update
    pebbleServer.local_ca_bundle(ctx, force_refresh=True)
    return True


def register_acme_servers(
    ctx: "ApiContext",
    acme_servers: List[AcmeServerInput],
    source: Literal["initial", "user"],
):
    for item in acme_servers:

        # always done
        server_ca_cert_bundle: Optional[str] = None

        filepath_ca_cert_bundle = item.get("filepath_ca_cert_bundle")
        ca_cert_bundle = item.get("ca_cert_bundle")
        if filepath_ca_cert_bundle and ca_cert_bundle:
            raise ValueError(
                "you may only submit one of: filepath_ca_cert_bundle, ca_cert_bundle"
            )

        if filepath_ca_cert_bundle:
            with open(filepath_ca_cert_bundle) as fh:
                server_ca_cert_bundle = fh.read()
            server_ca_cert_bundle = cert_utils.cleanup_pem_text(server_ca_cert_bundle)
        elif ca_cert_bundle:
            server_ca_cert_bundle = cert_utils.cleanup_pem_text(ca_cert_bundle)

        server = url_to_server(item["directory"])

        def _new_AcmeServer():
            dbObject = model_objects.AcmeServer()
            dbObject.is_unlimited_pending_authz = item.get(
                "is_unlimited_pending_authz", None
            )
            dbObject.timestamp_created = ctx.timestamp
            dbObject.name = item["name"]
            dbObject.directory = item["directory"]
            dbObject.protocol = item["protocol"]
            dbObject.is_supports_ari__version = item.get(
                "is_supports_ari__version", None
            )
            dbObject.server = server
            dbObject.server_ca_cert_bundle = server_ca_cert_bundle
            ctx.dbSession.add(dbObject)
            ctx.dbSession.flush(
                objects=[
                    dbObject,
                ]
            )

        if source == "initial":
            log.debug("Adding New ACME Server: %s", server)
            _new_AcmeServer()
        else:
            existingDbServer = get.get__AcmeServer__by_server(ctx, server)
            if not existingDbServer:
                log.debug("Adding New ACME Server: %s", server)
                _new_AcmeServer()
            else:
                log.debug("Existing ACME Server: %s", server)
                if existingDbServer.server_ca_cert_bundle != server_ca_cert_bundle:
                    log.debug("Updating: %s", server)
                    existingDbServer.server_ca_cert_bundle = server_ca_cert_bundle
    ctx.pyramid_transaction_commit()
    return True


def routine__clear_old_ari_checks(ctx: "ApiContext") -> bool:
    """
    clear from the database outdated ARI checks.
    An ARI check is considered outdated once it has been replaced with a newer ARI check.
    """
    # iterate over all the CertificateSigned - windowed query of 100
    # criteria: no ari check, ari_check expired
    # run & store ari check
    NOW = datetime.datetime.now(datetime.timezone.utc)

    """
    # The SQL we want (for now):

    DELETE FROM ari_check WHERE id NOT IN (
        SELECT subq.latest_ari_id FROM (
            SELECT
                max(id) AS latest_ari_id,
                certificate_signed_id
            FROM ari_check
            GROUP BY
                certificate_signed_id
        ) subq
    );
    """

    latest_ari_checks = (
        ctx.dbSession.query(
            sqlalchemy.func.max(AriCheck.id).label("latest_ari_id"),
            AriCheck.certificate_signed_id,
        )
        .group_by(AriCheck.certificate_signed_id)
        .subquery()
    )
    latest_ari_ids = ctx.dbSession.query(latest_ari_checks.c.latest_ari_id)
    stmt = sqlalchemy.delete(AriCheck).where(AriCheck.id.not_in(latest_ari_ids))
    result = ctx.dbSession.execute(stmt)
    ctx.pyramid_transaction_commit()
    return True


def routine__run_ari_checks(ctx: "ApiContext") -> bool:
    """
    Run ARI checks for certificates that require one
    * no ARI check logged
    * current time is after the latest ARI check's retry-after
    """
    # iterate over all the CertificateSigned - windowed query of 100
    # criteria: no ari check, ari_check expired
    # run & store ari check
    NOW = datetime.datetime.now(datetime.timezone.utc)
    timely_date = NOW - timedelta_ARI_CHECKS_TIMELY

    """
    # The SQL we want (for now):
    SELECT
        cert.id,
        latest_ari_checks.latest_ari_id,
        latest_ari_checks.timestamp_retry_after
    FROM
        certificate_signed AS cert
    LEFT OUTER JOIN (
        SELECT
            certificate_signed_id,
            max(id) as latest_ari_id,
            timestamp_retry_after
        FROM ari_check
        GROUP BY certificate_signed_id
    ) AS latest_ari_checks
    ON cert.id = latest_ari_checks.certificate_signed_id
    WHERE
        cert.is_active IS True
        AND
        (
            cert.is_ari_supported__cert IS True
            OR
            cert.is_ari_supported__order IS True
        )
        AND
        cert.timestamp_not_after > timely_date
        (
            latest_ari_checks.latest_ari_id IS NULL
            OR
            latest_ari_checks.timestamp_retry_after < datetime()
        )
    ORDER BY cert.id DESC;
    """

    latest_ari_checks = (
        ctx.dbSession.query(
            AriCheck.certificate_signed_id,
            sqlalchemy.func.max(AriCheck.id).label("latest_ari_id"),
            AriCheck.timestamp_retry_after,
        )
        .group_by(AriCheck.certificate_signed_id)
        .order_by(AriCheck.certificate_signed_id.desc())
        .subquery()
    )

    certs = (
        ctx.dbSession.query(CertificateSigned, latest_ari_checks.c.latest_ari_id)
        .outerjoin(
            latest_ari_checks,
            CertificateSigned.id == latest_ari_checks.c.certificate_signed_id,
        )
        .filter(
            CertificateSigned.is_active.is_(True),
            sqlalchemy_or(
                CertificateSigned.is_ari_supported__cert.is_(True),
                CertificateSigned.is_ari_supported__order.is_(True),
            ),
            CertificateSigned.timestamp_not_after > timely_date,
            sqlalchemy_or(
                latest_ari_checks.c.latest_ari_id.is_(None),
                latest_ari_checks.c.timestamp_retry_after < NOW,
            ),
        )
        .order_by(
            CertificateSigned.id.desc(),
            latest_ari_checks.c.latest_ari_id.desc(),
        )
        .all()
    )

    for dbCertificateSigned, latest_ari_id in certs:
        log.debug(
            "Running ARI Check for : %s [%s]"
            % (dbCertificateSigned.id, dbCertificateSigned.cert_serial)
        )
        dbAriObject, ari_check_result = actions_acme.do__AcmeV2_AriCheck(
            ctx,
            dbCertificateSigned=dbCertificateSigned,
        )
        ctx.pyramid_transaction_commit()

    return True


def _create_public_server(settings: Dict) -> StopableWSGIServer:
    """
    def tearDown(self):
        if self._testapp_wsgi is not None:
            self._testapp_wsgi.shutdown()
        AppTest.tearDown(self)
    """

    #
    # sanitize the settings
    #
    pryamid_bools = (
        "pyramid.debug_authorization"
        "pyramid.debug_notfound"
        "pyramid.debug_routematch"
    )
    for field in pryamid_bools:
        if field in settings:
            settings[field] = "false"
    if "pyramid.includes" in settings:
        settings["pyramid.includes"] = settings["pyramid.includes"].replace(
            "pyramid_debugtoolbar", ""
        )

    # ensure what the public can and can't see
    settings["enable_views_admin"] = "false"
    settings["enable_views_public"] = "true"

    try:
        http_port = settings.get("http_port.renewals")
        http_port = int(http_port)  # type: ignore[arg-type]
    except Exception:
        http_port = 7202

    # import here to avoid circular imports
    from ...web import main as app_main

    app = app_main(global_config=None, **settings)
    app_wsgi = StopableWSGIServer.create(
        app,
        host="localhost",
        port=http_port,
    )

    return app_wsgi


class FakeStopableWSGIServer(object):
    # used to mock interface for `StopableWSGIServer`
    def shutdown(self):
        pass


def _create_public_server__fake(settings: Dict) -> FakeStopableWSGIServer:
    # used to mock interface for `StopableWSGIServer`
    fake_wsgi = FakeStopableWSGIServer()
    return fake_wsgi


def routine__order_missing(
    ctx: "ApiContext",
    settings: Dict,
    create_public_server: Callable = _create_public_server,
    DEBUG: Optional[bool] = False,
) -> Tuple[Optional[int], Optional[int]]:
    """
    returns a tuple of:
        (count_success, count_failures)

    if no attempts are made:

        returns a tuple of:
            (None, None)
    """

    RENEWAL_RUN: str = "OrderMissing[%s]" % ctx.timestamp

    q__backup = (
        ctx.dbSession.query(model_objects.RenewalConfiguration)
        .outerjoin(
            model_objects.AcmeOrder,
            sqlalchemy_and(
                model_objects.RenewalConfiguration.id
                == model_objects.AcmeOrder.renewal_configuration_id,
                model_objects.AcmeOrder.certificate_type_id
                == model_utils.CertificateType.MANAGED_BACKUP,
                model_objects.AcmeOrder.is_processing.is_not(True),
            ),
        )
        .outerjoin(
            model_objects.CertificateSigned,
            model_objects.AcmeOrder.certificate_signed_id
            == model_objects.CertificateSigned.id,
        )
        .filter(
            model_objects.RenewalConfiguration.is_active.is_(True),
            model_objects.RenewalConfiguration.acme_account_id__backup.is_not(None),
            sqlalchemy_or(
                model_objects.AcmeOrder.id.is_(None),
                sqlalchemy_and(
                    model_objects.AcmeOrder.id.is_not(None),
                    model_objects.AcmeOrder.certificate_signed_id.is_(None),
                ),
            ),
        )
    )
    dbRenewalConfigurations__backup = q__backup.all()

    q__primary = (
        ctx.dbSession.query(model_objects.RenewalConfiguration)
        .outerjoin(
            model_objects.AcmeOrder,
            sqlalchemy_and(
                model_objects.RenewalConfiguration.id
                == model_objects.AcmeOrder.renewal_configuration_id,
                model_objects.AcmeOrder.certificate_type_id
                == model_utils.CertificateType.MANAGED_PRIMARY,
                model_objects.AcmeOrder.is_processing.is_not(True),
            ),
        )
        .outerjoin(
            model_objects.CertificateSigned,
            model_objects.AcmeOrder.certificate_signed_id
            == model_objects.CertificateSigned.id,
        )
        .filter(
            model_objects.RenewalConfiguration.is_active.is_(True),
            model_objects.RenewalConfiguration.acme_account_id__primary.is_not(None),
            sqlalchemy_or(
                model_objects.AcmeOrder.id.is_(None),
                sqlalchemy_and(
                    model_objects.AcmeOrder.id.is_not(None),
                    model_objects.AcmeOrder.certificate_signed_id.is_(None),
                ),
            ),
        )
    )
    dbRenewalConfigurations__primary = q__primary.all()

    def _debug_results():
        print("----")
        print("dbRenewalConfigurations__backup:")
        for r in dbRenewalConfigurations__backup:
            print(
                "RC:%s" % r.id,
            )
        print("----")
        print("dbRenewalConfigurations__primary:")
        for r in dbRenewalConfigurations__primary:
            print(
                "RC:%s" % r.id,
            )

    if DEBUG:
        _debug_results()
        pdb.set_trace()
        print("routine__order_missing")

    if not dbRenewalConfigurations__backup and not dbRenewalConfigurations__primary:
        return None, None

    count_renewals = 0
    count_failures = 0
    wsgi_server = create_public_server(settings)
    try:  # outer `try` block is to ensure we invoke `wsgi_server.shutdown()`

        def _order_missing(
            _dbRenewalConfiguration: "RenewalConfiguration",
            replaces_certificate_type: model_utils.CertificateType_Enum,
        ):
            nonlocal count_renewals
            nonlocal count_failures

            certificate_concept: str
            if (
                replaces_certificate_type
                == model_utils.CertificateType_Enum.MANAGED_BACKUP
            ):
                certificate_concept = "backup"
            elif (
                replaces_certificate_type
                == model_utils.CertificateType_Enum.MANAGED_PRIMARY
            ):
                certificate_concept = "primary"
            else:
                raise ValueError(
                    "unsuppored `replaces_certificate_type`: %s"
                    % replaces_certificate_type
                )

            log.debug(
                "No %s Certificate for: %s",
                (certificate_concept, _dbRenewalConfiguration.id),
            )
            log.debug(
                "Ordering a %s for RenewalConfiguration: %s",
                (certificate_concept, _dbRenewalConfiguration.id),
            )
            try:
                dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    dbRenewalConfiguration=_dbRenewalConfiguration,
                    processing_strategy="process_single",
                    acme_order_type_id=model_utils.AcmeOrderType.RENEWAL_CONFIGURATION_AUTOMATED,
                    note=RENEWAL_RUN,
                    replaces=certificate_concept,
                    replaces_type=model_utils.ReplacesType_Enum.AUTOMATIC,
                    replaces_certificate_type=replaces_certificate_type,
                )
                log.debug("Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id)
                log.debug(
                    "Renewal Result: CertificateSigned: %s",
                    dbAcmeOrderNew.certificate_signed_id,
                )
                if DEBUG:

                    def _debug():
                        print("Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id)
                        print(
                            "Renewal Result: CertificateSigned: %s",
                            dbAcmeOrderNew.certificate_signed_id,
                        )

                    _debug()

                if dbAcmeOrderNew.certificate_signed_id:
                    count_renewals += 1
                else:
                    count_failures += 1

            except Exception as exc:
                log.critical(
                    "Exception `%s` when processing AcmeOrder for RenewalConfiguration[%s]"
                    % (exc, _dbRenewalConfiguration.id)
                )
                # TODO: how should we handle this?
                # raise or catch and continue?
                raise

        for _dbRenewalConfiguration in dbRenewalConfigurations__backup:
            _order_missing(
                _dbRenewalConfiguration,
                model_utils.CertificateType_Enum.MANAGED_BACKUP,
            )

        for _dbRenewalConfiguration in dbRenewalConfigurations__primary:
            _order_missing(
                _dbRenewalConfiguration,
                model_utils.CertificateType_Enum.MANAGED_PRIMARY,
            )

    finally:
        wsgi_server.shutdown()

    return count_renewals, count_failures


def routine__renew_expiring(
    ctx: "ApiContext",
    settings: Dict,
    create_public_server: Callable = _create_public_server,
    renewal_configuration_ids__only_process: Optional[Tuple[int]] = None,
    count_expected_configurations: Optional[int] = None,
    DEBUG: Optional[bool] = False,
) -> Tuple[Optional[int], Optional[int]]:
    """
    returns a tuple of:
        (count_success, count_failures)

    if no attempts are made:

        returns a tuple of:
            (None, None)
    """

    RENEWAL_RUN: str = "RenewExpiring[%s]" % ctx.timestamp

    # `get_CertificateSigneds_renew_now` will compute a buffer,
    # so we do not have to submit a `timestamp_max_expiry`
    expiring_certs = get.get_CertificateSigneds_renew_now(ctx)
    if renewal_configuration_ids__only_process:
        # use a temporary variable for easier debugging
        _expiring_certs = [
            i
            for i in expiring_certs
            if i.acme_order.renewal_configuration_id
            in renewal_configuration_ids__only_process
        ]
        if count_expected_configurations:
            try:
                assert len(_expiring_certs) == count_expected_configurations
            except Exception:
                print(
                    "EXPECTED %s GOT %s"
                    % (count_expected_configurations, len(_expiring_certs))
                )
                raise

                # all_certs = get.get_CertificateSigneds_renew_now(ctx)
                # for cert in all_certs: print(cert.id, cert.acme_order.renewal_configuration_id)
        expiring_certs = _expiring_certs

    def _debug_results():
        print("---")
        print("Expiring Certs @ ", ctx.timestamp)
        for cert in expiring_certs:
            print(cert.id, cert.timestamp_not_after)
        print("---")

    if DEBUG:
        _debug_results()
        pdb.set_trace()
        print("routine__renew_expiring")

    if not expiring_certs:
        return None, None

    count_renewals = 0
    count_failures = 0
    wsgi_server = create_public_server(settings)
    try:
        for dbCertificateSigned in expiring_certs:
            if not dbCertificateSigned.acme_order:
                log.debug("No RenewalConfiguration for: %s", dbCertificateSigned.id)
                continue
            log.debug(
                "Renewing... : %s with RenewalConfiguration : %s",
                (
                    dbCertificateSigned.id,
                    dbCertificateSigned.acme_order.renewal_configuration_id,
                ),
            )
            try:
                replaces_certificate_type = (
                    model_utils.CertificateType.to_CertificateType_Enum(
                        dbCertificateSigned.acme_order.certificate_type_id
                    )
                )
                dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    dbRenewalConfiguration=dbCertificateSigned.acme_order.renewal_configuration,
                    processing_strategy="process_single",
                    acme_order_type_id=model_utils.AcmeOrderType.RENEWAL_CONFIGURATION_AUTOMATED,
                    note=RENEWAL_RUN,
                    replaces=dbCertificateSigned.ari_identifier,
                    replaces_type=model_utils.ReplacesType_Enum.AUTOMATIC,
                    replaces_certificate_type=replaces_certificate_type,
                )
                log.debug("Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id)
                log.debug(
                    "Renewal Result: CertificateSigned: %s",
                    dbAcmeOrderNew.certificate_signed_id,
                )
                if DEBUG:

                    def _debug():
                        print("Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id)
                        print(
                            "Renewal Result: CertificateSigned: %s",
                            dbAcmeOrderNew.certificate_signed_id,
                        )

                    _debug()

                if dbAcmeOrderNew.certificate_signed_id:
                    count_renewals += 1
                else:
                    count_failures += 1
                ctx.pyramid_transaction_commit()
            except Exception as exc:
                log.critical("Exception %s when processing AcmeOrder" % exc)
                # TODO: How should these be handled?
                # should we raise to end the process, or catch this and continue?
                raise
    finally:
        wsgi_server.shutdown()

    return count_renewals, count_failures
