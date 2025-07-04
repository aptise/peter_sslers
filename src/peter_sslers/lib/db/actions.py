# stdlib
import datetime
import logging
import pprint
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
from ...lib.utils import url_to_server
from ...lib.utils_datetime import datetime_ari_timely
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
    from ...model.objects import RoutineExecution
    from ...model.objects import SystemConfiguration
    from ...model.objects import UniqueFQDNSet
    from ...model.utils import DomainsChallenged
    from ..context import ApiContext


# ==============================================================================

log = logging.getLogger("peter_sslers.lib.db")

# ------------------------------------------------------------------------------


DEBUG_CIN = False
DEBUG_CONCEPT = False


class FakeStopableWSGIServer(object):
    # used to mock interface for `StopableWSGIServer`
    def shutdown(self):
        pass


def _create_public_server(settings: Dict) -> StopableWSGIServer:
    """
    This is used to create a public WSGI server
    The public server DISABLES the admin routes

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


def _create_public_server__fake(settings: Dict) -> FakeStopableWSGIServer:
    # used to mock interface for `StopableWSGIServer`
    fake_wsgi = FakeStopableWSGIServer()
    return fake_wsgi


def acme_dns__ensure_accounts(
    ctx: "ApiContext",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[int, int]:
    """Checks `Domain`s that need acme-dns accounts. Creates accounts if needed.

    Returns a tuple of (accounts_existing:int, accounts_new:int)
    """
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    accounts_existing = 0
    accounts_new = 0

    results = (
        ctx.dbSession.query(model_objects.RenewalConfiguration)
        .join(
            model_objects.UniquelyChallengedFQDNSet2Domain,
            model_objects.RenewalConfiguration.uniquely_challenged_fqdn_set_id
            == model_objects.UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id,
        )
        .join(
            model_objects.Domain,
            model_objects.UniquelyChallengedFQDNSet2Domain.domain_id
            == model_objects.Domain.id,
        )
        .join(
            model_objects.AcmeDnsServerAccount,
            model_objects.Domain.id == model_objects.AcmeDnsServerAccount.domain_id,
            isouter=True,
        )
        .filter(
            model_objects.UniquelyChallengedFQDNSet2Domain.acme_challenge_type_id
            == model_utils.AcmeChallengeType.dns_01,
        )
        .all()
    )
    for rc in results:
        for to_domain in rc.uniquely_challenged_fqdn_set.to_domains__dns_01:
            if False:
                print("===")
                print(to_domain.domain.domain_name)
                print(to_domain.domain.acme_dns_server_account__active)
            if to_domain.domain.acme_dns_server_account__active:
                accounts_existing += 1
            else:
                print(
                    "ensure_Domain_to_AcmeDnsServer: %s" % to_domain.domain.domain_name
                )
                _dbAcmeDnsServerAccount = (
                    lib_db.associate.ensure_Domain_to_AcmeDnsServer(
                        ctx,
                        to_domain.domain,
                        ctx.dbAcmeDnsServer_GlobalDefault,
                        discovery_type="via acme_dns_server._ensure_domains__submit",
                    )
                )
                accounts_new += 1
                ctx.pyramid_transaction_commit()

    return accounts_existing, accounts_new


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
    transaction_commit: Optional[bool] = None,
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
    if not transaction_commit:
        raise errors.AcknowledgeTransactionCommitRequired(
            "MUST persist external system data."
        )
    # validate this first!
    # dbSystemConfiguration = ctx._load_SystemConfiguration_cin()
    if not dbSystemConfiguration or not dbSystemConfiguration.is_configured:
        raise errors.DisplayableError(
            "the `certificate-if-needed` SystemConfiguration is not configured"
        )

    if DEBUG_CIN:
        print("api_domains__certificate_if_needed")
        pprint.pprint(locals())

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

    if DEBUG_CIN:
        print("domain_names", domain_names)

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

        if DEBUG_CIN:
            print("commiting for domain work")
            print("_result")
            pprint.pprint(_result)
            print("_logger_args")
            pprint.pprint(_logger_args)

        # do commit, just because we may have created a domain; also, logging!
        ctx.pyramid_transaction_commit()

        # look for a certificate
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
                    transaction_commit=True,
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

                elif isinstance(exc, errors.AcmeError):
                    _result["error"] = "Could not process AcmeOrder, %s" % str(exc)
                    _result["certificate_signed.status"] = "fail"
                    _logger_args["event_status_id"] = (
                        model_utils.OperationsObjectEventStatus.from_string(
                            "ApiDomains__certificate_if_needed__certificate_new_fail"
                        )
                    )
                elif isinstance(exc, errors.DuplicateAcmeOrder):
                    _result["error"] = "Could not process AcmeOrder, %s" % exc.args[0]
                    _result["certificate_signed.status"] = "fail"

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
            model_objects.CertificateCA.cert_issuer_uri.is_not(None),
            model_objects.CertificateCA.cert_issuer__reconciled.is_not(True),
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
        (
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
        .subquery()
        .as_scalar()
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
        (
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
        .subquery()
        .as_scalar()
    )
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
        (
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
        .subquery()
        .as_scalar()
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
        (
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
        .subquery()
        .as_scalar()
    )
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
        (
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
                CertificateSignedChain2.id
                == CertificateSignedChain2.certificate_signed_id,
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
        .subquery()
        .as_scalar()
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
        .as_scalar()
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
        .as_scalar()
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
        .as_scalar()
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
            model_objects.AcmeOrder.certificate_signed_id.is_not(None),
        )
        .subquery()
        .as_scalar()
    )
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

        server = url_to_server(item["directory_url"])

        def _new_AcmeServer():
            # TODO: migrate to create.create__AcmeServer
            dbObject = model_objects.AcmeServer()
            dbObject.is_unlimited_pending_authz = item.get(
                "is_unlimited_pending_authz", None
            )
            dbObject.timestamp_created = ctx.timestamp
            dbObject.name = item["name"]
            dbObject.directory_url = item["directory_url"]
            dbObject.protocol = item["protocol"]
            dbObject.is_supports_ari__version = item.get(
                "is_supports_ari__version", None
            )
            dbObject.is_retry_challenges = item.get("is_retry_challenges", None)
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


def routine__clear_old_ari_checks(ctx: "ApiContext") -> "RoutineExecution":
    """
    clear from the database outdated ARI checks.
    An ARI check is considered outdated once it has been replaced with a newer ARI check.
    """
    # iterate over all the CertificateSigned - windowed query of 100
    # criteria: no ari check, ari_check expired
    # run & store ari check

    # don't rely on ctx.timestamp, as it can be old
    # also, we need to time the routine
    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)

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

    # note this is still a query
    latest_ari_ids = ctx.dbSession.query(latest_ari_checks.c.latest_ari_id)

    # grab the count
    count_old_checks = (
        ctx.dbSession.query(AriCheck).filter(AriCheck.id.not_in(latest_ari_ids)).count()
    )
    count_records_success = count_old_checks

    stmt = sqlalchemy.delete(AriCheck).where(AriCheck.id.not_in(latest_ari_ids))
    result = ctx.dbSession.execute(stmt)
    ctx.pyramid_transaction_commit()

    TIMESTAMP_routine_end = datetime.datetime.now(datetime.timezone.utc)

    dbRoutineExecution = lib_db.create.create__RoutineExecution(
        ctx,
        routine_id=model_utils.Routine.routine__clear_old_ari_checks,
        timestamp_start=TIMESTAMP_routine_start,
        timestamp_end=TIMESTAMP_routine_end,
        count_records_success=count_records_success,
        count_records_fail=0,
    )
    ctx.pyramid_transaction_commit()

    return dbRoutineExecution


def routine__run_ari_checks(ctx: "ApiContext") -> "RoutineExecution":
    """
    Run ARI checks for certificates that require one
    * no ARI check logged
    * current time is after the latest ARI check's retry-after
    """
    # iterate over all the CertificateSigned - windowed query of 100
    # criteria: no ari check, ari_check expired
    # run & store ari check

    # don't rely on ctx.timestamp, as it can be old
    # also, we need to time the routine
    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)

    # the max_expiry will be in the future, to ensure we check ARI of anything
    # that expires until the next routine invocation
    timestamp_max_expiry = datetime_ari_timely(
        ctx, datetime_now=TIMESTAMP_routine_start, context="routine__run_ari_checks"
    )
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
        cert.timestamp_not_after <= datetime()
        AND
        (
            latest_ari_checks.latest_ari_id IS NULL
            OR
            latest_ari_checks.timestamp_retry_after <= datetime()
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
        ctx.dbSession.query(
            CertificateSigned,
            latest_ari_checks.c.latest_ari_id,
            # latest_ari_checks.c.timestamp_retry_after,
        )
        .outerjoin(
            latest_ari_checks,
            CertificateSigned.id == latest_ari_checks.c.certificate_signed_id,
        )
        .filter(
            CertificateSigned.is_active.is_(True),
            # these are considered expired
            CertificateSigned.timestamp_not_after <= timestamp_max_expiry,
            sqlalchemy_or(
                CertificateSigned.is_ari_supported__cert.is_(True),
                CertificateSigned.is_ari_supported__order.is_(True),
            ),
            sqlalchemy_or(
                latest_ari_checks.c.latest_ari_id.is_(None),
                # <= : select items that have expired
                latest_ari_checks.c.timestamp_retry_after <= timestamp_max_expiry,
            ),
        )
        .order_by(
            CertificateSigned.id.desc(),
            latest_ari_checks.c.latest_ari_id.desc(),
        )
        .all()
    )

    count_records_success = 0
    count_records_fail = 0
    for dbCertificateSigned, latest_ari_id in certs:
        log.debug(
            "Running ARI Check for : %s [%s]"
            % (dbCertificateSigned.id, dbCertificateSigned.cert_serial)
        )
        try:
            dbAriObject, ari_check_result = actions_acme.do__AcmeV2_AriCheck(
                ctx,
                dbCertificateSigned=dbCertificateSigned,
                force_check=True,  # a potential delay exists after above SQL
            )
            count_records_success += 1
            ctx.pyramid_transaction_commit()
        except errors.AcmeAriCheckDeclined as exc:
            count_records_fail += 1
            log.info(exc)
        except Exception as exc:
            count_records_fail += 1
            log.critical(exc)
            print(exc)

    TIMESTAMP_routine_end = datetime.datetime.now(datetime.timezone.utc)
    dbRoutineExecution = lib_db.create.create__RoutineExecution(
        ctx,
        routine_id=model_utils.Routine.routine__run_ari_checks,
        timestamp_start=TIMESTAMP_routine_start,
        timestamp_end=TIMESTAMP_routine_end,
        count_records_success=count_records_success,
        count_records_fail=count_records_fail,
    )
    ctx.pyramid_transaction_commit()

    return dbRoutineExecution


def routine__order_missing(
    ctx: "ApiContext",
    settings: Dict,
    create_public_server: Callable = _create_public_server,
    renewal_configuration_ids__only_process: Optional[Tuple[int, ...]] = None,
    dry_run: bool = False,
    limit: Optional[int] = None,
    DEBUG_LOCAL: Optional[bool] = False,
) -> "RoutineExecution":
    """
    returns "RoutineExecution" which contains
        (count_records_success, count_records_fail)

    """
    # don't rely on ctx.timestamp, as it can be old
    # also, we need to time the routine
    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)

    RENEWAL_RUN: str = "OrderMissing[%s]" % TIMESTAMP_routine_start

    subq__backup = (
        sqlalchemy.select(model_objects.AcmeOrder)
        .filter(
            model_objects.AcmeOrder.renewal_configuration_id
            == model_objects.RenewalConfiguration.id,
            model_objects.AcmeOrder.certificate_type_id
            == model_utils.CertificateType.MANAGED_BACKUP,
            model_objects.AcmeOrder.is_processing.is_not(True),
        )
        .exists()
    )
    q__backup = (
        ctx.dbSession.query(model_objects.RenewalConfiguration)
        .where(~subq__backup)
        .filter(
            model_objects.RenewalConfiguration.is_active.is_(True),
            model_objects.RenewalConfiguration.acme_account_id__backup.is_not(None),
        )
    )
    if renewal_configuration_ids__only_process:
        q__backup = q__backup.filter(
            model_objects.RenewalConfiguration.id.in_(
                renewal_configuration_ids__only_process
            )
        )
    if limit:
        q__backup = q__backup.order_by(model_objects.RenewalConfiguration.id.asc())
        q__backup = q__backup.limit(limit)
    dbRenewalConfigurations__backup = q__backup.all()

    subq__primary = (
        sqlalchemy.select(model_objects.AcmeOrder)
        .filter(
            model_objects.AcmeOrder.renewal_configuration_id
            == model_objects.RenewalConfiguration.id,
            model_objects.AcmeOrder.certificate_type_id
            == model_utils.CertificateType.MANAGED_PRIMARY,
            model_objects.AcmeOrder.is_processing.is_not(True),
        )
        .exists()
    )
    q__primary = (
        ctx.dbSession.query(model_objects.RenewalConfiguration)
        .where(~subq__primary)
        .filter(
            model_objects.RenewalConfiguration.is_active.is_(True),
            model_objects.RenewalConfiguration.acme_account_id__primary.is_not(None),
        )
    )
    if renewal_configuration_ids__only_process:
        q__primary = q__primary.filter(
            model_objects.RenewalConfiguration.id.in_(
                renewal_configuration_ids__only_process
            )
        )
    if limit:
        q__primary = q__primary.order_by(model_objects.RenewalConfiguration.id.asc())
        q__primary = q__primary.limit(limit)
    dbRenewalConfigurations__primary = q__primary.all()

    def _debug_results():
        print("----")
        print("dbRenewalConfigurations__backup:")
        for r in dbRenewalConfigurations__backup:
            print(
                "RC:%s %s" % (r.id, ("[%s]" % r.label if r.label else "")),
            )
            print("\t", r.acme_account__backup.acme_server.name)
            print("\t", r.domains_as_string)
        print("----")
        print("dbRenewalConfigurations__primary:")
        for r in dbRenewalConfigurations__primary:
            print(
                "RC:%s %s" % (r.id, ("[%s]" % r.label if r.label else "")),
            )
            print("\t", r.acme_account__primary.acme_server.name)
            print("\t", r.domains_as_string)
            print("-")
            print(r.acme_account_id__primary)

    if DEBUG_LOCAL or dry_run:
        print("*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~")
        print("routine__order_missing")
        print("*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~")
        _debug_results()
        # pdb.set_trace()

    count_renewals = 0
    count_failures = 0
    if dbRenewalConfigurations__backup or dbRenewalConfigurations__primary:

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
                    if dry_run:
                        count_renewals += 1
                        return False

                    dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                        ctx,
                        dbRenewalConfiguration=_dbRenewalConfiguration,
                        processing_strategy="process_single",
                        acme_order_type_id=model_utils.AcmeOrderType.RENEWAL_CONFIGURATION_AUTOMATED,
                        note=RENEWAL_RUN,
                        replaces=certificate_concept,
                        replaces_type=model_utils.ReplacesType_Enum.AUTOMATIC,
                        replaces_certificate_type=replaces_certificate_type,
                        transaction_commit=True,
                    )
                    log.debug("Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id)
                    log.debug(
                        "Renewal Result: CertificateSigned: %s",
                        dbAcmeOrderNew.certificate_signed_id,
                    )
                    if DEBUG_LOCAL or dry_run:

                        def _debug():
                            print("Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id)
                            print(
                                "Renewal Result: CertificateSigned: %s",
                                dbAcmeOrderNew.certificate_signed_id,
                            )

                        _debug()

                    if dbAcmeOrderNew.certificate_signed_id:
                        count_renewals += 1
                        return True
                    else:
                        count_failures += 1
                        return False

                except errors.AcmeServerErrorExistingRatelimit as exc:
                    # raise errors.AcmeServerErrorExistingRatelimit("ACME Account")
                    # raise errors.AcmeServerErrorExistingRatelimit("ACME Server")
                    # raise errors.AcmeServerErrorExistingRatelimit("ACME Server + Domain(s)")
                    log.critical(
                        "Exception `AcmeServerErrorExistingRatelimit(%s)` when processing AcmeOrder for RenewalConfiguration[%s]"
                        % (exc.args[0], _dbRenewalConfiguration.id)
                    )
                    if "ACME Account" in exc.args[0]:
                        if (
                            replaces_certificate_type
                            == model_utils.CertificateType_Enum.MANAGED_PRIMARY
                        ):
                            print(
                                "AcmeAccount.id=",
                                _dbRenewalConfiguration.acme_account_id__primary,
                            )
                        if (
                            replaces_certificate_type
                            == model_utils.CertificateType_Enum.MANAGED_BACKUP
                        ):
                            print(
                                "AcmeAccount.id=",
                                _dbRenewalConfiguration.acme_account_id__backup,
                            )
                    if "ACME Server" in exc.args[0]:
                        if (
                            replaces_certificate_type
                            == model_utils.CertificateType_Enum.MANAGED_PRIMARY
                        ):
                            print(
                                "AcmeServer.id=",
                                _dbRenewalConfiguration.acme_account__primary.acme_server_id,
                            )
                        if (
                            replaces_certificate_type
                            == model_utils.CertificateType_Enum.MANAGED_BACKUP
                        ):
                            print(
                                "AcmeServer.id=",
                                _dbRenewalConfiguration.acme_account__backup.acme_server_id,
                            )
                    if "Domain(s)" in exc.args[0]:
                        print("Domain(s)=", _dbRenewalConfiguration.domains_as_string)

                    # TODO: how should we handle this?
                    # raise or catch and continue?
                    count_failures += 1
                    return False

                except Exception as exc:
                    log.critical(
                        "Exception `%s` when processing AcmeOrder for RenewalConfiguration[%s]"
                        % (exc, _dbRenewalConfiguration.id)
                    )
                    # TODO: how should we handle this?
                    # raise or catch and continue?
                    count_failures += 1
                    return False

            total_runs = 0

            for _dbRenewalConfiguration in dbRenewalConfigurations__backup:
                _order_missing(
                    _dbRenewalConfiguration,
                    model_utils.CertificateType_Enum.MANAGED_BACKUP,
                )
                total_runs += 1
                if limit and total_runs >= limit:
                    break

            for _dbRenewalConfiguration in dbRenewalConfigurations__primary:
                _order_missing(
                    _dbRenewalConfiguration,
                    model_utils.CertificateType_Enum.MANAGED_PRIMARY,
                )
                total_runs += 1
                if limit and total_runs >= limit:
                    break

        finally:
            wsgi_server.shutdown()

    TIMESTAMP_routine_end = datetime.datetime.now(datetime.timezone.utc)
    dbRoutineExecution = lib_db.create.create__RoutineExecution(
        ctx,
        routine_id=model_utils.Routine.routine__order_missing,
        timestamp_start=TIMESTAMP_routine_start,
        timestamp_end=TIMESTAMP_routine_end,
        count_records_success=count_renewals,
        count_records_fail=count_failures,
        is_dry_run=dry_run,
    )
    ctx.pyramid_transaction_commit()

    return dbRoutineExecution


def routine__reconcile_blocks(
    ctx: "ApiContext",
    settings: Dict,
    create_public_server: Callable = _create_public_server,
    dry_run: bool = False,
    transaction_commit: Optional[bool] = None,
) -> "RoutineExecution":
    """
    Reconcile blocks

    TODO: integrate some of this with:
        route_name="admin:acme_orders:active:acme_server:sync",

    """
    # iterate over pending acme-orders, try to sync/etc

    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)

    # FIRST, sync ALL active orders
    #
    # TODO: batch this with limits and offsets?
    items_paged = lib_db.get.get__AcmeOrder__paginated(
        ctx,
        active_only=True,
        limit=None,
        offset=0,
    )
    _order_ids_pass = []
    _order_ids_fail = []
    if dry_run:
        _order_ids_pass = [dbAcmeOrder.id for dbAcmeOrder in items_paged]
        for dbAcmeOrder in items_paged:
            print("Sync ACME Order | %s" % dbAcmeOrder.id)
    else:
        for dbAcmeOrder in items_paged:
            dbAcmeOrder = ctx.dbSession.merge(dbAcmeOrder)
            log.debug("Syncing ACME Order | %s" % (dbAcmeOrder.id,))
            try:
                dbAcmeOrder = actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
                    ctx,
                    dbAcmeOrder=dbAcmeOrder,
                    transaction_commit=transaction_commit,
                )
                _order_ids_pass.append(dbAcmeOrder.id)
                ctx.pyramid_transaction_commit()
            except Exception as exc:
                _order_ids_fail.append(dbAcmeOrder.id)
                log.critical(
                    "Exception when syncing AcmeOrder[%s]: %s" % (dbAcmeOrder.id, exc)
                )
                print(exc)

    items_paged = lib_db.get.get__AcmeOrder__paginated(
        ctx,
        active_only=True,
        limit=None,
        offset=0,
    )
    if items_paged:
        if dry_run:
            for dbAcmeOrder in items_paged:
                if dbAcmeOrder.is_can_acme_process:
                    print("AcmeOrder.is_can_acme_process | %s" % dbAcmeOrder.id)
                elif dbAcmeOrder.is_can_acme_finalize:
                    print("AcmeOrder.is_can_acme_finalize | %s" % dbAcmeOrder.id)
                else:
                    continue
                _order_ids_pass.append(dbAcmeOrder.id)
        else:
            # SECOND
            # perhaps only do on `_order_ids_pass`
            wsgi_server = create_public_server(settings)
            try:
                for dbAcmeOrder in items_paged:
                    dbAcmeOrder = ctx.dbSession.merge(dbAcmeOrder)
                    if (not dbAcmeOrder.is_can_acme_process) and not (
                        dbAcmeOrder.is_can_acme_finalize
                    ):
                        continue
                    log.debug(
                        "Attempting Continuation of ACME Order %s" % (dbAcmeOrder.id,)
                    )
                    try:
                        while True:
                            if dbAcmeOrder.is_can_acme_process:
                                dbAcmeOrder = (
                                    actions_acme.do__AcmeV2_AcmeOrder__process(
                                        ctx,
                                        dbAcmeOrder=dbAcmeOrder,
                                        transaction_commit=True,
                                    )
                                )
                            elif dbAcmeOrder.is_can_acme_finalize:
                                dbAcmeOrder = (
                                    lib_db.actions_acme.do__AcmeV2_AcmeOrder__finalize(
                                        ctx,
                                        dbAcmeOrder=dbAcmeOrder,
                                        transaction_commit=transaction_commit,
                                    )
                                )
                            else:
                                break
                        _order_ids_pass.append(dbAcmeOrder.id)
                        ctx.pyramid_transaction_commit()
                    except Exception as exc:
                        _order_ids_fail.append(dbAcmeOrder.id)
                        log.critical(
                            "Exception when continuing AcmeOrder[%s]: %s"
                            % (dbAcmeOrder.id, exc)
                        )
                        print(exc)
            finally:
                wsgi_server.shutdown()

    _order_ids_pass = list(set(_order_ids_pass))
    _order_ids_fail = list(set(_order_ids_fail))

    TIMESTAMP_routine_end = datetime.datetime.now(datetime.timezone.utc)
    dbRoutineExecution = lib_db.create.create__RoutineExecution(
        ctx,
        routine_id=model_utils.Routine.routine__reconcile_blocks,
        timestamp_start=TIMESTAMP_routine_start,
        timestamp_end=TIMESTAMP_routine_end,
        count_records_success=len(_order_ids_pass),
        count_records_fail=len(_order_ids_fail),
        is_dry_run=dry_run,
    )
    ctx.pyramid_transaction_commit()

    return dbRoutineExecution


def routine__renew_expiring(
    ctx: "ApiContext",
    settings: Dict,
    create_public_server: Callable = _create_public_server,
    renewal_configuration_ids__only_process: Optional[Tuple[int, ...]] = None,
    count_expected_configurations: Optional[int] = None,
    dry_run: bool = False,
    limit: Optional[int] = None,
    DEBUG_LOCAL: Optional[bool] = False,
) -> "RoutineExecution":
    """
    returns "RoutineExecution" which contains
        (count_records_success, count_records_fail)

    """
    # don't rely on ctx.timestamp, as it can be old
    # also, we need to time the routine
    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)

    RENEWAL_RUN: str = "RenewExpiring[%s]" % TIMESTAMP_routine_start

    # `get_CertificateSigneds_renew_now` will compute a buffer,
    # so we do not have to submit a `timestamp_max_expiry`
    expiring_certs = get.get_CertificateSigneds_renew_now(ctx, limit=limit)

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
                print("routine__renew_expiring(")
                print(
                    "\tEXPECTED %s GOT %s"
                    % (count_expected_configurations, len(_expiring_certs))
                )
                for rc_id in renewal_configuration_ids__only_process:
                    print("\t\tRenewalConfiguration: [%s]" % rc_id)
                    rcCerts = get.get__CertificateSigned__by_RenewalConfigurationId__paginated(
                        ctx, rc_id
                    )
                    for dbCert in rcCerts:
                        print(
                            "\t\t\tCertificateSigned[%s]" % dbCert.id,
                            dbCert.timestamp_not_after,
                        )
                raise
                # Debugging Info
                #
                # for cert in expiring_certs: print(cert.id, cert.acme_order.renewal_configuration_id)
                #
                # all_certs = get.get_CertificateSigneds_renew_now(ctx)
                # all_certs = get.get_CertificateSigneds_renew_now(ctx, datetime.datetime.now(datetime.timezone.utc))
                #
                # for cert in all_certs: print(cert.id, cert.acme_order.renewal_configuration_id)
        expiring_certs = _expiring_certs

    def _debug_results():
        print("---")
        print("Expiring Certs @ ", ctx.timestamp)
        for cert in expiring_certs:
            print(
                "cert:",
                cert.id,
                "rc:",
                cert.acme_order.renewal_configuration_id if cert.acme_order else None,
                "notAfter:",
                cert.timestamp_not_after,
                "issuer:",
                (
                    cert.cert_issuer.replace(" ", "_").replace("\n", ";")
                    if cert.cert_issuer
                    else ""
                ),
            )
            print("\t", cert.domains_as_string)
        print("---")

    if DEBUG_LOCAL or dry_run:
        print("*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~")
        print("routine__renew_expiring")
        print("*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~")
        _debug_results()
        # pdb.set_trace()

    count_renewals = 0
    count_failures = 0
    if expiring_certs:
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
                if dry_run:
                    count_renewals += 1
                else:
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
                            transaction_commit=True,
                        )
                        log.debug("Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id)
                        log.debug(
                            "Renewal Result: CertificateSigned: %s",
                            dbAcmeOrderNew.certificate_signed_id,
                        )
                        if DEBUG_LOCAL or dry_run:

                            def _debug():
                                print(
                                    "Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id
                                )
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
                        count_failures += 1
        finally:
            wsgi_server.shutdown()

    TIMESTAMP_routine_end = datetime.datetime.now(datetime.timezone.utc)
    dbRoutineExecution = lib_db.create.create__RoutineExecution(
        ctx,
        routine_id=model_utils.Routine.routine__renew_expiring,
        timestamp_start=TIMESTAMP_routine_start,
        timestamp_end=TIMESTAMP_routine_end,
        count_records_success=count_renewals,
        count_records_fail=count_failures,
        is_dry_run=dry_run,
    )
    ctx.pyramid_transaction_commit()

    return dbRoutineExecution


def unset_acme_server_caches(
    ctx: "ApiContext",
    transaction_commit: Optional[bool] = None,
) -> "RoutineExecution":
    """
    Unsets the following cached information markers::

    * AcmeAccount.timestamp_last_authenticated
    * AcmeServerConfiguration.timestamp_lastchecked
      - AcmeServer.directory_latest.timestamp_lastchecked

    Unsetting these should trigger active reloads to the cache.

    Originally designed for tests, this was exported to a library function and
    commandline tool.
    """
    if not transaction_commit:
        raise errors.AcknowledgeTransactionCommitRequired(
            "MUST persist external system data."
        )

    # don't rely on ctx.timestamp, as it can be old
    # also, we need to time the routine
    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)

    RENEWAL_RUN: str = "UnsetAcmeServerCaches[%s]" % TIMESTAMP_routine_start

    # used to reset::
    # `model_objects.AcmeServerConfiguration.timestamp_lastchecked TIMESTAMP NOT NULL`
    one_year_ago = TIMESTAMP_routine_start - datetime.timedelta(days=365)

    dbAcmeAccounts = ctx.dbSession.query(model_objects.AcmeAccount).all()
    for _dbAcmeAccount in dbAcmeAccounts:
        _dbAcmeAccount.timestamp_last_authenticated = None

    dbAcmeServers = ctx.dbSession.query(model_objects.AcmeServer).all()
    for _dbAcmeServer in dbAcmeServers:
        _dbAcmeServer.profiles = None
        if _dbAcmeServer.directory_latest:
            _dbAcmeServer.directory_latest.timestamp_lastchecked = one_year_ago

    ctx.pyramid_transaction_commit()

    TIMESTAMP_routine_end = datetime.datetime.now(datetime.timezone.utc)
    dbRoutineExecution = lib_db.create.create__RoutineExecution(
        ctx,
        routine_id=model_utils.Routine.unset_acme_server_caches,
        timestamp_start=TIMESTAMP_routine_start,
        timestamp_end=TIMESTAMP_routine_end,
    )
    ctx.pyramid_transaction_commit()

    return dbRoutineExecution
