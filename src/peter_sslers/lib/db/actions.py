# stdlib
import datetime
import logging
import pprint
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

# pypi
import cert_utils
import requests
import sqlalchemy
from sqlalchemy import or_ as sqlalchemy_or
from sqlalchemy import SQLColumnExpression
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.sql.selectable import ScalarSelect
from typing_extensions import Literal
from typing_extensions import Protocol

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
from ...model.objects import RootStore
from ...model.objects import RootStoreVersion
from ...model.objects import RootStoreVersion_2_X509CertificateTrusted
from ...model.objects import X509Certificate
from ...model.utils import AcmeServerInput

if TYPE_CHECKING:
    from requests.structures import CaseInsensitiveDict

    from ..context import ApiContext
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeOrder
    from ...model.objects import Domain
    from ...model.objects import OperationsEvent
    from ...model.objects import PrivateKey
    from ...model.objects import RoutineExecution
    from ...model.objects import SystemConfiguration
    from ...model.objects import UniqueFQDNSet
    from ...model.utils import DomainsChallenged


# ==============================================================================

log = logging.getLogger("peter_sslers.lib.db")

# ------------------------------------------------------------------------------


DEBUG_CIN = False
DEBUG_CONCEPT = False


class _PublicServer(Protocol):
    def shutdown(self) -> Optional[bool]:
        """Stop the temporary public challenge server."""
        ...


class FakeStopableWSGIServer(object):
    # used to mock interface for `StopableWSGIServer`
    def shutdown(self) -> None:
        pass


def _create_public_server(settings: Dict[str, Any]) -> StopableWSGIServer:
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
    settings = settings.copy()
    pyramid_bools = (
        "pyramid.debug_authorization",
        "pyramid.debug_notfound",
        "pyramid.debug_routematch",
    )
    for field in pyramid_bools:
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


def _create_public_server__fake(settings: Dict[str, Any]) -> FakeStopableWSGIServer:
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
            == model_utils.AcmeChallenge_Type.dns_01,
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
    :param private_key_cycle__primary: (required)  A value from :class:`model.utils.PrivateKey_Cycle`
    :param private_key_technology__primary: (required)  A value from :class:`model.utils.PrivateKeyTechnology`
    :param acme_profile__primary: (optional)

    :param dbAcmeAccount__backup: (optional) A :class:`model.objects.AcmeAccount` object
    :param dbPrivateKey__backup: (optional) A :class:`model.objects.PrivateKey` object used to sign the request.
    :param acme_profile__backup: (optional)  str
    :param private_key_cycle__backup: (optional)  A value from :class:`model.utils.PrivateKey_Cycle`
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
    private_key_cycle_id__primary = model_utils.PrivateKey_Cycle.from_string(
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

        private_key_cycle_id__backup = model_utils.PrivateKey_Cycle.from_string(
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
            "x509_certificate.id": None,
            "x509_certificate.status": None,
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
        _dbX509Certificate = lib.db.get.get__X509Certificate__by_DomainId__latest(
            ctx, _dbDomain.id
        )
        if _dbX509Certificate:
            _result["x509_certificate.status"] = "exists"
            _result["x509_certificate.id"] = _dbX509Certificate.id
            _logger_args["event_status_id"] = (
                model_utils.OperationsObjectEventStatus.from_string(
                    "ApiDomains__certificate_if_needed__certificate_exists"
                )
            )
            _logger_args["dbX509Certificate"] = _dbX509Certificate
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
                        acme_challenge_duplicate_strategy_id=model_utils.AcmeChallenge_DuplicateStrategy.no_duplicates,
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
                    acme_order_type_id=model_utils.AcmeOrder_Type.CERTIFICATE_IF_NEEDED,
                    dbPrivateKey=dbPrivateKey__primary,
                    replaces_type=model_utils.ReplacesType_Enum.AUTOMATIC,
                    transaction_commit=True,
                )

                _logger_args["dbAcmeOrder"] = dbAcmeOrder
                _result["acme_order.id"] = dbAcmeOrder.id
                if dbAcmeOrder.x509_certificate_id:
                    _result["x509_certificate.status"] = "new"
                    _result["x509_certificate.id"] = dbAcmeOrder.x509_certificate_id
                    _logger_args["event_status_id"] = (
                        model_utils.OperationsObjectEventStatus.from_string(
                            "ApiDomains__certificate_if_needed__certificate_new_success"
                        )
                    )
                    _logger_args["dbX509Certificate"] = dbAcmeOrder.x509_certificate
                else:
                    _result["error"] = "AcmeOrder did not generate a X509Certificate"
                    _result["x509_certificate.status"] = "fail"
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
                    _result["x509_certificate.status"] = "fail"
                    _logger_args["event_status_id"] = (
                        model_utils.OperationsObjectEventStatus.from_string(
                            "ApiDomains__certificate_if_needed__certificate_new_fail"
                        )
                    )
                elif isinstance(exc, errors.DuplicateAcmeOrder):
                    _result["error"] = "Could not process AcmeOrder, %s" % exc.args[0]
                    _result["x509_certificate.status"] = "fail"

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
            "X509Certificate__deactivate_expired"
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
        ctx.dbSession.query(model_objects.X509Certificate)
        .filter(
            model_objects.X509Certificate.is_active.is_(True),
            model_objects.X509Certificate.timestamp_not_after < ctx.timestamp,
        )
        .order_by(model_objects.X509Certificate.timestamp_not_after.desc())
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
                model_objects.X509Certificate,
                model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id
                == model_objects.X509Certificate.unique_fqdn_set_id,
                isouter=True,
            )
            .filter(
                model_objects.X509Certificate.id == cert.id,
            )
            .all()
        )
        cert_ok = True
        for cert_domain in cert_domains:
            # if this Certificate is the latest Certificate for the domain, we can not turn it off
            if cert.id in (
                cert_domain.x509_certificate_id__latest_single,
                cert_domain.x509_certificate_id__latest_multi,
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
        event_payload_dict["x509_certificate.ids"] = deactivated_cert_ids
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


_header_2_format = {
    "application/pkcs7-mime": "pkcs7",
    "application/pkix-cert": "pkix-cert",
}


def _download_certificate(
    url: str,
    *,
    verify: Union[bool, str] = True,
    error_message: str = "Could not load certificate",
) -> Tuple[bytes, "CaseInsensitiveDict[str]"]:
    """Fetch certificate bytes without leaving connections or waits unbounded."""
    with requests.get(url, verify=verify, timeout=(3.05, 10)) as response:
        if response.status_code != 200:
            raise ValueError(error_message)
        return response.content, response.headers


def operations_reconcile_cas(
    ctx: "ApiContext",
) -> "OperationsEvent":
    """
    Tries to reconcile CAs.
    This involves checking to ensure the cert_issuer_uri is live and valid

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    assert ctx.timestamp
    dbX509CertificateTrusteds = (
        ctx.dbSession.query(model_objects.X509CertificateTrusted)
        .filter(
            model_objects.X509CertificateTrusted.cert_issuer_uri.is_not(None),
            model_objects.X509CertificateTrusted.cert_issuer__reconciled.is_not(True),
        )
        .all()
    )
    _x509_certificate_trusted_ids = []
    _x509_certificate_trusted_ids_fail = []
    for dbX509CertificateTrusted in dbX509CertificateTrusteds:
        log.debug("Reconciling CA...")
        _x509_certificate_trusted_ids.append(dbX509CertificateTrusted.id)
        cert_issuer_uri = dbX509CertificateTrusted.cert_issuer_uri
        log.debug(dbX509CertificateTrusted.cert_subject)
        log.debug(cert_issuer_uri)
        assert cert_issuer_uri
        try:
            content, headers = _download_certificate(cert_issuer_uri)
            content_type = headers.get("content-type")
            filetype = _header_2_format.get(content_type) if content_type else None
            cert_pems = None
            if filetype == "pkcs7":
                cert_pems = cert_utils.convert_pkcs7_to_pems(content)
            elif filetype == "pkix-cert":
                cert_pem = cert_utils.convert_der_to_pem(content)
                cert_pems = [
                    cert_pem,
                ]
            else:
                raise ValueError("Not Implemented: %s" % content_type)

            for cert_pem in cert_pems:
                cert_parsed = cert_utils.parse_cert(cert_pem)
                (
                    _dbX509CertificateTrustedReconciled,
                    _is_created,
                ) = getcreate.getcreate__X509CertificateTrusted__by_pem_text(
                    ctx,
                    cert_pem,
                    discovery_type="reconcile_cas",
                )
                # mark the first item as reconciled
                dbX509CertificateTrusted.cert_issuer__reconciled = True
                if (
                    not dbX509CertificateTrusted.cert_issuer__x509_certificate_trusted_id
                ):
                    dbX509CertificateTrusted.cert_issuer__x509_certificate_trusted_id = (
                        _dbX509CertificateTrustedReconciled.id
                    )
                else:
                    raise ValueError("Not Implemented: multiple reconciles")
                # mark the second item
                _reconciled_uris = _dbX509CertificateTrustedReconciled.reconciled_uris
                reconciled_uris = (
                    _reconciled_uris.split(" ") if _reconciled_uris else []
                )
                if cert_issuer_uri not in reconciled_uris:
                    reconciled_uris.append(cert_issuer_uri)
                    _reconciled_uris = " ".join(reconciled_uris)
                    _dbX509CertificateTrustedReconciled.reconciled_uris = (
                        _reconciled_uris
                    )

                dbX509CertificateTrustReconciliation = (
                    model_objects.X509CertificateTrustReconciliation()
                )
                dbX509CertificateTrustReconciliation.timestamp_operation = ctx.timestamp
                dbX509CertificateTrustReconciliation.x509_certificate_trusted_id = (
                    dbX509CertificateTrusted.id
                )
                dbX509CertificateTrustReconciliation.x509_certificate_trusted_id__issuer__reconciled = (
                    _dbX509CertificateTrustedReconciled.id
                )
                dbX509CertificateTrustReconciliation.result = True
                ctx.dbSession.add(dbX509CertificateTrustReconciliation)
        except Exception as exc:
            log.debug(
                "EXCEPTION - could not reconcile CA %s", dbX509CertificateTrusted.id
            )
            _x509_certificate_trusted_ids_fail.append(dbX509CertificateTrusted.id)

    event_payload_dict = lib.utils.new_event_payload_dict()
    event_payload_dict["x509_certificate_trusted.ids"] = _x509_certificate_trusted_ids
    if _x509_certificate_trusted_ids_fail:
        event_payload_dict["x509_certificate_trusted.ids_fail"] = (
            _x509_certificate_trusted_ids_fail
        )
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("operations__reconcile_cas"),
        event_payload_dict,
    )

    return dbOperationsEvent


def _refresh_domain_certificate_pointers(
    ctx: "ApiContext",
    domain_ids: Optional[List[int]] = None,
) -> None:
    """Refresh current certificate pointers without committing the transaction."""
    ctx.dbSession.flush()
    for suffix, single in (("single", True), ("multi", False)):
        selected = (
            sqlalchemy.select(model_objects.X509Certificate.id)
            .join(
                model_objects.UniqueFQDNSet2Domain,
                model_objects.X509Certificate.unique_fqdn_set_id
                == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
            )
            .where(
                model_objects.X509Certificate.is_active.is_(True),
                model_objects.X509Certificate.is_single_domain_cert.is_(single),
                model_objects.UniqueFQDNSet2Domain.domain_id == model_objects.Domain.id,
            )
            .order_by(
                model_objects.X509Certificate.timestamp_not_after.desc(),
                model_objects.X509Certificate.id.desc(),
            )
            .limit(1)
            .correlate(model_objects.Domain)
            .scalar_subquery()
        )
        statement = model_objects.Domain.__table__.update().values(
            {"x509_certificate_id__latest_" + suffix: selected}
        )
        if domain_ids is not None:
            statement = statement.where(model_objects.Domain.id.in_(domain_ids))
        ctx.dbSession.execute(statement)

    # Core updates do not synchronize ORM objects already held by the request.
    for domain in list(ctx.dbSession.identity_map.values()):
        if isinstance(domain, model_objects.Domain) and (
            domain_ids is None or domain.id in domain_ids
        ):
            ctx.dbSession.expire(domain, [
                "x509_certificate_id__latest_single", "x509_certificate_id__latest_multi",
                "x509_certificate__latest_single", "x509_certificate__latest_multi",
            ])


def operations_update_recents__domains(
    ctx: "ApiContext",
    dbDomains: Optional[Iterable["Domain"]] = None,
    dbUniqueFQDNSets: Optional[Iterable["UniqueFQDNSet"]] = None,
) -> "OperationsEvent":
    """
    Updates selected domains with current certificate pointers.

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomains: (optional) A list of :class:`model.objects.Domain` instances
    :param dbUniqueFQDNSets: (optional) A list of :class:`model.objects.UniqueFQDNSet` instances
    """
    # Materialize iterable inputs once: callers may supply generators.
    dbDomains = list(dbDomains) if dbDomains is not None else []
    dbUniqueFQDNSets = list(dbUniqueFQDNSets) if dbUniqueFQDNSets is not None else []
    if not dbDomains and not dbUniqueFQDNSets:
        raise ValueError("must submit at least one of `dbDomains` or `dbUniqueFQDNSets`")
    domain_id_set = {domain.id for domain in dbDomains}
    for fqdn_set in dbUniqueFQDNSets:
        domain_id_set.update(domain.id for domain in fqdn_set.domains)
    if not domain_id_set:
        raise ValueError("no Domains specified")
    domain_ids = sorted(domain_id_set)
    _unique_fqdn_set_ids = sorted({fqdn_set.id for fqdn_set in dbUniqueFQDNSets})

    _refresh_domain_certificate_pointers(ctx, domain_ids)

    # bookkeeping, doing this will mark the session as changed!
    event_payload_dict = lib.utils.new_event_payload_dict()
    event_payload_dict["domain.ids"] = domain_ids
    event_payload_dict["unique_fqdn_set.ids"] = _unique_fqdn_set_ids
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(
            "operations__update_recents__domains"
        ),
        event_payload_dict,
    )

    return dbOperationsEvent


def _reconcile_usage_counts(ctx: "ApiContext") -> None:
    """Rebuild usage counters without committing or retaining stale ORM values."""
    ctx.dbSession.flush()
    certificate = model_objects.X509Certificate
    key = model_objects.PrivateKey
    account = model_objects.AcmeAccount
    order = model_objects.AcmeOrder
    trusted = model_objects.X509CertificateTrusted
    association = model_objects.X509CertificateChain
    chain = model_objects.X509CertificateTrustChain

    def count_for(
        target: Union[type[model_objects.PrivateKey], type[model_objects.AcmeAccount]],
        source: Union[
            type[model_objects.X509Certificate], type[model_objects.AcmeOrder]
        ],
        foreign_key: SQLColumnExpression[Optional[int]],
        value: SQLColumnExpression[Optional[int]],
        *conditions: ColumnElement[bool],
    ) -> ScalarSelect[int]:
        return (
            sqlalchemy.select(sqlalchemy.func.count(value))
            .select_from(source)
            .where(foreign_key == target.id, *conditions)
            .correlate(target)
            .scalar_subquery()
        )

    trusted_count = (
        sqlalchemy.select(sqlalchemy.func.count(sqlalchemy.distinct(certificate.id)))
        .select_from(certificate)
        .join(association, association.x509_certificate_id == certificate.id)
        .join(chain, chain.id == association.x509_certificate_trust_chain_id)
        .where(
            certificate.is_active.is_(True),
            chain.x509_certificate_trusted_0_id == trusted.id,
        )
        .correlate(trusted)
        .scalar_subquery()
    )
    values: Dict[
        Union[
            type[model_objects.X509CertificateTrusted],
            type[model_objects.PrivateKey],
            type[model_objects.AcmeAccount],
        ],
        Dict[str, ScalarSelect[int]],
    ] = {
        trusted: {"count_active_certificates": trusted_count},
        key: {
            "count_active_certificates": count_for(
                key,
                certificate,
                certificate.private_key_id,
                certificate.id,
                certificate.is_active.is_(True),
            ),
            "count_x509_certificates": count_for(
                key, certificate, certificate.private_key_id, certificate.id
            ),
            "count_acme_orders": count_for(key, order, order.private_key_id, order.id),
        },
        account: {
            "count_acme_orders": count_for(
                account, order, order.acme_account_id, order.id
            ),
            "count_x509_certificates": count_for(
                account,
                order,
                order.acme_account_id,
                sqlalchemy.distinct(order.x509_certificate_id),
            ),
        },
    }
    for model, counters in values.items():
        ctx.dbSession.execute(model.__table__.update().values(**counters))
    for instance in list(ctx.dbSession.identity_map.values()):
        for model, counters in values.items():
            if isinstance(instance, model):
                ctx.dbSession.expire(instance, list(counters))
                break


def operations_update_recents__global(
    ctx: "ApiContext",
) -> "OperationsEvent":
    """
    updates all the objects to their most-recent relations

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    _refresh_domain_certificate_pointers(ctx)

    _reconcile_usage_counts(ctx)

    # TODO: should we do the timestamps?
    """
    UPDATE acme_account SET timestamp_last_x509_certificate_request = (
    SELECT MAX(timestamp_created) FROM x509_certificate_request
    WHERE x509_certificate_request.acme_account_id = acme_account.id);

    UPDATE acme_account SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_created) FROM x509_certificate
    WHERE x509_certificate.acme_account_id = acme_account.id);

    UPDATE private_key SET timestamp_last_x509_certificate_request = (
    SELECT MAX(timestamp_created) FROM x509_certificate_request
    WHERE x509_certificate_request.private_key_id = private_key.id);

    UPDATE private_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_created) FROM x509_certificate
    WHERE x509_certificate.private_key_id = private_key.id);
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

    ca_bundle_file = pebbleServer.local_ca_bundle(ctx) or False

    content, headers = _download_certificate(
        "https://127.0.0.1:15000/roots/0",
        verify=ca_bundle_file,
        error_message="Could not load first root",
    )
    root_pems = [content.decode("ascii")]
    alternates = acme_v2.get_header_links(headers, "alternate")
    for alternate in alternates:
        content, _ = _download_certificate(
            alternate,
            verify=ca_bundle_file,
            error_message="Could not load additional root",
        )
        root_pems.append(content.decode("ascii"))

    dbCACerts = []
    for _root_pem in root_pems:
        (
            _dbCACert,
            _is_created,
        ) = getcreate.getcreate__X509CertificateTrusted__by_pem_text(
            ctx,
            _root_pem,
            display_name="Detected Pebble Root",
            is_trusted_root=True,
            is_untrusted_root=True,
        )
        dbCACerts.append(_dbCACert)

    # touching this will generate if needed;
    # force_refresh will update
    pebbleServer.local_ca_bundle(ctx, force_refresh=True)
    return True


def refresh_roots(
    ctx: "ApiContext",
    dbOperationsEvent_child_of: Optional["OperationsEvent"] = None,
    include_deprecated: bool = False,
) -> Tuple["OperationsEvent", Dict]:
    """
    pebble uses a new ca_cert bundle each time it runs
    """
    log.info("refresh_roots")

    event_payload_dict = lib.utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("action__refresh_roots"),
        event_payload_dict,
        dbOperationsEvent_child_of=dbOperationsEvent_child_of,
    )

    # remove RootStoreVersion_2_X509CertificateTrusted
    subq = (
        ctx.dbSession.query(RootStoreVersion.id)
        .filter(RootStoreVersion.is_cert_utils_discovery.is_(True))
        .subquery()
    )
    ctx.dbSession.query(RootStoreVersion_2_X509CertificateTrusted).filter(
        RootStoreVersion_2_X509CertificateTrusted.root_store_version_id.in_(subq)
    ).delete(synchronize_session=False)

    # remove RootStoreVersion
    ctx.dbSession.query(RootStoreVersion).filter(
        RootStoreVersion.is_cert_utils_discovery.is_(True)
    ).delete(synchronize_session=False)

    # remove RootStore
    ctx.dbSession.query(RootStore).filter(
        RootStore.is_cert_utils_discovery.is_(True)
    ).delete(synchronize_session=False)

    # nestle this import, so we do not load it on every run
    from cert_utils.letsencrypt_info import certificates as letsencrypt_info

    certs = letsencrypt_info.CERT_CAS_DATA
    certs_order = letsencrypt_info._CERT_CAS_ORDER
    if include_deprecated:
        certs = {**certs, **letsencrypt_info.CERT_CAS_DEPRECATED}
        certs_order = certs_order + letsencrypt_info._CERT_CAS_DEPRECATED_ORDER

    # do a quick check
    _cert_ids = set(certs.keys())
    _cert_ids_order = set(certs_order)
    _missing_data = _cert_ids_order - _cert_ids
    if _missing_data:
        raise ValueError(
            "Missing from `letsencrypt_info.CERT_CAS_DATA`: %s" % _missing_data
        )
    _unordered = _cert_ids - _cert_ids_order
    if _unordered:
        raise ValueError(
            "Missing from `letsencrypt_info._CERT_CAS_ORDER`: %s" % _unordered
        )
    # end check

    certs_discovered = []
    certs_modified = []
    certs_lookup = {}  # stash the ones we create for a moment
    for cert_id in certs_order:
        cert_data = certs[cert_id]
        assert cert_data["cert_pem"]
        _is_created = False
        dbX509CertificateTrusted = get.get__X509CertificateTrusted__by_pem_text(
            ctx, cert_data["cert_pem"]
        )
        if not dbX509CertificateTrusted:
            is_trusted_root = cert_data.get("is_trusted_root")
            is_untrusted_root = cert_data.get("is_untrusted_root")
            (
                dbX509CertificateTrusted,
                _is_created,
            ) = getcreate.getcreate__X509CertificateTrusted__by_pem_text(
                ctx,
                cert_data["cert_pem"],
                display_name=cert_data["display_name"],
                is_trusted_root=is_trusted_root,
                is_untrusted_root=is_untrusted_root,
                discovery_type="initial setup",
            )
            if _is_created:
                certs_discovered.append(dbX509CertificateTrusted)
        if "is_trusted_root" in cert_data:
            if dbX509CertificateTrusted.is_trusted_root != cert_data["is_trusted_root"]:
                dbX509CertificateTrusted.is_trusted_root = cert_data["is_trusted_root"]
                if dbX509CertificateTrusted not in certs_discovered:
                    certs_modified.append(dbX509CertificateTrusted)
        elif "is_untrusted_root" in cert_data:
            if (
                dbX509CertificateTrusted.is_untrusted_root
                != cert_data["is_untrusted_root"]
            ):
                dbX509CertificateTrusted.is_untrusted_root = cert_data[
                    "is_untrusted_root"
                ]
                if dbX509CertificateTrusted not in certs_discovered:
                    certs_modified.append(dbX509CertificateTrusted)
        else:
            attrs = ("display_name",)
            for _k in attrs:
                if getattr(dbX509CertificateTrusted, _k) is None:
                    setattr(dbX509CertificateTrusted, _k, cert_data[_k])  # type: ignore[literal-required]
                    if dbX509CertificateTrusted not in certs_discovered:
                        certs_modified.append(dbX509CertificateTrusted)

        if ("compatibility" in cert_data) and (cert_data["compatibility"] is not None):
            # TODO: migrate to getcreate
            # TODO: log creation
            for root_stare_name, root_stare_data in cert_data["compatibility"].items():
                (version_min, version_max, version_notes) = root_stare_data
                dbRootStore = (
                    ctx.dbSession.query(model_objects.RootStore)
                    .filter(
                        sqlalchemy.func.lower(model_objects.RootStore.name)
                        == root_stare_name.lower(),
                    )
                    .first()
                )
                if not dbRootStore:
                    dbRootStore = model_objects.RootStore()
                    dbRootStore.name = root_stare_name
                    dbRootStore.timestamp_created = ctx.timestamp
                    dbRootStore.is_cert_utils_discovery = True
                    ctx.dbSession.add(dbRootStore)
                    ctx.dbSession.flush(objects=[dbRootStore])
                dbRootStoreVersion = (
                    ctx.dbSession.query(model_objects.RootStoreVersion)
                    .filter(
                        model_objects.RootStoreVersion.root_store_id == dbRootStore.id,
                        sqlalchemy.func.lower(
                            model_objects.RootStoreVersion.version_min
                        )
                        == (version_min.lower() if version_min else None),
                        sqlalchemy.func.lower(
                            model_objects.RootStoreVersion.version_max
                        )
                        == (version_max.lower() if version_max else None),
                    )
                    .first()
                )
                if not dbRootStoreVersion:
                    dbRootStoreVersion = model_objects.RootStoreVersion()
                    dbRootStoreVersion.root_store_id = dbRootStore.id
                    dbRootStoreVersion.version_min = version_min
                    dbRootStoreVersion.version_max = version_max
                    dbRootStoreVersion.version_notes = version_notes
                    dbRootStoreVersion.is_cert_utils_discovery = True
                    dbRootStoreVersion.timestamp_created = ctx.timestamp
                    ctx.dbSession.add(dbRootStoreVersion)
                    ctx.dbSession.flush(objects=[dbRootStoreVersion])

                dbRootStoreVersion2X509CertificateTrusted = (
                    ctx.dbSession.query(
                        model_objects.RootStoreVersion_2_X509CertificateTrusted
                    )
                    .filter(
                        model_objects.RootStoreVersion_2_X509CertificateTrusted.root_store_version_id
                        == dbRootStoreVersion.id,
                        model_objects.RootStoreVersion_2_X509CertificateTrusted.x509_certificate_trusted_id
                        == dbX509CertificateTrusted.id,
                    )
                    .first()
                )
                if not dbRootStoreVersion2X509CertificateTrusted:
                    dbRootStoreVersion2X509CertificateTrusted = (
                        model_objects.RootStoreVersion_2_X509CertificateTrusted()
                    )
                    dbRootStoreVersion2X509CertificateTrusted.root_store_version_id = (
                        dbRootStoreVersion.id
                    )
                    dbRootStoreVersion2X509CertificateTrusted.x509_certificate_trusted_id = (
                        dbX509CertificateTrusted.id
                    )
                    ctx.dbSession.add(dbRootStoreVersion2X509CertificateTrusted)
                    ctx.dbSession.flush(
                        objects=[dbRootStoreVersion2X509CertificateTrusted]
                    )
        certs_lookup[cert_id] = dbX509CertificateTrusted

    # bookkeeping update
    event_payload_dict["is_certificates_discovered"] = (
        True if certs_discovered else False
    )
    event_payload_dict["is_certificates_updated"] = True if certs_modified else False
    event_payload_dict["ids_discovered"] = [c.id for c in certs_discovered]
    event_payload_dict["ids_modified"] = [c.id for c in certs_modified]

    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return dbOperationsEvent, certs_lookup


def register_acme_servers(
    ctx: "ApiContext",
    acme_servers: List[AcmeServerInput],
    source: Literal["initial", "user", "reset"],
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
        elif source == "user":
            existingDbServer = get.get__AcmeServer__by_server(ctx, server)
            if not existingDbServer:
                log.debug("Adding New ACME Server: %s", server)
                _new_AcmeServer()
            else:
                log.debug("Existing ACME Server: %s", server)
                if existingDbServer.server_ca_cert_bundle != server_ca_cert_bundle:
                    log.debug("Updating: %s", server)
                    existingDbServer.server_ca_cert_bundle = server_ca_cert_bundle
                    existingDbServer.local_ca_bundle(ctx, force_refresh=True)
        elif source == "reset":
            existingDbServer = get.get__AcmeServer__by_server(ctx, server)
            if not existingDbServer:
                raise ValueError("Expected server in db: `%s`" % server)
            log.debug("Existing ACME Server: %s", server)
            if existingDbServer.server_ca_cert_bundle != server_ca_cert_bundle:
                log.debug("Updating: %s", server)
                existingDbServer.server_ca_cert_bundle = server_ca_cert_bundle
                existingDbServer.local_ca_bundle(ctx, force_refresh=True)
        else:
            raise ValueError("unknown")
    ctx.pyramid_transaction_commit()
    return True


def routine__clear_old_ari_checks(ctx: "ApiContext") -> "RoutineExecution":
    """
    clear from the database outdated ARI checks.
    An ARI check is considered outdated once it has been replaced with a newer ARI check.
    """
    # iterate over all the X509Certificate - windowed query of 100
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
                x509_certificate_id
            FROM ari_check
            GROUP BY
                x509_certificate_id
        ) subq
    );
    """

    latest_ari_checks = (
        ctx.dbSession.query(
            sqlalchemy.func.max(AriCheck.id).label("latest_ari_id"),
            AriCheck.x509_certificate_id,
        )
        .group_by(AriCheck.x509_certificate_id)
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
    # iterate over all the X509Certificate - windowed query of 100
    # criteria: no ari check, ari_check expired
    # run & store ari check

    # don't rely on ctx.timestamp, as it can be old
    # also, we need to time the routine
    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)
    assert ctx.application_settings is not None

    # the max_expiry will be slightly in the future, to ensure we check ARI of anything
    # that expires until the next routine invocation
    timestamp_max_expiry = datetime_ari_timely(
        ctx, datetime_now=TIMESTAMP_routine_start, context="routine__run_ari_checks"
    )
    latest_ari_checks = (
        ctx.dbSession.query(
            AriCheck.x509_certificate_id,
            AriCheck.id.label("latest_ari_id"),
            AriCheck.timestamp_retry_after,
            AriCheck.timestamp_created,
        )
        .filter(AriCheck.id.in_(get._latest_ari_ids()))
        .subquery()
    )

    certs = (
        ctx.dbSession.query(
            X509Certificate,
            latest_ari_checks.c.latest_ari_id,
            # latest_ari_checks.c.timestamp_retry_after,
        )
        .outerjoin(
            latest_ari_checks,
            X509Certificate.id == latest_ari_checks.c.x509_certificate_id,
        )
        .filter(
            # ARI is only managed for active certs
            X509Certificate.is_active.is_(True),
            # if `timestamp_not_after <= timestamp_max_expiry`::
            #   these are considered expired and must be renewed,
            #   so we don't need to run ARI checks on them
            X509Certificate.timestamp_not_after >= timestamp_max_expiry,
            # the cert or order MUST support ARI
            sqlalchemy_or(
                X509Certificate.is_ari_supported__cert.is_(True),
                X509Certificate.is_ari_supported__order.is_(True),
            ),
            sqlalchemy_or(
                # there is no ari check for this certificate
                latest_ari_checks.c.latest_ari_id.is_(None),
                # OR
                # <= : the previous ari check has expired
                get._ari_retry_due(
                    latest_ari_checks.c.timestamp_retry_after,
                    latest_ari_checks.c.timestamp_created,
                    TIMESTAMP_routine_start,
                    ctx.application_settings.get("offset.ari_updates", 60),
                ),
            ),
        )
        .order_by(
            X509Certificate.id.desc(),
            latest_ari_checks.c.latest_ari_id.desc(),
        )
        .all()
    )

    count_records_success = 0
    count_records_fail = 0
    for dbX509Certificate, latest_ari_id in certs:
        log.debug(
            "Running ARI Check for : %s [%s]"
            % (dbX509Certificate.id, dbX509Certificate.cert_serial)
        )
        try:
            dbAriObject, ari_check_result = actions_acme.do__AcmeV2_AriCheck(
                ctx,
                dbX509Certificate=dbX509Certificate,
                force_check=True,  # a potential delay exists after above SQL
            )
            check_succeeded = bool(dbAriObject.ari_check_status)
            ctx.pyramid_transaction_commit()
            if check_succeeded:
                count_records_success += 1
            else:
                count_records_fail += 1
        except errors.AcmeAriCheckDeclined as exc:
            count_records_fail += 1
            log.info(exc)
        except Exception as exc:
            count_records_fail += 1
            ctx.pyramid_transaction_rollback()
            log.exception("ARI check failed for certificate %s", dbX509Certificate.id)

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


def _validate_routine_limit(limit: Optional[int]) -> None:
    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("limit must be a non-negative integer or None")


def _continue_reconciled_order(ctx: "ApiContext", order: "AcmeOrder") -> "AcmeOrder":
    """Advance an order without repeatedly sending the same unchanged work."""
    seen: Set[Tuple[int, Optional[int], Tuple[Tuple[int, int], ...]]] = set()
    # Each authorization can be discovered then validated; allow three more
    # steps for the order refresh, finalization, and certificate download.
    remaining_steps = 2 * len(order.acme_authorizations_pending) + 3
    while (
        order.is_can_acme_process
        or order.is_can_acme_finalize
        or order.is_can_acme_server_download_certificate
    ):
        if remaining_steps == 0:
            raise errors.AcmeCommunicationError(
                "ACME order reconciliation exceeded its step limit"
            )
        remaining_steps -= 1
        state = (
            order.acme_status_order_id,
            order.x509_certificate_id,
            tuple(
                sorted(
                    (authorization.id, authorization.acme_status_authorization_id)
                    for authorization in order.acme_authorizations_pending
                )
            ),
        )
        if state in seen:
            raise errors.AcmeCommunicationError(
                "ACME order reconciliation made no progress"
            )
        seen.add(state)
        if order.is_can_acme_server_download_certificate:
            order = actions_acme.do__AcmeV2_AcmeOrder__download_certificate(
                ctx, dbAcmeOrder=order, transaction_commit=True
            )
        elif order.is_can_acme_finalize:
            order = actions_acme.do__AcmeV2_AcmeOrder__finalize(
                ctx, dbAcmeOrder=order, transaction_commit=True
            )
        else:
            order = actions_acme.do__AcmeV2_AcmeOrder__process(
                ctx, dbAcmeOrder=order, transaction_commit=True
            )
    return order


def routine__order_missing(
    ctx: "ApiContext",
    settings: Dict[str, Any],
    create_public_server: Callable[
        [Dict[str, Any]], _PublicServer
    ] = _create_public_server,
    renewal_configuration_ids__only_process: Optional[Tuple[int, ...]] = None,
    dry_run: bool = False,
    limit: Optional[int] = None,
    DEBUG_LOCAL: Optional[bool] = False,
) -> "RoutineExecution":
    """
    returns "RoutineExecution" which contains
        (count_records_success, count_records_fail)

    """
    _validate_routine_limit(limit)

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
            == model_utils.X509CertificateType.MANAGED_BACKUP,
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
    if renewal_configuration_ids__only_process is not None:
        q__backup = q__backup.filter(
            model_objects.RenewalConfiguration.id.in_(
                renewal_configuration_ids__only_process
            )
        )
    q__backup = q__backup.order_by(model_objects.RenewalConfiguration.id.asc()).limit(
        limit
    )
    dbRenewalConfigurations__backup = q__backup.all()

    subq__primary = (
        sqlalchemy.select(model_objects.AcmeOrder)
        .filter(
            model_objects.AcmeOrder.renewal_configuration_id
            == model_objects.RenewalConfiguration.id,
            model_objects.AcmeOrder.certificate_type_id
            == model_utils.X509CertificateType.MANAGED_PRIMARY,
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
    if renewal_configuration_ids__only_process is not None:
        q__primary = q__primary.filter(
            model_objects.RenewalConfiguration.id.in_(
                renewal_configuration_ids__only_process
            )
        )
    q__primary = q__primary.order_by(model_objects.RenewalConfiguration.id.asc()).limit(
        limit
    )
    dbRenewalConfigurations__primary = q__primary.all()

    jobs = [
        (configuration.id, model_utils.X509CertificateType_Enum.MANAGED_BACKUP)
        for configuration in dbRenewalConfigurations__backup
    ] + [
        (configuration.id, model_utils.X509CertificateType_Enum.MANAGED_PRIMARY)
        for configuration in dbRenewalConfigurations__primary
    ]
    if limit is not None:
        jobs = jobs[:limit]

    if DEBUG_LOCAL or dry_run:
        for configuration_id, certificate_type in jobs:
            print(
                "Order missing %s for RenewalConfiguration[%s]"
                % (certificate_type.name, configuration_id)
            )

    count_renewals = 0
    count_failures = 0
    if dry_run:
        count_renewals = len(jobs)
    elif jobs:
        wsgi_server = create_public_server(settings)
        try:
            for configuration_id, certificate_type in jobs:
                try:
                    configuration = ctx.dbSession.get(
                        model_objects.RenewalConfiguration, configuration_id
                    )
                    if configuration is None:
                        raise ValueError("RenewalConfiguration no longer exists")
                    certificate_concept = (
                        "backup"
                        if certificate_type
                        == model_utils.X509CertificateType_Enum.MANAGED_BACKUP
                        else "primary"
                    )
                    order = actions_acme.do__AcmeV2_AcmeOrder__new(
                        ctx,
                        dbRenewalConfiguration=configuration,
                        processing_strategy="process_single",
                        acme_order_type_id=model_utils.AcmeOrder_Type.RENEWAL_CONFIGURATION_AUTOMATED,
                        note=RENEWAL_RUN,
                        replaces=certificate_concept,
                        replaces_type=model_utils.ReplacesType_Enum.AUTOMATIC,
                        replaces_certificate_type=certificate_type,
                        transaction_commit=True,
                    )
                    issued = bool(order.x509_certificate_id)
                    ctx.pyramid_transaction_commit()
                    if issued:
                        count_renewals += 1
                    else:
                        count_failures += 1
                except Exception:
                    ctx.pyramid_transaction_rollback()
                    count_failures += 1
                    log.exception(
                        "Missing-certificate order failed for RenewalConfiguration[%s] (%s)",
                        configuration_id,
                        certificate_type,
                    )
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
    settings: Dict[str, Any],
    create_public_server: Callable[
        [Dict[str, Any]], _PublicServer
    ] = _create_public_server,
    dry_run: bool = False,
    transaction_commit: Optional[bool] = None,
) -> "RoutineExecution":
    """Sync pending orders, then continue each successfully synced order."""
    if not dry_run and not transaction_commit:
        raise errors.AcknowledgeTransactionCommitRequired(
            "MUST persist external system data."
        )
    timestamp_start = datetime.datetime.now(datetime.timezone.utc)
    order_model = model_objects.AcmeOrder
    order_ids = [
        identity
        for (identity,) in ctx.dbSession.query(order_model.id)
        .filter(
            sqlalchemy.or_(
                order_model.acme_status_order_id.in_(
                    model_utils.Acme_Status_Order.IDS_active
                ),
                sqlalchemy.and_(
                    order_model.acme_status_order_id
                    == model_utils.Acme_Status_Order.from_string("valid"),
                    order_model.x509_certificate_id.is_(None),
                    order_model.certificate_url.is_not(None),
                    order_model.certificate_url != "",
                ),
            )
        )
        .order_by(order_model.id.desc())
        .all()
    ]
    succeeded: Set[int] = set()
    failed: Set[int] = set()
    if dry_run:
        for order_id in order_ids:
            print("Sync ACME Order | %s" % order_id)
        succeeded.update(order_ids)
    else:
        for order_id in order_ids:
            try:
                order = get.get__AcmeOrder__by_id(ctx, order_id)
                if order is None:
                    raise ValueError("AcmeOrder no longer exists")
                actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
                    ctx, dbAcmeOrder=order, transaction_commit=True
                )
                ctx.pyramid_transaction_commit()
                succeeded.add(order_id)
            except Exception:
                ctx.pyramid_transaction_rollback()
                failed.add(order_id)
                log.exception("Exception when syncing AcmeOrder[%s]", order_id)

        # Do not retry failed syncs in the same run, or pick up orders that were
        # created by another routine while this invocation was syncing.
        candidates = [
            (order.id, order.is_can_acme_process or order.is_can_acme_finalize)
            for order in ctx.dbSession.query(order_model)
            .filter(order_model.id.in_(succeeded))
            .order_by(order_model.id.desc())
            .all()
            if (
                order.is_can_acme_process
                or order.is_can_acme_finalize
                or order.is_can_acme_server_download_certificate
            )
        ]
        if candidates:
            wsgi_server = (
                create_public_server(settings)
                if any(needs_server for _, needs_server in candidates)
                else None
            )
            try:
                for order_id, _ in candidates:
                    try:
                        order = get.get__AcmeOrder__by_id(ctx, order_id)
                        if order is None:
                            raise ValueError("AcmeOrder no longer exists")
                        _continue_reconciled_order(ctx, order)
                        ctx.pyramid_transaction_commit()
                    except Exception:
                        ctx.pyramid_transaction_rollback()
                        failed.add(order_id)
                        log.exception(
                            "Exception when continuing AcmeOrder[%s]", order_id
                        )
            finally:
                if wsgi_server is not None:
                    wsgi_server.shutdown()

    routine = create.create__RoutineExecution(
        ctx,
        routine_id=model_utils.Routine.routine__reconcile_blocks,
        timestamp_start=timestamp_start,
        timestamp_end=datetime.datetime.now(datetime.timezone.utc),
        count_records_success=len(succeeded - failed),
        count_records_fail=len(failed),
        is_dry_run=dry_run,
    )
    ctx.pyramid_transaction_commit()
    return routine


def routine__renew_expiring(
    ctx: "ApiContext",
    settings: Dict[str, Any],
    create_public_server: Callable[
        [Dict[str, Any]], _PublicServer
    ] = _create_public_server,
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
    _validate_routine_limit(limit)

    # don't rely on ctx.timestamp, as it can be old
    # also, we need to time the routine
    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)

    RENEWAL_RUN: str = "RenewExpiring[%s]" % TIMESTAMP_routine_start

    # `get_X509Certificates_renew_now` will compute a buffer,
    # so we do not have to submit a `timestamp_max_expiry`
    expiring_certs = get.get_X509Certificates_renew_now(
        ctx,
        limit=limit,
        renewal_configuration_ids=renewal_configuration_ids__only_process,
    )
    if count_expected_configurations is not None:
        if (
            type(count_expected_configurations) is not int
            or count_expected_configurations < 0
        ):
            raise ValueError(
                "count_expected_configurations must be a non-negative integer"
            )
        if len(expiring_certs) != count_expected_configurations:
            raise ValueError(
                "Expected %s renewal candidates; selected %s"
                % (count_expected_configurations, len(expiring_certs))
            )

    if DEBUG_LOCAL or dry_run:
        for certificate in expiring_certs:
            print("Renew X509Certificate[%s]" % certificate.id)

    count_renewals = len(expiring_certs) if dry_run else 0
    count_failures = 0
    if expiring_certs and not dry_run:
        wsgi_server = create_public_server(settings)
        try:
            for certificate_id in [certificate.id for certificate in expiring_certs]:
                try:
                    dbX509Certificate = ctx.dbSession.get(
                        X509Certificate, certificate_id
                    )
                    if dbX509Certificate is None or not dbX509Certificate.acme_order:
                        raise ValueError(
                            "Renewal candidate no longer has an ACME order"
                        )
                    replaces_certificate_type = (
                        model_utils.X509CertificateType.to_X509CertificateType_Enum(
                            dbX509Certificate.acme_order.certificate_type_id
                        )
                    )
                    dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                        ctx,
                        dbRenewalConfiguration=dbX509Certificate.acme_order.renewal_configuration,
                        processing_strategy="process_single",
                        acme_order_type_id=model_utils.AcmeOrder_Type.RENEWAL_CONFIGURATION_AUTOMATED,
                        note=RENEWAL_RUN,
                        replaces=dbX509Certificate.ari_identifier,
                        replaces_type=model_utils.ReplacesType_Enum.AUTOMATIC,
                        replaces_certificate_type=replaces_certificate_type,
                        transaction_commit=True,
                    )
                    log.debug("Renewal Result: AcmeOrder: %s", dbAcmeOrderNew.id)
                    log.debug(
                        "Renewal Result: X509Certificate: %s",
                        dbAcmeOrderNew.x509_certificate_id,
                    )
                    issued = bool(dbAcmeOrderNew.x509_certificate_id)
                    ctx.pyramid_transaction_commit()
                    if issued:
                        count_renewals += 1
                    else:
                        count_failures += 1
                except Exception:
                    ctx.pyramid_transaction_rollback()
                    count_failures += 1
                    log.exception(
                        "Renewal failed for X509Certificate[%s]", certificate_id
                    )
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
