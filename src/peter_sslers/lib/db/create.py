# stdlib
import datetime
import json
import logging
from typing import Dict
from typing import List
from typing import Literal
from typing import Optional
from typing import TYPE_CHECKING

# pypi
import cert_utils
from dateutil import parser as dateutil_parser

# from typing_extensions import Required
# from typing_extensions import TypedDict

# local
from .helpers import _certificate_parse_to_record
from .logger import _log_object_event
from .logger import log__OperationsEvent
from .validate import ensure_domains_dns01
from .validate import validate_domain_names
from .. import errors
from .. import utils
from ... import lib
from ...lib.db import get as _get  # noqa: F401
from ...model import objects as model_objects
from ...model import utils as model_utils

# from typing import Optional

if TYPE_CHECKING:
    from ...lib.acme_v2 import AriCheckResult
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeAuthorization
    from ...model.objects import AcmeAuthorizationPotential
    from ...model.objects import AcmeChallenge
    from ...model.objects import AcmeChallengePoll
    from ...model.objects import AcmeChallengeUnknownPoll
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeDnsServerAccount
    from ...model.objects import AcmeEventLog
    from ...model.objects import AcmeOrder
    from ...model.objects import AcmeOrderSubmission
    from ...model.objects import AcmeServer
    from ...model.objects import AriCheck
    from ...model.objects import CertificateCA
    from ...model.objects import CertificateCAChain
    from ...model.objects import CertificateCAPreference
    from ...model.objects import CertificateRequest
    from ...model.objects import CertificateSigned
    from ...model.objects import CoverageAssuranceEvent
    from ...model.objects import Domain
    from ...model.objects import DomainAutocert
    from ...model.objects import PrivateKey
    from ...model.objects import RenewalConfiguration
    from ...model.objects import UniqueFQDNSet
    from ..utils import ApiContext
    from ...model.utils import DomainsChallenged

    # --


# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


def create__AcmeServer(
    ctx: "ApiContext",
    name: str,
    directory: str,
    protocol: str,
) -> "AcmeServer":
    """
    Create a new AcmeServer
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param name: (required) The name
    :param directory: (required) The directory
    :param protocol: (required) The protocol, must be "acme-v2"

    returns: :class:`model.objects.AcmeServer`
    """
    if not directory or (
        not directory.startswith("http://") and not directory.startswith("https://")
    ):
        raise ValueError("invalid `directory`")

    if protocol != "acme-v2":
        raise ValueError("invalid `protocol`")

    assert ctx.timestamp

    # ok, try to build one...
    dbAcmeServer = model_objects.AcmeServer()
    dbAcmeServer.timestamp_created = ctx.timestamp
    dbAcmeServer.name = name
    dbAcmeServer.directory = directory
    dbAcmeServer.is_default = None
    dbAcmeServer.is_enabled = True
    dbAcmeServer.protocol = protocol
    dbAcmeServer.server = utils.url_to_server(directory)
    ctx.dbSession.add(dbAcmeServer)
    ctx.dbSession.flush(
        objects=[
            dbAcmeServer,
        ]
    )
    return dbAcmeServer


def create__AcmeOrder(
    ctx: "ApiContext",
    acme_order_response: Dict,
    acme_order_type_id: int,
    acme_order_processing_status_id: int,
    acme_order_processing_strategy_id: int,
    domains_challenged: "DomainsChallenged",
    order_url: str,
    certificate_type_id: int,
    dbAcmeAccount: "AcmeAccount",
    dbUniqueFQDNSet: "UniqueFQDNSet",
    dbEventLogged: "AcmeEventLog",
    dbRenewalConfiguration: "RenewalConfiguration",
    dbPrivateKey: "PrivateKey",  # could be a Placeholder(0) key
    private_key_cycle_id: int,
    transaction_commit: Literal[True],
    # optionals
    is_auto_renew: bool = True,
    is_save_alternate_chains: bool = True,
    dbAcmeOrder_renewal_of: Optional["AcmeOrder"] = None,
    dbAcmeOrder_retry_of: Optional["AcmeOrder"] = None,
    dbCertificateRequest: Optional["CertificateRequest"] = None,
    private_key_deferred_id: Optional[int] = None,
    private_key_strategy_id__requested: Optional[int] = None,
) -> "AcmeOrder":
    """
    Create a new ACME Order

    `PrivateKey` is required so we don't autogenerate keys on failures

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance

    :param acme_order_response: (required) dictionary object from the server, representing an ACME payload
    :param acme_order_type_id: (required) What type of order is this? Valid options are in :class:`model.utils.AcmeOrderType`
    :param acme_order_processing_status_id: (required) Valid options are in :class:`model.utils.AcmeOrder_ProcessingStatus`
    :param acme_order_processing_strategy_id: (required) Valid options are in :class:`model.utils.AcmeOrder_ProcessingStrategy`
    :param domains_challenged: (required) A listing of the preferred challenges. see :class:`model.utils.DomainsChallenged`
    :param order_url: (required) the url of the object
    :param certificate_type_id: (required) The value of :class:`model.utils.CertificateType`
    :param dbAcmeAccount: (required) The :class:`model.objects.AcmeAccount` associated with the order
    :param dbUniqueFQDNSet: (required) The :class:`model.objects.UniqueFQDNSet` associated with the order
    :param dbEventLogged: (required) The :class:`model.objects.AcmeEventLog` associated with submitting the order to LetsEncrypt
    :param dbRenewalConfiguration: (required) The :class:`model.objects.RenewalConfiguration` associated with the order
    :param private_key_cycle_id: (required) Valid options are in :class:`model.utils.PrivateKeyCycle`

    :param is_auto_renew: (optional) should this AcmeOrder be created with the auto-renew toggle on?  Default: `True`
    :param is_save_alternate_chains: (optional) should alternate chains be saved if detected?  Default: `True`
    :param dbAcmeOrder_retry_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbAcmeOrder_renewal_of: (optional) A :class:`model.objects.AcmeOrder` object
    :param dbCertificateRequest: (optional) The :class:`model.objects.CertificateRequest` associated with the order
    :param dbPrivateKey: (optional) The :class:`model.objects.PrivateKey` associated with the order
    :param private_key_deferred_id: (optional) See `model.utils.PrivateKeyDeferred`
    :param private_key_strategy_id__requested: (required) Valid options are in :class:`model.utils.PrivateKeyStrategy`

    :param transaction_commit: (required) Boolean value. required to indicate this persists to the database.

    returns: dbAcmeOrder
    """
    if not transaction_commit:
        raise ValueError("`create__AcmeOrder` must persist to the database.")

    if acme_order_type_id not in model_utils.AcmeOrderType._mapping:
        raise ValueError("Unsupported `acme_order_type_id`: %s" % acme_order_type_id)

    if certificate_type_id not in model_utils.CertificateType._options_AcmeOrder_id:
        raise ValueError("Unsupported `certificate_type_id`: %s" % certificate_type_id)

    if acme_order_response is None:
        raise ValueError(
            "`create__AcmeOrder` must be invoked with a `acme_order_response`."
        )

    if not dbAcmeAccount:
        raise ValueError("`create__AcmeOrder` must be invoked with a `dbAcmeAccount`.")

    if not dbPrivateKey:
        raise ValueError("`create__AcmeOrder` must be invoked with a `dbPrivateKey`.")

    if not dbRenewalConfiguration:
        raise ValueError("`create__AcmeOrder` requires `dbRenewalConfiguration`")

    if not dbUniqueFQDNSet:
        raise ValueError("`create__AcmeOrder` requires `dbUniqueFQDNSet`")

    if dbCertificateRequest:
        if dbCertificateRequest.unique_fqdn_set_id != dbUniqueFQDNSet.id:
            raise ValueError(
                "`create__AcmeOrder` mismatch of (dbCertificateRequest, dbUniqueFQDNSet)."
            )

    if dbAcmeOrder_retry_of:
        if dbCertificateRequest:
            if dbAcmeOrder_retry_of.certificate_request != dbCertificateRequest:
                raise ValueError("received conflicting CertificateRequests.")
        else:
            dbCertificateRequest = dbAcmeOrder_retry_of.certificate_request

    if all((dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of)):
        raise ValueError(
            "`create__AcmeOrder` must be invoked with one or None of (`dbAcmeOrder_retry_of, dbAcmeOrder_renewal_of`)."
        )

    if dbPrivateKey.acme_account_id__owner:
        if dbAcmeAccount.id != dbPrivateKey.acme_account_id__owner:
            raise ValueError("The specified PrivateKey belongs to another AcmeAccount.")

    if not private_key_strategy_id__requested:
        raise ValueError("missing `private_key_strategy_id__requested`")

    # DEBUG
    if model_utils.PrivateKeyCycle.as_string(private_key_cycle_id) == "account_default":
        # this should be computer BEFORE creating the order
        raise ValueError("account_default should never be here")

    if TYPE_CHECKING:
        assert ctx.timestamp

    # validate the domains that were submitted
    # we already test for this on submission, but be safe!
    if not domains_challenged:
        raise ValueError("domains_challenged is required")
    _domain_names_all = domains_challenged.domains_as_list
    # this may raise errors.AcmeDomainsBlocklisted
    validate_domain_names(ctx, _domain_names_all)

    # we already test for this on submission, but be safe!
    _dns01_domain_names = domains_challenged["dns-01"]
    if _dns01_domain_names:
        # this may raise errors.AcmeDomainsBlocklisted
        ensure_domains_dns01(ctx, _dns01_domain_names)

    # acme_status_order_id = model_utils.Acme_Status_Order.ID_DEFAULT
    acme_status_order_id = model_utils.Acme_Status_Order.from_string(
        acme_order_response["status"]
    )
    finalize_url = acme_order_response.get("finalize")
    certificate_url = acme_order_response.get("certificate")
    timestamp_expires = acme_order_response.get("expires")
    if timestamp_expires:
        timestamp_expires = dateutil_parser.parse(timestamp_expires)
        timestamp_expires = timestamp_expires.replace(tzinfo=None)

    dbAcmeOrder = model_objects.AcmeOrder()
    dbAcmeOrder.is_processing = True
    dbAcmeOrder.is_auto_renew = is_auto_renew
    dbAcmeOrder.is_save_alternate_chains = is_save_alternate_chains
    dbAcmeOrder.timestamp_created = ctx.timestamp
    dbAcmeOrder.order_url = order_url
    dbAcmeOrder.certificate_type_id = certificate_type_id
    dbAcmeOrder.acme_order_type_id = acme_order_type_id
    dbAcmeOrder.acme_status_order_id = acme_status_order_id
    dbAcmeOrder.acme_order_processing_status_id = acme_order_processing_status_id
    dbAcmeOrder.acme_order_processing_strategy_id = acme_order_processing_strategy_id
    dbAcmeOrder.acme_account_id = dbAcmeAccount.id
    dbAcmeOrder.renewal_configuration_id = dbRenewalConfiguration.id
    dbAcmeOrder.uniquely_challenged_fqdn_set_id = (
        dbRenewalConfiguration.uniquely_challenged_fqdn_set_id
    )
    dbAcmeOrder.acme_event_log_id = dbEventLogged.id
    dbAcmeOrder.certificate_request_id = (
        dbCertificateRequest.id if dbCertificateRequest else None
    )
    dbAcmeOrder.private_key_id = dbPrivateKey.id
    dbAcmeOrder.private_key_cycle_id = private_key_cycle_id
    dbAcmeOrder.private_key_deferred_id = private_key_deferred_id
    dbAcmeOrder.private_key_strategy_id__requested = private_key_strategy_id__requested
    dbAcmeOrder.unique_fqdn_set_id = dbUniqueFQDNSet.id
    dbAcmeOrder.finalize_url = finalize_url
    dbAcmeOrder.certificate_url = certificate_url
    dbAcmeOrder.timestamp_expires = timestamp_expires
    dbAcmeOrder.timestamp_updated = datetime.datetime.utcnow()
    if dbAcmeOrder_retry_of:
        dbAcmeOrder.acme_order_id__retry_of = dbAcmeOrder_retry_of.id
    if dbAcmeOrder_renewal_of:
        dbAcmeOrder.acme_order_id__renewal_of = dbAcmeOrder_renewal_of.id
    ctx.dbSession.add(dbAcmeOrder)
    ctx.dbSession.flush(objects=[dbAcmeOrder])

    # then update the event with the order
    dbEventLogged.acme_order_id = dbAcmeOrder.id
    ctx.dbSession.flush(objects=[dbEventLogged])

    # then update the renewal configuration with the order
    dbRenewalConfiguration.acme_order_id__latest_attempt = dbAcmeOrder.id
    ctx.dbSession.flush(objects=[dbRenewalConfiguration])

    # and note the submission
    create__AcmeOrderSubmission(ctx, dbAcmeOrder)

    # do we have any preferences in challenges?
    domains_challenged.ENSURE_DEFAULT_HTTP01()
    _dbDomainObjects = dbUniqueFQDNSet.domain_objects
    for act_, domains_ in domains_challenged.items():
        # act_ = acme-challenge-type
        # domains_ = list of domains
        if not domains_:
            continue
        acme_challenge_type_id = model_utils.AcmeChallengeType.from_string(act_)

        # create a potential object
        for domain_name_ in domains_:
            if domain_name_ not in _dbDomainObjects:
                raise ValueError("did not load domain from database")
            # create a blocking authz
            dbAcmeAuthorizationPotential = (  # noqa: F841
                create__AcmeAuthorizationPotential(
                    ctx,
                    dbAcmeOrder=dbAcmeOrder,
                    dbDomain=_dbDomainObjects[domain_name_],
                    acme_challenge_type_id=acme_challenge_type_id,
                )
            )

    # now loop the authorization URLs to create stub records for this order
    for authorization_url in acme_order_response.get("authorizations", []):
        (
            _dbAuthPlacholder,
            _is_auth_created,
            _is_auth_2_order_created,
        ) = lib.db.getcreate.getcreate__AcmeAuthorizationUrl(
            ctx,
            authorization_url=authorization_url,
            dbAcmeOrder=dbAcmeOrder,
            is_via_new_order=True,
        )

    # persist this to the db
    if transaction_commit:
        ctx.pyramid_transaction_commit()

    return dbAcmeOrder


def create__AcmeOrderSubmission(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
) -> "AcmeOrderSubmission":
    assert ctx.timestamp
    dbAcmeOrderSubmission = model_objects.AcmeOrderSubmission()
    dbAcmeOrderSubmission.acme_order_id = dbAcmeOrder.id
    dbAcmeOrderSubmission.timestamp_created = ctx.timestamp
    ctx.dbSession.add(dbAcmeOrderSubmission)
    ctx.dbSession.flush(objects=[dbAcmeOrderSubmission])
    return dbAcmeOrderSubmission


def create__AcmeAuthorizationPotential(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
    dbDomain: "Domain",
    acme_challenge_type_id: int,
) -> "AcmeAuthorizationPotential":
    dbAcmeAuthorizationPotential = model_objects.AcmeAuthorizationPotential()
    dbAcmeAuthorizationPotential.acme_order_id = dbAcmeOrder.id
    dbAcmeAuthorizationPotential.timestamp_created = ctx.timestamp
    dbAcmeAuthorizationPotential.domain_id = dbDomain.id
    dbAcmeAuthorizationPotential.acme_challenge_type_id = acme_challenge_type_id
    ctx.dbSession.add(dbAcmeAuthorizationPotential)
    ctx.dbSession.flush(objects=[dbAcmeAuthorizationPotential])
    return dbAcmeAuthorizationPotential


def create__AcmeAuthorization(*args, **kwargs):
    raise ValueError("use `getcreate__AcmeAuthorization`")


def create__AcmeChallenge(
    ctx: "ApiContext",
    dbDomain: "Domain",
    acme_challenge_type_id: int,
    # optionals
    dbAcmeAuthorization: Optional["AcmeAuthorization"] = None,
    challenge_url: Optional[str] = None,
    token: Optional[str] = None,
    keyauthorization: Optional[str] = None,
    acme_status_challenge_id: int = model_utils.Acme_Status_Challenge.ID_DEFAULT,
    is_via_sync: Optional[bool] = None,
) -> "AcmeChallenge":
    """
    Create a new Challenge
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomain: (required) The :class:`model.objects.Domain`
    :param acme_challenge_type_id: (required) An option from :class:`model_utils.AcmeChallengeType`.
    :param dbAcmeAuthorization: (optional) The :class:`model.objects.AcmeAuthorization`
    :param challenge_url: (optional) challenge_url token
    :param token: (optional) string token
    :param keyauthorization: (optional) string keyauthorization
    :param acme_status_challenge_id: (optional) An option from :class:`model_utils.Acme_Status_Challenge`.
    :param is_via_sync: (optional) boolean. if True will allow duplicate challenges as one is on the server

    """
    if not dbAcmeAuthorization:
        raise ValueError("must be invoked with `dbAcmeAuthorization`")
    if not dbDomain:
        raise ValueError("must be invoked with `dbDomain`")

    if not acme_challenge_type_id:
        raise ValueError("must be invoked with `acme_challenge_type_id`")
    if acme_challenge_type_id not in model_utils.AcmeChallengeType._mapping:
        raise ValueError("invalid `acme_challenge_type_id`")

    _competing_challenges = None
    assert ctx.request
    assert ctx.request.registry
    assert ctx.timestamp
    if ctx.request.registry.settings["app_settings"]["block_competing_challenges"]:
        _active_challenges = lib.db.get.get__AcmeChallenges__by_DomainId__active(
            ctx,
            dbDomain.id,
            acme_challenge_type_id=acme_challenge_type_id,
        )
        if _active_challenges:
            if not is_via_sync:
                raise errors.AcmeDuplicateChallenge(_active_challenges)
            _competing_challenges = _active_challenges

    dbAcmeChallenge = model_objects.AcmeChallenge()
    dbAcmeChallenge.acme_authorization_id = dbAcmeAuthorization.id
    dbAcmeChallenge.timestamp_created = ctx.timestamp
    dbAcmeChallenge.domain_id = dbDomain.id
    dbAcmeChallenge.acme_challenge_type_id = acme_challenge_type_id
    dbAcmeChallenge.acme_status_challenge_id = acme_status_challenge_id
    dbAcmeChallenge.token = token
    dbAcmeChallenge.keyauthorization = keyauthorization
    dbAcmeChallenge.challenge_url = challenge_url

    ctx.dbSession.add(dbAcmeChallenge)
    ctx.dbSession.flush(objects=[dbAcmeChallenge])

    if _competing_challenges:
        dbAcmeChallengeCompeting = model_objects.AcmeChallengeCompeting()
        dbAcmeChallengeCompeting.timestamp_created = ctx.timestamp
        dbAcmeChallengeCompeting.domain_id = dbDomain.id
        ctx.dbSession.add(dbAcmeChallengeCompeting)
        ctx.dbSession.flush(objects=[dbAcmeChallengeCompeting])
        _competing_challenges.append(dbAcmeChallenge)
        for _chall in _competing_challenges:
            dbAcmeChallengeCompeting2AcmeChallenge = (
                model_objects.AcmeChallengeCompeting2AcmeChallenge()
            )
            dbAcmeChallengeCompeting2AcmeChallenge.acme_challenge_competing_id = (
                dbAcmeChallengeCompeting.id
            )
            dbAcmeChallengeCompeting2AcmeChallenge.acme_challenge_id = _chall.id
            ctx.dbSession.add(dbAcmeChallengeCompeting2AcmeChallenge)
            ctx.dbSession.flush(objects=[dbAcmeChallengeCompeting2AcmeChallenge])
    return dbAcmeChallenge


def create__AcmeChallengePoll(
    ctx: "ApiContext",
    dbAcmeChallenge: model_objects.AcmeChallenge,
    remote_ip_address: str,
) -> "AcmeChallengePoll":
    """
    Create a new AcmeChallengePoll - this is a log

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeChallenge: (required) The challenge which was polled
    :param remote_ip_address: (required) The remote ip address (string)
    """
    remote_ip_address_id: int
    assert ctx.timestamp
    (dbRemoteIpAddress, _created) = lib.db.getcreate.getcreate__RemoteIpAddress(
        ctx, remote_ip_address
    )
    remote_ip_address_id = dbRemoteIpAddress.id

    dbAcmeChallengePoll = model_objects.AcmeChallengePoll()
    dbAcmeChallengePoll.acme_challenge_id = dbAcmeChallenge.id
    dbAcmeChallengePoll.timestamp_polled = ctx.timestamp
    dbAcmeChallengePoll.remote_ip_address_id = remote_ip_address_id
    ctx.dbSession.add(dbAcmeChallengePoll)
    ctx.dbSession.flush(objects=[dbAcmeChallengePoll])
    return dbAcmeChallengePoll


def create__AcmeChallengeUnknownPoll(
    ctx: "ApiContext",
    domain: str,
    challenge: str,
    remote_ip_address: str,
) -> "AcmeChallengeUnknownPoll":
    """
    Create a new AcmeChallengeUnknownPoll - this is an unknown polling

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain: (required) domain (string)
    :param challenge: (required) challenge (string)
    :param remote_ip_address: (required) remote_ip_address (string)
    """
    assert ctx.timestamp
    remote_ip_address_id: int
    (dbRemoteIpAddress, _created) = lib.db.getcreate.getcreate__RemoteIpAddress(
        ctx, remote_ip_address
    )
    remote_ip_address_id = dbRemoteIpAddress.id

    dbAcmeChallengeUnknownPoll = model_objects.AcmeChallengeUnknownPoll()
    dbAcmeChallengeUnknownPoll.domain = domain
    dbAcmeChallengeUnknownPoll.challenge = challenge
    dbAcmeChallengeUnknownPoll.timestamp_polled = ctx.timestamp
    dbAcmeChallengeUnknownPoll.remote_ip_address_id = remote_ip_address_id
    ctx.dbSession.add(dbAcmeChallengeUnknownPoll)
    ctx.dbSession.flush(objects=[dbAcmeChallengeUnknownPoll])
    return dbAcmeChallengeUnknownPoll


def create__AcmeDnsServerAccount(
    ctx: "ApiContext",
    dbAcmeDnsServer: "AcmeDnsServer",
    dbDomain: "Domain",
    username: str,
    password: str,
    fulldomain: str,
    subdomain: str,
    allowfrom: str,
) -> "AcmeDnsServerAccount":
    """
    create wrapping an acms-dns Server and Domain (AcmeDnsServerAccount)

    return dbAcmeDnsServerAccount,

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeDnsServer: (required)
    :param dbDomain: (required)

    :param username: (required)
    :param password: (required)
    :param fulldomain: (required)
    :param subdomain: (required)
    :param fulldomain: (required)
    :param allowfrom: (required)
    """
    assert ctx.timestamp
    if not dbAcmeDnsServer.is_active:
        raise ValueError("Inactive AcmeDnsServer")
    event_type_id = model_utils.OperationsEventType.from_string(
        "AcmeDnsServerAccount__insert"
    )
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["acme_dns_server_id"] = dbAcmeDnsServer.id
    event_payload_dict["domain_id"] = dbDomain.id

    # sometimes an empty list pops in
    if isinstance(allowfrom, list):
        allowfrom = str(allowfrom)

    # bookkeeping
    dbOperationsEvent = log__OperationsEvent(ctx, event_type_id, event_payload_dict)
    dbAcmeDnsServerAccount = model_objects.AcmeDnsServerAccount()
    dbAcmeDnsServerAccount.timestamp_created = ctx.timestamp
    dbAcmeDnsServerAccount.acme_dns_server_id = dbAcmeDnsServer.id
    dbAcmeDnsServerAccount.domain_id = dbDomain.id
    dbAcmeDnsServerAccount.operations_event_id__created = dbOperationsEvent.id
    dbAcmeDnsServerAccount.username = username
    dbAcmeDnsServerAccount.password = password
    dbAcmeDnsServerAccount.fulldomain = fulldomain
    dbAcmeDnsServerAccount.subdomain = subdomain
    dbAcmeDnsServerAccount.allowfrom = allowfrom
    ctx.dbSession.add(dbAcmeDnsServerAccount)
    ctx.dbSession.flush(objects=[dbAcmeDnsServerAccount])
    return dbAcmeDnsServerAccount


def create__AriCheck(
    ctx: "ApiContext",
    dbCertificateSigned: "CertificateSigned",
    ariCheckResult: Optional["AriCheckResult"],
) -> "AriCheck":
    dbAriCheck = model_objects.AriCheck()
    dbAriCheck.certificate_signed_id = dbCertificateSigned.id
    dbAriCheck.timestamp_created = ctx.timestamp

    if ariCheckResult:
        if ariCheckResult["status_code"] != 200:
            dbAriCheck.ari_check_status = False
            dbAriCheck.raw_response = json.dumps(ariCheckResult["payload"])
        else:
            if TYPE_CHECKING:
                assert ariCheckResult["payload"] is not None
            dbAriCheck.ari_check_status = True
            if ariCheckResult["payload"].get("suggestedWindow"):
                _start = ariCheckResult["payload"]["suggestedWindow"].get("start")
                if _start:
                    _start = utils.ari_timestamp_to_python(_start)
                dbAriCheck.suggested_window_start = _start
                _end = ariCheckResult["payload"]["suggestedWindow"].get("end")
                if _end:
                    _end = utils.ari_timestamp_to_python(_end)
                dbAriCheck.suggested_window_end = _end
            retry_after_secs = ariCheckResult["headers"].get("Retry-After")
            if retry_after_secs:
                retry_after = ctx.timestamp + datetime.timedelta(
                    seconds=int(retry_after_secs)
                )
                dbAriCheck.timestamp_retry_after = retry_after
    else:
        dbAriCheck.ari_check_status = False

    ctx.dbSession.add(dbAriCheck)
    ctx.dbSession.flush(objects=[dbAriCheck])
    return dbAriCheck


def create__CertificateCAPreference(
    ctx: "ApiContext",
    dbCertificateCA: "CertificateCA",
    slot_id: Optional[int] = None,
) -> "CertificateCAPreference":
    """
    Create a new CertificateCAPreference entry

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbCertificateCA: (required) a `model_objects.CertificateCA` object
    :param slot_id: (optional) The id, if any. defaults to db managing the id
    """
    dbCertificateCAPreference = model_objects.CertificateCAPreference()
    if slot_id:
        dbCertificateCAPreference.id = slot_id
    dbCertificateCAPreference.certificate_ca_id = dbCertificateCA.id
    ctx.dbSession.add(dbCertificateCAPreference)
    ctx.dbSession.flush(objects=[dbCertificateCAPreference])
    return dbCertificateCAPreference


def create__CertificateRequest(
    ctx: "ApiContext",
    csr_pem: str,
    certificate_request_source_id: int,
    dbPrivateKey: "PrivateKey",
    domain_names: List[str],
    dbCertificateSigned__issued: Optional["CertificateSigned"] = None,
    discovery_type: Optional[str] = None,
) -> "CertificateRequest":
    """
    Create a new Certificate Signing Request (CSR)

    If uploading, use the getcreate function, which also has docs regarding the formatting.

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param csr_pem: (required) A Certificate Signing Request with PEM formatting
    :param certificate_request_source_id: (required) What is the source of this? Valid options are in :class:`model.utils.CertificateRequestSource`
    :param dbPrivateKey: (required) Private Key used to sign the CSR
    :param domain_names: (required) A list of domain names
    :param dbCertificateSigned__issued: (optional) a `model_objects.CertificateSigned`
    :param str discovery_type: (optional) Text about the discovery
    """
    if (
        certificate_request_source_id
        not in model_utils.CertificateRequestSource._mapping
    ):
        raise ValueError(
            "Unsupported `certificate_request_source_id`: %s"
            % certificate_request_source_id
        )

    _event_type_id = None
    if certificate_request_source_id == model_utils.CertificateRequestSource.IMPORTED:
        _event_type_id = model_utils.OperationsEventType.from_string(
            "CertificateRequest__new__imported"
        )
    elif (
        certificate_request_source_id == model_utils.CertificateRequestSource.ACME_ORDER
    ):
        _event_type_id = model_utils.OperationsEventType.from_string(
            "CertificateRequest__new__acme_order"
        )
    else:
        raise ValueError(
            "Unsupported `certificate_request_source_id`: %s"
            % certificate_request_source_id
        )

    assert ctx.timestamp

    if domain_names is None:
        raise ValueError("Must submit `domain_names` for creation")

    if dbPrivateKey is None:
        raise ValueError("Must submit `dbPrivateKey` for creation")

    if csr_pem is None:
        raise ValueError("Must submit a valid `csr_pem`")
    csr_pem = cert_utils.cleanup_pem_text(csr_pem)

    # scoping
    csr_domain_names = None
    csr_pem_md5 = None
    csr__spki_sha256 = None

    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(ctx, _event_type_id)

    _tmpfile = None
    try:
        if cert_utils.NEEDS_TEMPFILES:
            # store the csr_text in a tmpfile
            _tmpfile = cert_utils.new_pem_tempfile(csr_pem)

        # validate
        cert_utils.validate_csr(
            csr_pem=csr_pem,
            csr_pem_filepath=_tmpfile.name if _tmpfile else None,
        )

        _csr_domain_names = cert_utils.parse_csr_domains(
            csr_pem=csr_pem,
            csr_pem_filepath=_tmpfile.name if _tmpfile else None,
            submitted_domain_names=domain_names,
        )
        # this function checks the domain names match a simple regex
        csr_domain_names = cert_utils.utils.domains_from_list(_csr_domain_names)
        if len(csr_domain_names) != len(_csr_domain_names):
            raise ValueError(
                "One or more of the domain names in the CSR are not allowed (%s)"
                % _csr_domain_names
            )
        if not csr_domain_names:
            raise ValueError(
                "Must submit `csr_pem` that contains `domain_names` (found None)"
            )
        if set(csr_domain_names) != set(domain_names):
            raise ValueError(
                "received different values for `domain_names` than exist in the CSR"
            )

        # calculate the md5
        csr_pem_md5 = cert_utils.utils.md5_text(csr_pem)

        # grab and check the spki
        csr__spki_sha256 = cert_utils.parse_csr__spki_sha256(
            csr_pem=csr_pem,
            csr_pem_filepath=_tmpfile.name if _tmpfile else None,
        )
        if csr__spki_sha256 != dbPrivateKey.spki_sha256:
            raise ValueError("Computed mismatch on SPKI")

    finally:
        if _tmpfile is not None:
            _tmpfile.close()

    # ensure the domains are registered into our system
    domain_objects: Dict[str, "Domain"] = {
        _domain_name: lib.db.getcreate.getcreate__Domain__by_domainName(
            ctx,
            _domain_name,
            discovery_type="via CertificateRequest",
        )[
            0
        ]  # (dbDomain, _is_created)
        for _domain_name in domain_names
    }
    # we'll use this tuple in a bit...
    # getcreate__Domain__by_domainName returns a tuple of (domainObject, is_created)
    (
        dbUniqueFQDNSet,
        is_created_fqdn,
    ) = lib.db.getcreate.getcreate__UniqueFQDNSet__by_domainObjects(
        ctx,
        list(domain_objects.values()),
        discovery_type="via CertificateRequest",
    )

    # build the cert
    dbCertificateRequest = model_objects.CertificateRequest()
    dbCertificateRequest.timestamp_created = ctx.timestamp
    dbCertificateRequest.certificate_request_source_id = certificate_request_source_id
    dbCertificateRequest.csr_pem = csr_pem
    dbCertificateRequest.csr_pem_md5 = csr_pem_md5  # computed in initial block
    dbCertificateRequest.operations_event_id__created = dbOperationsEvent.id
    dbCertificateRequest.private_key_id = dbPrivateKey.id
    dbCertificateRequest.key_technology_id = dbPrivateKey.key_technology_id
    dbCertificateRequest.unique_fqdn_set_id = dbUniqueFQDNSet.id
    dbCertificateRequest.spki_sha256 = csr__spki_sha256
    dbCertificateRequest.discovery_type = discovery_type

    ctx.dbSession.add(dbCertificateRequest)
    ctx.dbSession.flush(objects=[dbCertificateRequest])

    event_payload_dict["certificate_request.id"] = dbCertificateRequest.id
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            "CertificateRequest__insert"
        ),
        dbCertificateRequest=dbCertificateRequest,
    )

    #
    # increment private key counts
    #
    dbPrivateKey.count_acme_orders += 1
    if not dbPrivateKey.timestamp_last_certificate_request or (
        dbPrivateKey.timestamp_last_certificate_request < ctx.timestamp
    ):
        dbPrivateKey.timestamp_last_certificate_request = ctx.timestamp
    ctx.dbSession.flush(objects=[dbPrivateKey])

    return dbCertificateRequest


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__CertificateSigned(
    ctx: "ApiContext",
    cert_pem: str,
    cert_domains_expected: List[str],
    dbCertificateCAChain: "CertificateCAChain",
    certificate_type_id: int,
    # optionals
    is_active: bool = False,
    dbAcmeOrder: Optional["AcmeOrder"] = None,
    dbCertificateCAChains_alt: Optional[List["CertificateCAChain"]] = None,
    dbCertificateRequest: Optional["CertificateRequest"] = None,
    dbPrivateKey: Optional["PrivateKey"] = None,
    dbUniqueFQDNSet: Optional["UniqueFQDNSet"] = None,
    discovery_type: Optional[str] = None,
) -> "CertificateSigned":
    """
    Create a new CertificateSigned

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param cert_pem: (required) The certificate in PEM encoding
    :param cert_domains_expected: (required) a list of domains in the cert we
      expect to see
    :param dbCertificateCAChain: (required) The :class:`model.objects.CertificateCAChain`
      that signed this certificate.
    :param certificate_type_id: (required) The :class:`model.utils.CertifcateType`
      corresponding to this Certificate

    :param is_active: (optional) default `False`; do not activate a certificate
      when uploading unless specified.
    :param dbCertificateCAChains_alt: (optional) Iterable. Alternate
      :class:`model.objects.CertificateCAChain`s that signed this certificate
    :param dbAcmeOrder: (optional) The :class:`model.objects.AcmeOrder` the certificate was generated through.
        if provivded, do not submit `dbCertificateRequest` or `dbPrivateKey`
    :param dbCertificateRequest: (optional) The :class:`model.objects.CertificateRequest` the certificate was generated through.
        if provivded, do not submit `dbAcmeOrder`
    :param dbPrivateKey: (optional) The :class:`model.objects.PrivateKey` that signed the certificate, if no `dbAcmeOrder` is provided
    :param dbUniqueFQDNSet: (optional) The :class:`model.objects.UniqueFQDNSet` representing domains on the certificate.
        required if there is no `dbAcmeOrder` or `dbCertificateRequest`; do not provide otherwise
    :param str discovery_type: (optional) Text about the discovery
    """
    if not any((dbAcmeOrder, dbPrivateKey)):
        raise ValueError(
            "create__CertificateSigned must be provided with `dbPrivateKey` or `dbAcmeOrder`"
        )
    if not any((dbAcmeOrder, dbCertificateRequest, dbUniqueFQDNSet)):
        raise ValueError(
            "create__CertificateSigned must be provided with `dbCertificateRequest`, `dbAcmeOrder` or `dbUniqueFQDNSet`"
        )
    if dbUniqueFQDNSet:
        if any(
            (
                dbAcmeOrder,
                dbCertificateRequest,
            )
        ):
            raise ValueError(
                "getcreate__CertificateSigned must not be provided with `dbCertificateRequest` or `dbAcmeOrder` when `dbUniqueFQDNSet` is provided."
            )
    if not dbCertificateCAChain:
        raise ValueError("must submit `dbCertificateCAChain`")

    if certificate_type_id not in model_utils.CertificateType._mapping:
        raise ValueError("invalid `certificate_type_id`")

    assert ctx.timestamp

    dbAcmeAccount = None
    if dbAcmeOrder:
        dbAcmeAccount = dbAcmeOrder.acme_account
        dbUniqueFQDNSet = dbAcmeOrder.unique_fqdn_set
        if dbCertificateRequest:
            if dbCertificateRequest != dbAcmeOrder.certificate_request:
                raise ValueError(
                    "create__CertificateSigned was with `dbCertificateRequest` and a conflicting `dbAcmeOrder`"
                )
        else:
            dbCertificateRequest = dbAcmeOrder.certificate_request
        if dbPrivateKey:
            if dbPrivateKey != dbAcmeOrder.private_key:
                raise ValueError(
                    "create__CertificateSigned was with `dbPrivateKey` and a conflicting `dbAcmeOrder`"
                )
        else:
            dbPrivateKey = dbAcmeOrder.certificate_request.private_key

    if not dbPrivateKey:
        raise ValueError("dbPrivateKey should have been supplied or inferred")

    if dbCertificateRequest:
        if dbUniqueFQDNSet:
            if dbUniqueFQDNSet.id != dbCertificateRequest.unique_fqdn_set_id:
                raise ValueError("could not compute the correct UniqueFQDNSet")
        else:
            dbUniqueFQDNSet = dbCertificateRequest.unique_fqdn_set

    if not dbUniqueFQDNSet:
        raise ValueError("a `UniqueFQDNSet` should have been computed by now")

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("CertificateSigned__insert")
    )

    _tmpfileCert = None
    try:
        # cleanup the cert_pem
        cert_pem = cert_utils.cleanup_pem_text(cert_pem)
        if cert_utils.NEEDS_TEMPFILES:
            _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

        # validate
        cert_utils.validate_cert(
            cert_pem=cert_pem,
            cert_pem_filepath=_tmpfileCert.name if _tmpfileCert else None,
        )

        # validate the domains!
        # let's make sure have the right domains in the cert!!
        # this only happens on development during tests when we use a single cert
        # for all requests...
        # so we don't need to handle this or save it
        cert_domains = cert_utils.parse_cert__domains(
            cert_pem=cert_pem,
            cert_pem_filepath=_tmpfileCert.name if _tmpfileCert else None,
        )
        if set(cert_domains_expected) != set(cert_domains):
            log.error("set(cert_domains_expected) != set(cert_domains)")
            log.error(cert_domains_expected)
            log.error(cert_domains)
            raise ValueError(
                "CertificateSigned Domains do not match the expected ones! this should never happen!"
            )

        # ok, now pull the dates off the cert
        dbCertificateSigned = model_objects.CertificateSigned()
        dbCertificateSigned.certificate_type_id = certificate_type_id
        dbCertificateSigned.timestamp_created = ctx.timestamp
        dbCertificateSigned.cert_pem = cert_pem
        dbCertificateSigned.cert_pem_md5 = cert_utils.utils.md5_text(cert_pem)
        dbCertificateSigned.is_active = is_active
        dbCertificateSigned.unique_fqdn_set_id = dbUniqueFQDNSet.id
        dbCertificateSigned.private_key_id = dbPrivateKey.id
        dbCertificateSigned.key_technology_id = dbPrivateKey.key_technology_id
        dbCertificateSigned.operations_event_id__created = dbOperationsEvent.id
        dbCertificateSigned.discovery_type = discovery_type
        if dbUniqueFQDNSet.count_domains == 1:
            dbCertificateSigned.is_single_domain_cert = True
        elif dbUniqueFQDNSet.count_domains >= 1:
            dbCertificateSigned.is_single_domain_cert = False

        """
        The following are set by `_certificate_parse_to_record`
            :attr:`model.utils.CertificateSigned.timestamp_not_before`
            :attr:`model.utils.CertificateSigned.timestamp_not_after`
            :attr:`model.utils.CertificateSigned.cert_subject`
            :attr:`model.utils.CertificateSigned.cert_issuer`
            :attr:`model.utils.CertificateSigned.fingerprint_sha1`
            :attr:`model.utils.CertificateSigned.spki_sha256`
            :attr:`model.utils.CertificateSigned.cert_serial`
            :attr:`model.utils.CertificateSigned.is_ari_supported`
            :attr:`model.utils.CertificateSigned.is_ari_supported__cert`
        """
        _certificate_parse_to_record(
            cert_pem=cert_pem,
            cert_pem_filepath=_tmpfileCert.name if _tmpfileCert else None,
            dbCertificateSigned=dbCertificateSigned,
        )
        if dbPrivateKey:
            if dbCertificateSigned.spki_sha256 != dbPrivateKey.spki_sha256:
                raise ValueError("Computed mismatch on SPKI")
        if dbCertificateRequest:
            dbCertificateSigned.certificate_request_id = dbCertificateRequest.id

        ctx.dbSession.connection().engine.echo = True
        ctx.dbSession.add(dbCertificateSigned)
        ctx.dbSession.flush(objects=[dbCertificateSigned])

        dbCertificateSignedChain = model_objects.CertificateSignedChain()
        dbCertificateSignedChain.certificate_signed_id = dbCertificateSigned.id
        dbCertificateSignedChain.certificate_ca_chain_id = dbCertificateCAChain.id
        dbCertificateSignedChain.is_upstream_default = True
        ctx.dbSession.add(dbCertificateSignedChain)
        ctx.dbSession.flush(objects=[dbCertificateSignedChain])

        # increment account/private key counts
        dbPrivateKey.count_certificate_signeds += 1
        if not dbPrivateKey.timestamp_last_certificate_issue or (
            dbPrivateKey.timestamp_last_certificate_issue < ctx.timestamp
        ):
            dbPrivateKey.timestamp_last_certificate_issue = ctx.timestamp
        if dbAcmeAccount:
            dbAcmeAccount.count_certificate_signeds += 1
            if not dbAcmeAccount.timestamp_last_certificate_issue or (
                dbAcmeAccount.timestamp_last_certificate_issue < ctx.timestamp
            ):
                dbAcmeAccount.timestamp_last_certificate_issue = ctx.timestamp

        event_payload_dict["certificate_signed.id"] = dbCertificateSigned.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "CertificateSigned__insert"
            ),
            dbCertificateSigned=dbCertificateSigned,
        )

        # final, just to be safe
        ctx.dbSession.flush()

        if dbAcmeOrder:
            # dbCertificateSigned.acme_order_id__generated_by = dbAcmeOrder.id
            dbAcmeOrder.certificate_signed = dbCertificateSigned  # dbAcmeOrder.certificate_signed_id = dbCertificateSigned.id
            dbAcmeOrder.acme_order_processing_status_id = (
                model_utils.AcmeOrder_ProcessingStatus.certificate_downloaded
            )  # note that we've completed this!

            if dbAcmeOrder.acme_account.acme_server.is_supports_ari:
                dbCertificateSigned.is_ari_supported = True
                dbCertificateSigned.is_ari_supported__order = True

            # final, just to be safe
            ctx.dbSession.flush()

        if dbCertificateCAChains_alt:
            for _dbCertificateCAChain in dbCertificateCAChains_alt:
                dbCertificateSignedChain = model_objects.CertificateSignedChain()
                dbCertificateSignedChain.certificate_signed_id = dbCertificateSigned.id
                dbCertificateSignedChain.certificate_ca_chain_id = (
                    _dbCertificateCAChain.id
                )
                dbCertificateSignedChain.is_upstream_default = False
                ctx.dbSession.add(dbCertificateSignedChain)
                ctx.dbSession.flush(objects=[dbCertificateSignedChain])

    except Exception as exc:  # noqa: F841
        raise
    finally:
        if _tmpfileCert is not None:
            _tmpfileCert.close()

    return dbCertificateSigned


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__CoverageAssuranceEvent(
    ctx: "ApiContext",
    coverage_assurance_event_type_id: int,
    coverage_assurance_event_status_id: int,
    # optionals
    coverage_assurance_resolution_id: Optional[int] = None,
    dbPrivateKey: Optional["PrivateKey"] = None,
    dbCertificateSigned: Optional["CertificateSigned"] = None,
    dbCoverageAssuranceEvent_parent: Optional["CoverageAssuranceEvent"] = None,
) -> "CoverageAssuranceEvent":
    """
    Create a new Certificate Signing Request (CSR)

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param coverage_assurance_event_type_id: (required) :class:`model.utils.CoverageAssuranceEvent`
    :param coverage_assurance_event_status_id: (required) :class:`model.utils.CoverageAssuranceEventStatus`

    :param coverage_assurance_resolution_id: (optional) :class:`model.utils.CoverageAssuranceResolution`; defaults to 'unresolved'
    :param dbPrivateKey: (optional) a `model_objects.PrivateKey`
    :param dbCertificateSigned: (optional) a `model_objects.CertificateSigned`
    :param dbCoverageAssuranceEvent_parent: (optional) a `model_objects.CoverageAssuranceEvent`
    """
    if (
        coverage_assurance_event_type_id
        not in model_utils.CoverageAssuranceEventType._mapping
    ):
        raise ValueError(
            "Unsupported `coverage_assurance_event_type_id`: %s"
            % coverage_assurance_event_type_id
        )
    if (
        coverage_assurance_event_status_id
        not in model_utils.CoverageAssuranceEventStatus._mapping
    ):
        raise ValueError(
            "Unsupported `coverage_assurance_event_status_id`: %s"
            % coverage_assurance_event_status_id
        )
    if coverage_assurance_resolution_id is None:
        coverage_assurance_resolution_id = (
            model_utils.CoverageAssuranceResolution.from_string("unresolved")
        )
    else:
        if (
            coverage_assurance_resolution_id
            not in model_utils.CoverageAssuranceResolution._mapping
        ):
            raise ValueError(
                "Unsupported `coverage_assurance_resolution_id`: %s"
                % coverage_assurance_resolution_id
            )

    if not any((dbPrivateKey, dbCertificateSigned)):
        raise ValueError(
            "must submit at least one of (dbPrivateKey, dbCertificateSigned)"
        )

    assert ctx.timestamp

    dbCoverageAssuranceEvent = model_objects.CoverageAssuranceEvent()
    dbCoverageAssuranceEvent.timestamp_created = ctx.timestamp
    dbCoverageAssuranceEvent.coverage_assurance_event_type_id = (
        coverage_assurance_event_type_id
    )
    dbCoverageAssuranceEvent.coverage_assurance_event_status_id = (
        coverage_assurance_event_status_id
    )
    dbCoverageAssuranceEvent.coverage_assurance_resolution_id = (
        coverage_assurance_resolution_id
    )
    if dbPrivateKey:
        dbCoverageAssuranceEvent.private_key_id = dbPrivateKey.id
    if dbCertificateSigned:
        dbCoverageAssuranceEvent.certificate_signed_id = dbCertificateSigned.id
    if dbCoverageAssuranceEvent_parent:
        dbCoverageAssuranceEvent.coverage_assurance_event_id__parent = (
            dbCoverageAssuranceEvent_parent.id
        )

    ctx.dbSession.add(dbCoverageAssuranceEvent)
    ctx.dbSession.flush(objects=[dbCoverageAssuranceEvent])

    return dbCoverageAssuranceEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__DomainAutocert(
    ctx: "ApiContext",
    dbDomain: "Domain",
) -> "DomainAutocert":
    """
    Generates a new :class:`model.objects.DomainAutocert` for the datastore

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomain: (required) an instance of :class:`model.objects.Domain`
    """
    assert ctx.timestamp
    dbDomainAutocert = model_objects.DomainAutocert()
    dbDomainAutocert.domain_id = dbDomain.id
    dbDomainAutocert.timestamp_created = datetime.datetime.utcnow()
    ctx.dbSession.add(dbDomainAutocert)
    ctx.dbSession.flush(objects=[dbDomainAutocert])
    return dbDomainAutocert


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__PrivateKey(
    ctx: "ApiContext",
    private_key_source_id: int,
    private_key_type_id: int,
    # optionals
    key_technology_id: int = model_utils.KeyTechnology._DEFAULT_PrivateKey_id,
    private_key_id__replaces: Optional[int] = None,
    acme_account_id__owner: Optional[int] = None,
    discovery_type: Optional[str] = None,
    # bits_rsa=None,
) -> "PrivateKey":
    """
    Generates a new :class:`model.objects.PrivateKey` for the datastore

    This function is a bit weird, because we invoke a GetCreate

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param int private_key_source_id: (required) An int matching a source in A :class:`lib.utils.PrivateKeySource`
    :param int private_key_type_id: (required) Valid options are in :class:`model.utils.PrivateKeyType`
    :param int private_key_id__replaces: (required) if this key replaces a compromised key, note it.
    :param int key_technology_id: (required) see `modul.utils.KeyTechnology`
    # :param int bits_rsa: (required) how many bits for the RSA PrivateKey, see `key_technology_id`

    :param int acme_account_id__owner: (optional) the id of a :class:`model.objects.AcmeAccount` which owns this :class:`model.objects.PrivateKey`

    :param str discovery_type: (optional) Text about the discovery
    """
    cu_new_args = model_utils.KeyTechnology.to_new_args(key_technology_id)
    key_pem = cert_utils.new_private_key(
        key_technology_id=cu_new_args["key_technology_id"],
        rsa_bits=cu_new_args.get("rsa_bits"),
        ec_curve=cu_new_args.get("ec_curve"),
    )
    dbPrivateKey, _is_created = lib.db.getcreate.getcreate__PrivateKey__by_pem_text(
        ctx,
        key_pem,
        private_key_source_id=private_key_source_id,
        private_key_type_id=private_key_type_id,
        acme_account_id__owner=acme_account_id__owner,
        private_key_id__replaces=private_key_id__replaces,
        discovery_type=discovery_type,
    )
    return dbPrivateKey


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def create__RenewalConfiguration(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    private_key_cycle_id: int,
    key_technology_id: int,
    domains_challenged: "DomainsChallenged",
) -> "RenewalConfiguration":
    """
    Sets params for AcmeOrders and Renewals

    This must happen within the context other events

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) A :class:`model.objects.AcmeAccount` object
    :param private_key_cycle_id: (required) Valid options are in :class:`model.utils.PrivateKeyCycle`
    :param key_technology_id: (required) Valid options are in :class:`model.utils.KeyTechnology`
    :param domains_challenged: (required) A listing of the preferred challenges. see :class:`model.utils.DomainsChallenged`
    :returns :class:`model.objects.RenewalConfiguration`
    """
    if (
        private_key_cycle_id
        not in model_utils.PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle_id
    ):
        raise ValueError(
            "Unsupported `private_key_cycle_id`: %s" % private_key_cycle_id
        )
    if (
        key_technology_id
        not in model_utils.KeyTechnology._options_RenewalConfiguration_private_key_technology_id
    ):
        raise ValueError("Unsupported `key_technology_id`: %s" % key_technology_id)
    if not dbAcmeAccount.is_active:
        raise ValueError("must supply active `dbAcmeAccount`")

    assert ctx.timestamp

    # this may raise errors.AcmeDomainsBlocklisted
    _domain_names_all = domains_challenged.domains_as_list
    validate_domain_names(ctx, _domain_names_all)

    _domain_objects: Dict[str, "Domain"] = {}
    for _chall, _domains in domains_challenged.items():
        if not _domains:
            continue
        for _domain_name in _domains:
            _domain_objects[
                _domain_name
            ] = lib.db.getcreate.getcreate__Domain__by_domainName(
                ctx,
                _domain_name,
                discovery_type="via RenewalConfiguration",
            )[
                0
            ]  # (dbDomain, _is_created)

    dbUniqueFQDNSet, _is_created = (
        lib.db.getcreate.getcreate__UniqueFQDNSet__by_domainObjects(
            ctx,
            domainObjects=[i for i in _domain_objects.values()],
            discovery_type="via RenewalConfiguration",
        )
    )

    dbUniquelyChallengedFQDNSet, _is_created = (
        lib.db.getcreate.getcreate__UniquelyChallengedFQDNSet__by_domainObjects_domainsChallenged(
            ctx,
            domainObjects=_domain_objects,
            domainsChallenged=domains_challenged,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            discovery_type="via RenewalConfiguration",
        )
    )

    # ok, so now let's make sure we don't have a duplicate...

    existingRenewalConfiguration = (
        ctx.dbSession.query(model_objects.RenewalConfiguration)
        .filter(
            model_objects.RenewalConfiguration.acme_account_id == dbAcmeAccount.id,
            model_objects.RenewalConfiguration.uniquely_challenged_fqdn_set_id
            == dbUniquelyChallengedFQDNSet.id,
            model_objects.RenewalConfiguration.private_key_cycle_id
            == private_key_cycle_id,
            model_objects.RenewalConfiguration.key_technology_id == key_technology_id,
        )
        .first()
    )
    if existingRenewalConfiguration:
        raise errors.DuplicateRenewalConfiguration(existingRenewalConfiguration)

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx, model_utils.OperationsEventType.from_string("RenewalConfiguration__insert")
    )

    dbRenewalConfiguration = model_objects.RenewalConfiguration()
    dbRenewalConfiguration.timestamp_created = ctx.timestamp
    dbRenewalConfiguration.is_active = True
    dbRenewalConfiguration.operations_event_id__created = dbOperationsEvent.id

    # core elements
    dbRenewalConfiguration.private_key_cycle_id = private_key_cycle_id
    dbRenewalConfiguration.key_technology_id = key_technology_id
    dbRenewalConfiguration.acme_account_id = dbAcmeAccount.id
    dbRenewalConfiguration.unique_fqdn_set_id = dbUniqueFQDNSet.id
    dbRenewalConfiguration.uniquely_challenged_fqdn_set_id = (
        dbUniquelyChallengedFQDNSet.id
    )

    ctx.dbSession.add(dbRenewalConfiguration)
    ctx.dbSession.flush(objects=[dbRenewalConfiguration])

    # more bookkeeping!
    event_payload_dict["renewal_configuration.id"] = dbRenewalConfiguration.id
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])
    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            "RenewalConfiguration__insert"
        ),
        dbRenewalConfiguration=dbRenewalConfiguration,
    )

    return dbRenewalConfiguration


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "create__CertificateRequest",
    "create__CertificateSigned",
    "create__PrivateKey",
    "create__RenewalConfiguration",
)
