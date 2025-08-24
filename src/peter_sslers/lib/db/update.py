# stdlib
import datetime
import hashlib
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
from dateutil import parser as dateutil_parser
from typing_extensions import Literal

# localapp
from .create import create__AcmeServerConfiguration
from .create import create__Notification
from .get import get__AcmeAccount__by_id
from .get import get__AcmeAuthorizationPotential__by_AcmeOrderId_DomainId
from .get import get__AcmeDnsServer__by_api_url
from .get import get__AcmeDnsServer__GlobalDefault
from .get import get__Domain__by_name
from .get import get__EnrollmentFactory__by_name
from .. import errors
from ... import lib
from ...lib import acme_v2
from ...lib import events as _events  # noqa: F401
from ...lib import utils as lib_utils
from ...model import objects as model_objects
from ...model import utils as model_utils

if TYPE_CHECKING:
    from ..context import ApiContext
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeAuthorization
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeOrder
    from ...model.objects import AcmeServer
    from ...model.objects import CertificateCAPreference
    from ...model.objects import CertificateCAPreferencePolicy
    from ...model.objects import CoverageAssuranceEvent
    from ...model.objects import DomainAutocert
    from ...model.objects import EnrollmentFactory
    from ...model.objects import Notification
    from ...model.objects import OperationsEvent
    from ...model.objects import PrivateKey
    from ...model.objects import RenewalConfiguration
    from ...model.objects import SystemConfiguration
    from ...model.objects import X509Certificate

# ==============================================================================

log = logging.getLogger("peter_sslers.lib.db")

# ------------------------------------------------------------------------------


def update_AcmeAccount__account_url(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    account_url: Optional[str] = None,
) -> bool:
    if account_url is None:
        dbAcmeAccount.account_url = None
        dbAcmeAccount.account_url_sha256 = None
    else:
        dbAcmeAccount.account_url = account_url
        dbAcmeAccount.account_url_sha256 = hashlib.sha256(
            account_url.encode()
        ).hexdigest()
    return True


def update_AcmeAccount__name(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    name: Optional[str],
) -> str:
    name = lib_utils.normalize_unique_text(name) if name else None
    if dbAcmeAccount.name != name:
        dbAcmeAccount.name = name
        ctx.dbSession.flush(objects=[dbAcmeAccount])
    event_status = "AcmeAccount__edit__name"
    return event_status


def update_AcmeAccount__order_defaults(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    order_default_private_key_cycle: str,
    order_default_private_key_technology: str,
    order_default_acme_profile: Optional[str] = None,
) -> str:
    _transitions: List[str] = []
    if dbAcmeAccount.order_default_private_key_cycle != order_default_private_key_cycle:
        try:
            order_default_private_key_cycle_id = (
                model_utils.PrivateKeyCycle.from_string(order_default_private_key_cycle)
            )
        except KeyError:
            raise errors.InvalidTransition(
                "Invalid option: `order_default_private_key_cycle`"
            )
        if (
            order_default_private_key_cycle_id
            not in model_utils.PrivateKeyCycle._options_AcmeAccount_order_default_id
        ):
            raise errors.InvalidTransition(
                "Invalid option: `order_default_private_key_cycle`"
            )
        dbAcmeAccount.order_default_private_key_cycle_id = (
            order_default_private_key_cycle_id
        )
        _transitions.append("order_default_private_key_cycle_id")
    if (
        dbAcmeAccount.order_default_private_key_technology
        != order_default_private_key_technology
    ):
        try:
            order_default_private_key_technology_id = (
                model_utils.KeyTechnology.from_string(
                    order_default_private_key_technology
                )
            )
        except KeyError:
            raise errors.InvalidTransition(
                "Invalid option: `order_default_private_key_technology`"
            )
        if (
            order_default_private_key_technology_id
            not in model_utils.KeyTechnology._options_AcmeAccount_order_default_id
        ):
            raise errors.InvalidTransition(
                "Invalid option: `order_default_private_key_technology`"
            )
        dbAcmeAccount.order_default_private_key_technology_id = (
            order_default_private_key_technology_id
        )
        _transitions.append("order_default_private_key_technology_id")
    if dbAcmeAccount.order_default_acme_profile != order_default_acme_profile:
        dbAcmeAccount.order_default_acme_profile = order_default_acme_profile
        _transitions.append("order_default_acme_profile")
    if not _transitions:
        raise ValueError("No valid transitions atempted")
    ctx.dbSession.flush(objects=[dbAcmeAccount])
    event_status = "AcmeAccount__edit__order_defaults"
    return event_status


def update_AcmeAccount__private_key_technology(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    private_key_technology: str,
) -> str:
    if dbAcmeAccount.private_key_technology == private_key_technology:
        raise errors.InvalidTransition("Already updated: `private_key_technology`")
    try:
        private_key_technology_id = model_utils.KeyTechnology.from_string(
            private_key_technology
        )
    except KeyError:
        raise errors.InvalidTransition("Invalid option: `private_key_technology`")
    if (
        private_key_technology_id
        not in model_utils.KeyTechnology._options_AcmeAccount_private_key_technology_id
    ):
        raise errors.InvalidTransition("Invalid option: `private_key_technology`")
    dbAcmeAccount.private_key_technology_id = private_key_technology_id
    ctx.dbSession.flush(objects=[dbAcmeAccount])
    event_status = "AcmeAccount__edit__private_key_technology"
    return event_status


def update_AcmeAccount__set_active(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
) -> str:
    if dbAcmeAccount.is_active:
        raise errors.InvalidTransition("Already activated.")
    if dbAcmeAccount.timestamp_deactivated:
        raise errors.InvalidTransition("AccountKey was deactivated.")
    dbAcmeAccount.is_active = True
    ctx.dbSession.flush(objects=[dbAcmeAccount])
    event_status = "AcmeAccount__mark__active"
    return event_status


def update_AcmeAccount__set_deactivated(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
) -> str:
    log.debug("update_AcmeAccount__set_deactivated", dbAcmeAccount.id)
    if dbAcmeAccount.timestamp_deactivated:
        raise errors.InvalidTransition("Already deactivated.")
    dbAcmeAccount.is_active = False
    dbAcmeAccount.timestamp_deactivated = ctx.timestamp
    ctx.dbSession.flush(objects=[dbAcmeAccount])
    event_status = "AcmeAccount__mark__deactivated"
    return event_status


def update_AcmeAccount__terms_of_service(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    terms_of_service: str,
) -> bool:
    """
    returns True if an update was done; False if not
    """
    log.debug("update_AcmeAccount__terms_of_service", dbAcmeAccount.id)

    terms_of_service = terms_of_service.strip()
    if dbAcmeAccount.terms_of_service == terms_of_service:
        return False

    _to_flush = [
        dbAcmeAccount,
    ]

    oldTos = dbAcmeAccount.tos
    if oldTos:
        oldTos.is_active = None
        _to_flush.append(oldTos)

    newTos = model_objects.AcmeAccount_2_TermsOfService()
    newTos.acme_account_id = dbAcmeAccount.id
    newTos.is_active = True
    newTos.timestamp_created = ctx.timestamp
    newTos.terms_of_service = terms_of_service
    ctx.dbSession.add(newTos)
    _to_flush.append(newTos)

    # dbAcmeAccount.tos = newTos

    ctx.dbSession.flush(objects=_to_flush)
    return True


def update_AcmeAccount__unset_active(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
) -> str:
    log.debug("update_AcmeAccount__unset_active", dbAcmeAccount.id)
    if not dbAcmeAccount.is_active:
        raise errors.InvalidTransition("Already deactivated.")
    if (
        dbAcmeAccount.system_configurations__primary
        or dbAcmeAccount.system_configurations__backup
    ):
        raise errors.InvalidTransition(
            "This AcmeAccount is registered with SystemConfiguration(s)."
        )
    dbAcmeAccount.is_active = False
    ctx.dbSession.flush(objects=[dbAcmeAccount])
    event_status = "AcmeAccount__mark__inactive"
    return event_status


def update_AcmeAccount__is_render_in_selects(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    action: Literal["enable", "disable"],
) -> str:
    log.debug("update_AcmeAccount__is_render_in_selects", dbAcmeAccount.id)
    if action == "enable":
        if dbAcmeAccount.is_render_in_selects:
            raise errors.InvalidTransition("Already enabled.")
        # TODO: check max
        dbAcmeAccount.is_render_in_selects = True
        event_status = "AcmeAccount__mark__is_render_in_selects"
    elif action == "disable":
        if not dbAcmeAccount.is_render_in_selects:
            raise errors.InvalidTransition("Already disabled.")
        dbAcmeAccount.is_render_in_selects = False
        event_status = "AcmeAccount__mark__no_render_in_selects"
    ctx.dbSession.flush(objects=[dbAcmeAccount])
    return event_status


def update_AcmeAuthorization_from_payload(
    ctx: "ApiContext",
    dbAcmeAuthorization: "AcmeAuthorization",
    authorization_payload: Dict,
) -> bool:
    authorization_status = authorization_payload["status"]
    acme_status_authorization_id = model_utils.Acme_Status_Authorization.from_string(
        authorization_status
    )
    _updated = False
    _domain_id: Optional[int] = dbAcmeAuthorization.domain_id
    if (
        authorization_status
        not in model_utils.Acme_Status_Authorization.OPTIONS_X_UPDATE
    ):
        timestamp_expires = authorization_payload.get("expires")
        if timestamp_expires:
            timestamp_expires = dateutil_parser.parse(timestamp_expires)

        identifer = authorization_payload["identifier"]
        if identifer["type"] != "dns":
            raise ValueError("unexpected authorization payload: identifier type")
        domain_name = identifer["value"]
        dbDomain = get__Domain__by_name(ctx, domain_name, preload=False)
        if not dbDomain:
            raise ValueError(
                "This `Domain` name has not been seen before. This should not be possible."
            )
        _domain_id = dbDomain.id

        if dbAcmeAuthorization.domain_id != dbDomain.id:
            dbAcmeAuthorization.domain_id = dbDomain.id
            _updated = True
        if dbAcmeAuthorization.timestamp_expires != timestamp_expires:
            dbAcmeAuthorization.timestamp_expires = timestamp_expires
            _updated = True

    if dbAcmeAuthorization.acme_status_authorization_id != acme_status_authorization_id:
        dbAcmeAuthorization.acme_status_authorization_id = acme_status_authorization_id
        _updated = True

    # drop the AcmeAuthorizationPotential
    if _domain_id and dbAcmeAuthorization.acme_order_id__created:
        _potential = get__AcmeAuthorizationPotential__by_AcmeOrderId_DomainId(
            ctx,
            dbAcmeAuthorization.acme_order_id__created,
            _domain_id,
        )
        if _potential:
            ctx.dbSession.delete(_potential)

    if _updated:
        dbAcmeAuthorization.timestamp_updated = datetime.datetime.now(
            datetime.timezone.utc
        )
        ctx.dbSession.flush(objects=[dbAcmeAuthorization])
        return True

    return False


def update_AcmeDnsServer__set_global_default(
    ctx: "ApiContext",
    dbAcmeDnsServer: "AcmeDnsServer",
) -> Tuple[str, Dict]:
    if dbAcmeDnsServer.is_global_default:
        raise errors.InvalidTransition("Already global default.")

    if not dbAcmeDnsServer.is_active:
        raise errors.InvalidTransition("This item must be active.")

    alt_info: Dict = {}
    formerDefault = get__AcmeDnsServer__GlobalDefault(ctx)
    if formerDefault:
        formerDefault.is_global_default = None
        ctx.dbSession.flush(
            objects=[
                formerDefault,
            ]
        )
        alt_info["event_payload_dict"] = {
            "acme_dns_server_id.former_default": formerDefault.id,
        }
        alt_info["event_alt"] = ("AcmeDnsServer__mark__notdefault", formerDefault)
    dbAcmeDnsServer.is_global_default = True
    ctx.dbSession.flush(objects=[dbAcmeDnsServer])
    event_status = "AcmeDnsServer__mark__default"
    return event_status, alt_info


def update_AcmeDnsServer__api_url__domain(
    ctx: "ApiContext", dbAcmeDnsServer: "AcmeDnsServer", api_url: str, domain: str
) -> bool:
    if (dbAcmeDnsServer.api_url == api_url) and (dbAcmeDnsServer.domain == domain):
        raise errors.InvalidTransition("No change")
    dbAcmeDnsServerAlt = get__AcmeDnsServer__by_api_url(ctx, api_url)
    if dbAcmeDnsServerAlt and (dbAcmeDnsServerAlt.id != dbAcmeDnsServer.id):
        raise errors.InvalidTransition(
            "Another acme-dns Server is enrolled with this same API URL."
        )
    dbAcmeDnsServer.api_url = api_url
    dbAcmeDnsServer.domain = domain
    ctx.dbSession.flush(objects=[dbAcmeDnsServer])
    return True


def update_AcmeDnsServer__set_active(
    ctx: "ApiContext",
    dbAcmeDnsServer: "AcmeDnsServer",
) -> str:
    if dbAcmeDnsServer.is_active:
        raise errors.InvalidTransition("Already activated.")
    dbAcmeDnsServer.is_active = True
    ctx.dbSession.flush(objects=[dbAcmeDnsServer])
    event_status = "AcmeDnsServer__mark__active"
    return event_status


def update_AcmeDnsServer__unset_active(
    ctx: "ApiContext",
    dbAcmeDnsServer: "AcmeDnsServer",
) -> str:
    if not dbAcmeDnsServer.is_active:
        raise errors.InvalidTransition("Already deactivated.")
    if dbAcmeDnsServer.is_global_default:
        raise errors.InvalidTransition(
            "You can not deactivate the global default. Set another `AcmeDnsServer` as the global default first."
        )
    dbAcmeDnsServer.is_active = False
    ctx.dbSession.flush(objects=[dbAcmeDnsServer])
    event_status = "AcmeDnsServer__mark__inactive"
    return event_status


def update_AcmeOrder_deactivate(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
    is_manual: bool = False,
) -> bool:
    """
    `deactivate` should mark the order as:
        `is_processing = False`
    """
    if dbAcmeOrder.is_processing is not True:
        raise errors.InvalidTransition("This `AcmeOrder` is not processing.")
    if is_manual:
        # False : The AcmeOrder has been cancelled by the user.
        dbAcmeOrder.is_processing = False
    else:
        # None :  The AcmeOrder has completed, it may be successful or a failure.
        dbAcmeOrder.is_processing = None
    dbAcmeOrder.timestamp_updated = ctx.timestamp
    ctx.dbSession.flush(objects=[dbAcmeOrder])

    res = update_AcmeOrder_deactivate_AcmeAuthorizationPotentials(  # noqa: F841
        ctx, dbAcmeOrder
    )
    return True


def update_AcmeOrder_deactivate_AcmeAuthorizationPotentials(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
) -> bool:
    """
    This will only deactivate the authorization blocks...
    """
    if dbAcmeOrder.acme_authorization_potentials:
        ctx.dbSession.flush()
        _updates = [
            dbAcmeOrder,
        ]
        for _pending in dbAcmeOrder.acme_authorization_potentials:
            ctx.dbSession.delete(_pending)
            _updates.append(_pending)
        ctx.dbSession.flush()
        return True
    return False


def update_AcmeOrder_finalized(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
    finalize_response: Dict,
) -> Literal[True]:
    """
    This will only deactivate the authorization blocks...
    """

    _ari_replaces = finalize_response.get("replaces", None)
    if _ari_replaces:
        dbAcmeOrder.replaces = _ari_replaces
        ctx.dbSession.flush(objects=[dbAcmeOrder])

    # deactivate any authz potentials
    update_AcmeOrder_deactivate_AcmeAuthorizationPotentials(
        ctx,
        dbAcmeOrder=dbAcmeOrder,
    )
    return True


def update_AcmeServer__is_retry_challenges(
    ctx: "ApiContext",
    dbAcmeServer: "AcmeServer",
    is_retry_challenges: bool = True,
):
    if is_retry_challenges:
        if dbAcmeServer.is_retry_challenges:
            raise errors.InvalidTransition(
                "Already Configured: is_retry_challenges==True"
            )
        dbAcmeServer.is_retry_challenges = True
        event_status = "AcmeServer__mark__is_retry_challenges_true"
    else:
        if not dbAcmeServer.is_retry_challenges:
            raise errors.InvalidTransition(
                "Already Configured: is_retry_challenges==False"
            )
        dbAcmeServer.is_retry_challenges = False
        event_status = "AcmeServer__mark__is_retry_challenges_false"
    ctx.dbSession.flush([dbAcmeServer])
    return event_status


def update_AcmeServer__is_unlimited_pending_authz(
    ctx: "ApiContext",
    dbAcmeServer: "AcmeServer",
    is_unlimited_pending_authz: bool = True,
) -> str:
    if is_unlimited_pending_authz:
        if dbAcmeServer.is_unlimited_pending_authz:
            raise errors.InvalidTransition(
                "Already Configured: is_unlimited_pending_authz==True"
            )
        dbAcmeServer.is_unlimited_pending_authz = True
        event_status = "AcmeServer__mark__is_unlimited_authz_true"
    else:
        if not dbAcmeServer.is_unlimited_pending_authz:
            raise errors.InvalidTransition(
                "Already Configured: is_unlimited_pending_authz==False"
            )
        dbAcmeServer.is_unlimited_pending_authz = False
        event_status = "AcmeServer__mark__is_unlimited_authz_false"
    ctx.dbSession.flush([dbAcmeServer])
    return event_status


"""

def update_AcmeServer__activate_default(
    ctx: "ApiContext",
    dbAcmeServer_new: "AcmeServer",
) -> str:
    '''
    TODO: reintegrate
    this function was used to activate a default server based on the config
    '''
    from .get import get__AcmeServer__default
    _objs = [
        dbAcmeServer_new,
    ]
    dbAcmeServer_default = get__AcmeServer__default(ctx)
    if dbAcmeServer_default:
        _objs.append(dbAcmeServer_default)
        if dbAcmeServer_default.id != dbAcmeServer_new.id:
            dbAcmeServer_default.is_default = None
    if not dbAcmeServer_new.is_default:
        dbAcmeServer_new.is_default = True
    if not dbAcmeServer_new.is_enabled:
        dbAcmeServer_new.is_enabled = True
    ctx.dbSession.flush(_objs)
    event_status = "AcmeServer__activate_default"
    return event_status


def update_AcmeServer__set_is_enabled(
    ctx: "ApiContext",
    dbAcmeServer: "AcmeServer",
) -> str:
    if dbAcmeServer.is_enabled:
        raise errors.InvalidTransition("Already enabled")
    dbAcmeServer.is_enabled = True
    event_status = "AcmeServer__mark__is_enabled"
    return event_status

"""


def update_AcmeServer_profiles(
    ctx: "ApiContext",
    dbAcmeServer: "AcmeServer",
    profiles_str: Optional[str],
) -> bool:
    # TODO: anaylize/notify that profiles have changed
    # BUT, we only call this from code that has made that comparison
    # _profiles_old = dbAcmeServer.profiles  # noqa: F841
    if dbAcmeServer.profiles != profiles_str:
        dbAcmeServer.profiles = profiles_str
        ctx.dbSession.flush(objects=[dbAcmeServer])
    return True


def update_AcmeServer_directory(
    ctx: "ApiContext",
    dbAcmeServer: "AcmeServer",
    acme_directory_payload: Dict,
    timestamp: Optional[datetime.datetime] = None,
) -> bool:
    # don't trust ctx.timestamp on this, as we be in a long-running action
    if not timestamp:
        timestamp = ctx.timestamp
    # the LetsEncrypt server puts in a random entry, so the directory changes
    directory_string = acme_v2.serialize_directory_object(acme_directory_payload)
    _changed = False
    if (not dbAcmeServer.directory_latest) or (
        dbAcmeServer.directory_latest.directory_payload != directory_string
    ):
        initial_config = True if not dbAcmeServer.directory_latest else False
        directoryLatest = create__AcmeServerConfiguration(  # noqa: F841
            ctx,
            dbAcmeServer,
            directory_string,
            timestamp=timestamp,
        )
        _changed = True
        if not initial_config:
            message = (
                "Detected a change in the `directory` of AcmeServer[%s]."
                % dbAcmeServer.id
            )
            _notification = create__Notification(  # noqa: F841
                ctx,
                notification_type_id=model_utils.NotificationType.ACME_SERVER_CHANGED,
                message=message,
            )
    else:
        dbAcmeServer.directory_latest.timestamp_lastchecked = timestamp
        _changed = True

    _meta, _profiles_str = acme_v2.parse_acme_directory(acme_directory_payload)
    if _profiles_str != dbAcmeServer.profiles:
        _result = update_AcmeServer_profiles(  # noqa: F841
            ctx, dbAcmeServer, _profiles_str
        )
        _changed = True

    #
    if _changed:
        ctx.dbSession.flush(objects=[dbAcmeServer])

    return _changed


def update_CertificateCAPreferencePolicy_reprioritize(
    ctx: "ApiContext",
    dbCertificateCaPreferencePolicy: "CertificateCAPreferencePolicy",
    dbPreference_active: "CertificateCAPreference",
    priority: str,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbCertificateCaPreferencePolicy: (required) A single instance of
        :class:`model.objects.CertificateCaPreferencePolicy`
    :param dbPreference_active: (required) A single instance of
        :class:`model.objects.CertificateCAPreference` which is being moved
        within the Preference list of `dbCertificateCaPreferencePolicy`
    :param priority: string. required. must be "increase" or "decrease"
    """
    dbPref_other = None
    if priority == "increase":
        if dbPreference_active.slot_id <= 1:
            raise errors.InvalidTransition(
                "This item can not be increased in priority."
            )
        target_slot_id = dbPreference_active.slot_id - 1
        # okay, now iterate over the list...
        for _dbPref in dbCertificateCaPreferencePolicy.certificate_ca_preferences:
            if _dbPref.slot_id == target_slot_id:
                dbPref_other = _dbPref
                break
        if not dbPref_other:
            raise errors.InvalidTransition("Illegal Operation.")

        # set the other to a placeholder
        dbPref_other.slot_id = 999
        ctx.dbSession.flush(objects=[dbPref_other])

        # set the new
        dbPreference_active.slot_id = target_slot_id
        ctx.dbSession.flush(objects=[dbPreference_active])

        # and update the other
        dbPref_other.slot_id = dbPreference_active.slot_id + 1
        ctx.dbSession.flush(objects=[dbPref_other])

    elif priority == "decrease":
        if dbPreference_active.slot_id == len(
            dbCertificateCaPreferencePolicy.certificate_ca_preferences
        ):
            raise errors.InvalidTransition(
                "This item can not be decreased in priority."
            )
        target_slot_id = dbPreference_active.slot_id + 1
        # okay, now iterate over the list...
        for _dbPref in dbCertificateCaPreferencePolicy.certificate_ca_preferences:
            if _dbPref.slot_id == target_slot_id:
                dbPref_other = _dbPref
                break
        if not dbPref_other:
            raise errors.InvalidTransition("Illegal Operation.")

        # set the old to a placeholder
        dbPref_other.slot_id = 999
        ctx.dbSession.flush(objects=[dbPref_other])

        # set the new
        dbPreference_active.slot_id = target_slot_id
        ctx.dbSession.flush(objects=[dbPreference_active])

        # and update the other
        dbPref_other.slot_id = dbPreference_active.slot_id - 1
        ctx.dbSession.flush(objects=[dbPref_other])

    else:
        raise errors.InvalidTransition("Invalid priority.")

    return True


def update_CoverageAssuranceEvent__set_resolution(
    ctx: "ApiContext",
    dbCoverageAssuranceEvent: "CoverageAssuranceEvent",
    resolution: str,
) -> bool:
    resolution_id = model_utils.CoverageAssuranceResolution.from_string(resolution)
    if resolution == "unresolved":
        pass
    elif resolution == "abandoned":
        pass
    elif resolution == "PrivateKey_replaced":
        if dbCoverageAssuranceEvent.x509_certificate_id:
            raise errors.InvalidTransition("incompatible `resolution`")
    elif resolution == "X509Certificate_replaced":
        if not dbCoverageAssuranceEvent.x509_certificate_id:
            raise errors.InvalidTransition("incompatible `resolution`")
    if resolution_id == dbCoverageAssuranceEvent.coverage_assurance_resolution_id:
        raise errors.InvalidTransition("No Change")
    dbCoverageAssuranceEvent.coverage_assurance_resolution_id = resolution_id
    ctx.dbSession.flush(objects=[dbCoverageAssuranceEvent])
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_DomainAutocert_without_AcmeOrder(
    ctx: "ApiContext",
    dbDomainAutocert: "DomainAutocert",
) -> bool:
    dbDomainAutocert.timestamp_finished = datetime.datetime.now(datetime.timezone.utc)
    dbDomainAutocert.is_successful = False
    ctx.dbSession.flush(objects=[dbDomainAutocert])
    return True


def update_DomainAutocert_with_AcmeOrder(
    ctx: "ApiContext",
    dbDomainAutocert: "DomainAutocert",
    dbAcmeOrder: Optional["AcmeOrder"] = None,
) -> Literal[True]:
    if not dbAcmeOrder:
        raise errors.InvalidTransition("missing `dbAcmeOrder`")
    dbDomainAutocert.acme_order_id = dbAcmeOrder.id
    dbDomainAutocert.timestamp_finished = datetime.datetime.now(datetime.timezone.utc)
    if dbAcmeOrder.acme_status_order == "valid":
        dbDomainAutocert.is_successful = True
    else:
        dbDomainAutocert.is_successful = False
    ctx.dbSession.flush(objects=[dbDomainAutocert])
    return True


def update_DomainAutocert_with_RenewalConfiguration(
    ctx: "ApiContext",
    dbDomainAutocert: "DomainAutocert",
    dbRenewalConfiguration: "RenewalConfiguration",
) -> Literal[True]:
    dbDomainAutocert.renewal_configuration_id = dbRenewalConfiguration.id
    ctx.dbSession.flush(objects=[dbDomainAutocert])
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_Notification__dismiss(
    ctx: "ApiContext",
    dbNotification: "Notification",
) -> Literal[True]:
    dbNotification.is_active = False
    ctx.dbSession.flush(objects=[dbNotification])
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_EnrollmentFactory(
    ctx: "ApiContext",
    dbEnrollmentFactory: "EnrollmentFactory",
    acme_account_id__primary: int,
    private_key_cycle__primary: str,
    private_key_technology__primary: str,
    acme_profile__primary: Optional[str],
    acme_account_id__backup: Optional[int],
    private_key_cycle__backup: Optional[str],
    private_key_technology__backup: Optional[str],
    acme_profile__backup: Optional[str],
    name: Optional[str],
    note: Optional[str],
    domain_template_http01: Optional[str],
    domain_template_dns01: Optional[str],
    label_template: Optional[str],
    is_export_filesystem_id: Optional[int],
) -> bool:
    if not any(
        (
            acme_account_id__primary,
            private_key_cycle__primary,
            private_key_technology__primary,
        )
    ):
        raise errors.InvalidTransition("Missing Required Primary.")

    # these require some validation
    name = lib_utils.normalize_unique_text(name) if name else None
    if name:
        if name.startswith("rc-") or name.startswith("global"):
            raise ValueError("`name` contains a reserved prefix or is a reserved word")

        existingEnrollmentFactory = get__EnrollmentFactory__by_name(ctx, name)
        if existingEnrollmentFactory and (
            existingEnrollmentFactory.id != dbEnrollmentFactory.id
        ):
            raise errors.InvalidTransition(
                "An EnrollmentFactory already exists with this name."
            )

    # default to original
    if is_export_filesystem_id is None:
        is_export_filesystem_id = dbEnrollmentFactory.is_export_filesystem_id

    dbAcmeAccountPrimary = get__AcmeAccount__by_id(ctx, acme_account_id__primary)
    if not dbAcmeAccountPrimary:
        raise errors.InvalidTransition("Could not load Primary")

    if not any((domain_template_http01, domain_template_dns01)):
        raise errors.InvalidTransition("must submit a template")

    if acme_account_id__backup:
        dbAcmeAccountBackup = get__AcmeAccount__by_id(ctx, acme_account_id__backup)
        if not dbAcmeAccountBackup:
            raise errors.InvalidTransition("Could not load Backup")
        if dbAcmeAccountPrimary.acme_server_id == dbAcmeAccountBackup.acme_server_id:
            raise errors.InvalidTransition(
                "Primary and Backup AcmeAccounts MUST be on different servers."
            )

    changes = False

    private_key_cycle_id__primary = model_utils.PrivateKeyCycle.from_string(
        private_key_cycle__primary
    )
    private_key_technology_id__primary = model_utils.KeyTechnology.from_string(
        private_key_technology__primary
    )

    private_key_cycle_id__backup = (
        model_utils.PrivateKeyCycle.from_string(private_key_cycle__backup)
        if private_key_cycle__backup
        else None
    )
    private_key_technology_id__backup = (
        model_utils.KeyTechnology.from_string(private_key_technology__backup)
        if private_key_technology__backup
        else None
    )

    if name != dbEnrollmentFactory.name:
        raise errors.InvalidTransition("`EnrollmentFactory.name` can not be changed.")

    pairings = (
        ("acme_account_id__primary", acme_account_id__primary),
        ("private_key_cycle_id__primary", private_key_cycle_id__primary),
        ("private_key_technology_id__primary", private_key_technology_id__primary),
        ("acme_profile__primary", acme_profile__primary),
        ("acme_account_id__backup", acme_account_id__backup),
        ("private_key_cycle_id__backup", private_key_cycle_id__backup),
        ("private_key_technology_id__backup", private_key_technology_id__backup),
        ("acme_profile__backup", acme_profile__backup),
        ("note", note),
        ("label_template", label_template),
        ("domain_template_http01", domain_template_http01),
        ("domain_template_dns01", domain_template_dns01),
        ("is_export_filesystem_id", is_export_filesystem_id),
    )
    for p in pairings:
        if getattr(dbEnrollmentFactory, p[0]) != p[1]:
            setattr(dbEnrollmentFactory, p[0], p[1])
            changes = True

    if changes:
        ctx.dbSession.flush(objects=[dbEnrollmentFactory])

    return changes


def update_PrivateKey__set_active(
    ctx: "ApiContext",
    dbPrivateKey: "PrivateKey",
) -> str:
    if dbPrivateKey.is_active:
        raise errors.InvalidTransition("Already activated.")
    if dbPrivateKey.is_compromised:
        raise errors.InvalidTransition("Can not activate a compromised key")
    dbPrivateKey.is_active = True
    ctx.dbSession.flush(objects=[dbPrivateKey])
    event_status = "PrivateKey__mark__active"
    return event_status


def update_PrivateKey__set_compromised(
    ctx: "ApiContext",
    dbPrivateKey: "PrivateKey",
    dbOperationsEvent: "OperationsEvent",
) -> str:
    if dbPrivateKey.is_compromised:
        raise errors.InvalidTransition("Already compromised")
    dbPrivateKey.is_active = False
    dbPrivateKey.is_compromised = True
    ctx.dbSession.flush(objects=[dbPrivateKey])

    lib.events.PrivateKey_compromised(
        ctx,
        dbPrivateKey,
        dbOperationsEvent=dbOperationsEvent,
    )

    event_status = "PrivateKey__mark__compromised"
    return event_status


def update_PrivateKey__unset_active(
    ctx: "ApiContext",
    dbPrivateKey: "PrivateKey",
) -> str:
    if not dbPrivateKey.is_active:
        raise errors.InvalidTransition("Already deactivated")
    dbPrivateKey.is_active = False
    ctx.dbSession.flush(objects=[dbPrivateKey])
    event_status = "PrivateKey__mark__inactive"
    return event_status


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_RenewalConfiguration__set_active(
    ctx: "ApiContext",
    dbRenewalConfiguration: "RenewalConfiguration",
) -> str:
    if dbRenewalConfiguration.is_active:
        raise errors.InvalidTransition("Already activated.")
    dbRenewalConfiguration.is_active = True
    ctx.dbSession.flush(objects=[dbRenewalConfiguration])
    event_status = "RenewalConfiguration__mark__active"
    return event_status


def update_RenewalConfiguration__unset_active(
    ctx: "ApiContext",
    dbRenewalConfiguration: "RenewalConfiguration",
) -> str:
    log.debug("update_RenewalConfiguration__unset_active", dbRenewalConfiguration.id)
    if not dbRenewalConfiguration.is_active:
        raise errors.InvalidTransition("Already deactivated.")
    dbRenewalConfiguration.is_active = False
    ctx.dbSession.flush(objects=[dbRenewalConfiguration])
    event_status = "RenewalConfiguration__mark__inactive"
    return event_status


def update_RenewalConfiguration__update_exports(
    ctx: "ApiContext",
    dbRenewalConfiguration: "RenewalConfiguration",
    action: Literal["is_export_filesystem-on", "is_export_filesystem-off"],
) -> str:
    log.debug("update_RenewalConfiguration__unset_active", dbRenewalConfiguration.id)
    if dbRenewalConfiguration.enrollment_factory_id__via:
        raise errors.InvalidTransition(
            "`is_export_filesystem` must be managed by the EnrollmentFactory"
        )

    if action == "is_export_filesystem-on":
        if (
            dbRenewalConfiguration.is_export_filesystem_id
            == model_utils.OptionsOnOff.ON
        ):
            raise errors.InvalidTransition("`is_export_filesystem` already on")
        dbRenewalConfiguration.is_export_filesystem_id = model_utils.OptionsOnOff.ON
        event_status = "RenewalConfiguration__mark__is_export_filesystem__on"
    elif action == "is_export_filesystem-off":
        if (
            dbRenewalConfiguration.is_export_filesystem_id
            == model_utils.OptionsOnOff.OFF
        ):
            raise errors.InvalidTransition("`is_export_filesystem` already off")
        dbRenewalConfiguration.is_export_filesystem_id = model_utils.OptionsOnOff.OFF
        event_status = "RenewalConfiguration__mark__is_export_filesystem__off"
    ctx.dbSession.flush(objects=[dbRenewalConfiguration])
    return event_status


def update_SystemConfiguration(
    ctx: "ApiContext",
    dbSystemConfiguration: "SystemConfiguration",
    acme_account_id__primary: int,
    private_key_cycle__primary: str,
    private_key_technology__primary: str,
    acme_profile__primary: Optional[str],
    acme_account_id__backup: Optional[int],
    private_key_cycle__backup: Optional[str],
    private_key_technology__backup: Optional[str],
    acme_profile__backup: Optional[str],
    force_reconciliation: bool = False,
) -> bool:
    if not any(
        (
            acme_account_id__primary,
            private_key_cycle__primary,
            private_key_technology__primary,
        )
    ):
        raise errors.InvalidTransition("Missing Required Primary.")

    dbAcmeAccountPrimary = get__AcmeAccount__by_id(ctx, acme_account_id__primary)
    if not dbAcmeAccountPrimary:
        raise errors.InvalidTransition("Could not load Primary")

    if acme_account_id__backup:
        dbAcmeAccountBackup = get__AcmeAccount__by_id(ctx, acme_account_id__backup)
        if not dbAcmeAccountBackup:
            raise errors.InvalidTransition("Could not load Backup")
        if dbAcmeAccountPrimary.acme_server_id == dbAcmeAccountBackup.acme_server_id:
            raise errors.InvalidTransition(
                "Primary and Backup AcmeAccounts MUST be on different servers."
            )

    changes = []

    private_key_cycle_id__primary = model_utils.PrivateKeyCycle.from_string(
        private_key_cycle__primary
    )
    private_key_technology_id__primary = model_utils.KeyTechnology.from_string(
        private_key_technology__primary
    )

    private_key_cycle_id__backup = (
        model_utils.PrivateKeyCycle.from_string(private_key_cycle__backup)
        if private_key_cycle__backup
        else None
    )
    private_key_technology_id__backup = (
        model_utils.KeyTechnology.from_string(private_key_technology__backup)
        if private_key_technology__backup
        else None
    )

    # global MUST only allow account defaults
    # otherwise everything gets too confusing
    if dbSystemConfiguration.name == "global":
        # primary
        if acme_profile__primary != "@":
            raise errors.InvalidTransition("Global `acme_profile__primary` MUST be `@`")
        if private_key_cycle_id__primary != model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT:
            raise errors.InvalidTransition(
                "Global `private_key_cycle__primary` MUST be `account_default`"
            )
        if (
            private_key_technology_id__primary
            != model_utils.KeyTechnology.ACCOUNT_DEFAULT
        ):
            raise errors.InvalidTransition(
                "Global `private_key_technology__primary` MUST be `account_default`"
            )
        # backup
        if acme_profile__backup != "@":
            raise errors.InvalidTransition("Global `acme_profile__backup` MUST be `@`")
        if private_key_cycle_id__backup != model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT:
            raise errors.InvalidTransition(
                "Global `private_key_cycle__backup` MUST be `account_default`"
            )
        if (
            private_key_technology_id__backup
            != model_utils.KeyTechnology.ACCOUNT_DEFAULT
        ):
            raise errors.InvalidTransition(
                "Global `private_key_technology__backup` MUST be `account_default`"
            )

    pairings = (
        ("acme_account_id__primary", acme_account_id__primary),
        ("private_key_cycle_id__primary", private_key_cycle_id__primary),
        ("private_key_technology_id__primary", private_key_technology_id__primary),
        ("acme_profile__primary", acme_profile__primary),
        ("acme_account_id__backup", acme_account_id__backup),
        ("private_key_cycle_id__backup", private_key_cycle_id__backup),
        ("private_key_technology_id__backup", private_key_technology_id__backup),
        ("acme_profile__backup", acme_profile__backup),
    )
    for p in pairings:
        if getattr(dbSystemConfiguration, p[0]) != p[1]:
            setattr(dbSystemConfiguration, p[0], p[1])
            changes.append(p[0])

    if changes or force_reconciliation:
        if not dbSystemConfiguration.is_configured:
            if dbSystemConfiguration.acme_account_id__primary:
                dbSystemConfiguration.is_configured = True
        ctx.dbSession.flush(objects=[dbSystemConfiguration])

    return True if changes else False


def update_X509Certificate__mark_compromised(
    ctx: "ApiContext",
    dbX509Certificate: "X509Certificate",
    via_PrivateKey_compromised: Optional[bool] = None,
) -> str:
    # the PrivateKey has been compromised
    dbX509Certificate.is_compromised_private_key = True
    dbX509Certificate.is_revoked = True  # NOTE: this has nothing to do with the acme-server, it is just a local marking
    if dbX509Certificate.is_active:
        dbX509Certificate.is_active = False
    ctx.dbSession.flush(objects=[dbX509Certificate])
    event_status = "X509Certificate__mark__compromised"
    return event_status


def update_X509Certificate__set_active(
    ctx: "ApiContext",
    dbX509Certificate: "X509Certificate",
) -> str:
    if dbX509Certificate.is_active:
        raise errors.InvalidTransition("Already active.")

    if dbX509Certificate.is_revoked:
        raise errors.InvalidTransition(
            "Certificate is revoked; `active` status can not be changed."
        )

    if dbX509Certificate.is_compromised_private_key:
        raise errors.InvalidTransition(
            "Certificate has a compromised PrivateKey; `active` status can not be changed."
        )

    if dbX509Certificate.is_deactivated:
        raise errors.InvalidTransition(
            "Certificate was deactivated; `active` status can not be changed."
        )

    # now make it active!
    dbX509Certificate.is_active = True
    ctx.dbSession.flush(objects=[dbX509Certificate])

    # cleanup options
    event_status = "X509Certificate__mark__active"
    return event_status


"""
as of 1.0, AcmeOrders do not; must use a RenewalConfiguration
as of .40, X509Certificates do not auto-renew. Instead, AcmeOrders do.

def update_X509Certificate__set_renew_auto(ctx, dbX509Certificate,):
    if dbX509Certificate.renewals_managed_by == "AcmeOrder":
        raise errors.InvalidTransition("auto-renew is managed by the AcmeOrder")
    if dbX509Certificate.is_auto_renew:
        raise errors.InvalidTransition("Already active.")
    # activate!
    dbX509Certificate.is_auto_renew = True
    event_status = "X509Certificate__mark__renew_auto"
    return event_status


def update_X509Certificate__set_renew_manual(ctx, dbX509Certificate,):
    if dbX509Certificate.renewals_managed_by == "AcmeOrder":
        raise errors.InvalidTransition("auto-renew is managed by the AcmeOrder")
    if not dbX509Certificate.is_auto_renew:
        raise errors.InvalidTransition("Already inactive.")
    # deactivate!
    dbX509Certificate.is_auto_renew = False
    event_status = "X509Certificate__mark__renew_manual"
    return event_status
"""


def update_X509Certificate__set_revoked(
    ctx: "ApiContext",
    dbX509Certificate: "X509Certificate",
) -> str:
    if dbX509Certificate.is_revoked:
        raise errors.InvalidTransition("Certificate is already revoked")

    # mark revoked
    dbX509Certificate.is_revoked = True

    # inactivate it
    dbX509Certificate.is_active = False

    # deactivate it, permanently
    dbX509Certificate.is_deactivated = True

    ctx.dbSession.flush(objects=[dbX509Certificate])

    # cleanup options
    event_status = "X509Certificate__mark__revoked"
    return event_status


def update_X509Certificate__unset_active(
    ctx: "ApiContext",
    dbX509Certificate: "X509Certificate",
) -> str:
    if not dbX509Certificate.is_active:
        raise errors.InvalidTransition("Already inactive.")

    # inactivate it
    dbX509Certificate.is_active = False

    ctx.dbSession.flush(objects=[dbX509Certificate])

    event_status = "X509Certificate__mark__inactive"
    return event_status


def update_X509Certificate__unset_revoked(
    ctx: "ApiContext",
    dbX509Certificate: "X509Certificate",
) -> str:
    """
    this is currently not supported
    """

    if not dbX509Certificate.is_revoked:
        raise errors.InvalidTransition("Certificate is not revoked")

    # unset the revoke
    dbX509Certificate.is_revoked = False

    ctx.dbSession.flush(objects=[dbX509Certificate])

    # lead is_active and is_deactivated as-is
    # cleanup options
    event_status = "X509Certificate__mark__unrevoked"
    return event_status
