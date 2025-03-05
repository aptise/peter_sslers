# stdlib
import datetime
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
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
from .get import get__AcmeDnsServer__by_root_url
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
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeServer
    from ...model.objects import AcmeAuthorization
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeOrder
    from ...model.objects import CertificateSigned
    from ...model.objects import CertificateCAPreference
    from ...model.objects import CoverageAssuranceEvent
    from ...model.objects import DomainAutocert
    from ...model.objects import EnrollmentFactory
    from ...model.objects import Notification
    from ...model.objects import SystemConfiguration
    from ...model.objects import OperationsEvent
    from ...model.objects import PrivateKey
    from ...model.objects import RenewalConfiguration
    from ..context import ApiContext

# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


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
        # `formStash.fatal_form(` will raise a `FormInvalid()`
        raise errors.InvalidTransition("Already global default.")

    if not dbAcmeDnsServer.is_active:
        # `formStash.fatal_form(` will raise a `FormInvalid()`
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


def update_AcmeDnsServer__root_url(
    ctx: "ApiContext",
    dbAcmeDnsServer: "AcmeDnsServer",
    root_url: str,
) -> bool:
    if dbAcmeDnsServer.root_url == root_url:
        raise errors.InvalidTransition("No change")
    dbAcmeDnsServerAlt = get__AcmeDnsServer__by_root_url(ctx, root_url)
    if dbAcmeDnsServerAlt:
        raise errors.InvalidTransition(
            "Another acme-dns Server is enrolled with this same root url."
        )
    dbAcmeDnsServer.root_url = root_url
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
) -> bool:
    """
    `deactivate` should mark the order as:
        `is_processing = False`
    """
    if dbAcmeOrder.is_processing is not True:
        raise errors.InvalidTransition("This `AcmeOrder` is not processing.")
    dbAcmeOrder.is_processing = False
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
        _updates = [
            dbAcmeOrder,
        ]
        for _pending in dbAcmeOrder.acme_authorization_potentials:
            ctx.dbSession.delete(_pending)
            _updates.append(_pending)
        ctx.dbSession.flush(objects=_updates)
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
    acme_directory: Dict,
) -> bool:
    # the LetsEncrypt server puts in a random entry, so the directory changes
    directory_string = acme_v2.serialize_directory_object(acme_directory)
    _changed = False
    if (not dbAcmeServer.directory_latest) or (
        dbAcmeServer.directory_latest.directory != directory_string
    ):
        initial_config = True if not dbAcmeServer.directory_latest else False
        directoryLatest = create__AcmeServerConfiguration(  # noqa: F841
            ctx,
            dbAcmeServer,
            directory_string,
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
    _meta, _profiles_str = acme_v2.parse_acme_directory(acme_directory)
    if _profiles_str != dbAcmeServer.profiles:
        _result = update_AcmeServer_profiles(  # noqa: F841
            ctx, dbAcmeServer, _profiles_str
        )
        _changed = True

    if _changed:
        ctx.dbSession.flush(objects=[dbAcmeServer])

    return _changed


def update_CertificateCAPreference_reprioritize(
    ctx: "ApiContext",
    dbPreference_active: "CertificateCAPreference",
    dbCertificateCAPreferences: Sequence["CertificateCAPreference"],
    priority: str,
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbPreference_active: (required) A single instance of
        :class:`model.objects.CertificateCAPreference` which is being moved
        within the Preference list
    :param dbCertificateCAPreferences: (required) The full listing of
        :class:`model.objects.CertificateCAPreference` objects
    :param priority: string. required. must be "increase" or "decrease"
    """
    dbPref_other = None
    if priority == "increase":
        if dbPreference_active.id <= 1:
            raise errors.InvalidTransition(
                "This item can not be increased in priority."
            )
        target_slot_id = dbPreference_active.id - 1
        # okay, now iterate over the list...
        for _dbPref in dbCertificateCAPreferences:
            if _dbPref.id == target_slot_id:
                dbPref_other = _dbPref
                break
        if not dbPref_other:
            raise errors.InvalidTransition("Illegal Operation.")

        # set the other to a placeholder
        dbPref_other.id = 999
        ctx.dbSession.flush(objects=[dbPref_other])

        # set the new
        dbPreference_active.id = target_slot_id
        ctx.dbSession.flush(objects=[dbPreference_active])

        # and update the other
        dbPref_other.id = dbPreference_active.id + 1
        ctx.dbSession.flush(objects=[dbPref_other])

    elif priority == "decrease":
        if dbPreference_active.id == len(dbCertificateCAPreferences):
            raise errors.InvalidTransition(
                "This item can not be decreased in priority."
            )
        target_slot_id = dbPreference_active.id + 1
        # okay, now iterate over the list...
        for _dbPref in dbCertificateCAPreferences:
            if _dbPref.id == target_slot_id:
                dbPref_other = _dbPref
                break
        if not dbPref_other:
            raise errors.InvalidTransition("Illegal Operation.")

        # set the old to a placeholder
        dbPref_other.id = 999
        ctx.dbSession.flush(objects=[dbPref_other])

        # set the new
        dbPreference_active.id = target_slot_id
        ctx.dbSession.flush(objects=[dbPreference_active])

        # and update the other
        dbPref_other.id = dbPreference_active.id - 1
        ctx.dbSession.flush(objects=[dbPref_other])

    else:
        # `formStash.fatal_form(` will raise a `FormInvalid()`
        raise errors.InvalidTransition("Invalid priority.")

    return True


def update_CertificateSigned__mark_compromised(
    ctx: "ApiContext",
    dbCertificateSigned: "CertificateSigned",
    via_PrivateKey_compromised: Optional[bool] = None,
) -> str:
    # the PrivateKey has been compromised
    dbCertificateSigned.is_compromised_private_key = True
    dbCertificateSigned.is_revoked = True  # NOTE: this has nothing to do with the acme-server, it is just a local marking
    if dbCertificateSigned.is_active:
        dbCertificateSigned.is_active = False
    ctx.dbSession.flush(objects=[dbCertificateSigned])
    event_status = "CertificateSigned__mark__compromised"
    return event_status


def update_CertificateSigned__set_active(
    ctx: "ApiContext",
    dbCertificateSigned: "CertificateSigned",
) -> str:
    if dbCertificateSigned.is_active:
        raise errors.InvalidTransition("Already active.")

    if dbCertificateSigned.is_revoked:
        raise errors.InvalidTransition(
            "Certificate is revoked; `active` status can not be changed."
        )

    if dbCertificateSigned.is_compromised_private_key:
        raise errors.InvalidTransition(
            "Certificate has a compromised PrivateKey; `active` status can not be changed."
        )

    if dbCertificateSigned.is_deactivated:
        raise errors.InvalidTransition(
            "Certificate was deactivated; `active` status can not be changed."
        )

    # now make it active!
    dbCertificateSigned.is_active = True
    ctx.dbSession.flush(objects=[dbCertificateSigned])

    # cleanup options
    event_status = "CertificateSigned__mark__active"
    return event_status


"""
as of 1.0, AcmeOrders do not; must use a RenewalConfiguration
as of .40, CertificateSigneds do not auto-renew. Instead, AcmeOrders do.

def update_CertificateSigned__set_renew_auto(ctx, dbCertificateSigned,):
    if dbCertificateSigned.renewals_managed_by == "AcmeOrder":
        raise errors.InvalidTransition("auto-renew is managed by the AcmeOrder")
    if dbCertificateSigned.is_auto_renew:
        raise errors.InvalidTransition("Already active.")
    # activate!
    dbCertificateSigned.is_auto_renew = True
    event_status = "CertificateSigned__mark__renew_auto"
    return event_status


def update_CertificateSigned__set_renew_manual(ctx, dbCertificateSigned,):
    if dbCertificateSigned.renewals_managed_by == "AcmeOrder":
        raise errors.InvalidTransition("auto-renew is managed by the AcmeOrder")
    if not dbCertificateSigned.is_auto_renew:
        raise errors.InvalidTransition("Already inactive.")
    # deactivate!
    dbCertificateSigned.is_auto_renew = False
    event_status = "CertificateSigned__mark__renew_manual"
    return event_status
"""


def update_CertificateSigned__set_revoked(
    ctx: "ApiContext",
    dbCertificateSigned: "CertificateSigned",
) -> str:
    if dbCertificateSigned.is_revoked:
        raise errors.InvalidTransition("Certificate is already revoked")

    # mark revoked
    dbCertificateSigned.is_revoked = True

    # inactivate it
    dbCertificateSigned.is_active = False

    # deactivate it, permanently
    dbCertificateSigned.is_deactivated = True

    ctx.dbSession.flush(objects=[dbCertificateSigned])

    # cleanup options
    event_status = "CertificateSigned__mark__revoked"
    return event_status


def update_CertificateSigned__unset_active(
    ctx: "ApiContext",
    dbCertificateSigned: "CertificateSigned",
) -> str:
    if not dbCertificateSigned.is_active:
        raise errors.InvalidTransition("Already inactive.")

    # inactivate it
    dbCertificateSigned.is_active = False

    ctx.dbSession.flush(objects=[dbCertificateSigned])

    event_status = "CertificateSigned__mark__inactive"
    return event_status


def update_CertificateSigned__unset_revoked(
    ctx: "ApiContext",
    dbCertificateSigned: "CertificateSigned",
) -> str:
    """
    this is currently not supported
    """

    if not dbCertificateSigned.is_revoked:
        raise errors.InvalidTransition("Certificate is not revoked")

    # unset the revoke
    dbCertificateSigned.is_revoked = False

    ctx.dbSession.flush(objects=[dbCertificateSigned])

    # lead is_active and is_deactivated as-is
    # cleanup options
    event_status = "CertificateSigned__mark__unrevoked"
    return event_status


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
        if dbCoverageAssuranceEvent.certificate_signed_id:
            raise errors.InvalidTransition("incompatible `resolution`")
    elif resolution == "CertificateSigned_replaced":
        if not dbCoverageAssuranceEvent.certificate_signed_id:
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
) -> bool:
    if not dbAcmeOrder:
        raise errors.InvalidTransition("missing `AcmeOrder`")
    dbDomainAutocert.acme_order_id = dbAcmeOrder.id
    dbDomainAutocert.timestamp_finished = datetime.datetime.now(datetime.timezone.utc)
    if dbAcmeOrder.acme_status_order == "valid":
        dbDomainAutocert.is_successful = True
    else:
        dbDomainAutocert.is_successful = False
    ctx.dbSession.flush(objects=[dbDomainAutocert])
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_Notification__dismiss(
    ctx: "ApiContext",
    dbNotification: "Notification",
) -> bool:
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
    is_export_filesystem: Optional[bool],
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
    if name:
        existingEnrollmentFactory = get__EnrollmentFactory__by_name(ctx, name)
        if existingEnrollmentFactory and (
            existingEnrollmentFactory.id != dbEnrollmentFactory.id
        ):
            raise errors.InvalidTransition(
                "An EnrollmentFactory already exists with this name."
            )

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

    name = lib_utils.normalize_unique_text(name) if name else None
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
        ("domain_template_http01", domain_template_http01),
        ("domain_template_dns01", domain_template_dns01),
        ("is_export_filesystem", is_export_filesystem),
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
            changes = True

    if changes:
        if not dbSystemConfiguration.is_configured:
            if dbSystemConfiguration.acme_account_id__primary:
                dbSystemConfiguration.is_configured = True
        ctx.dbSession.flush(objects=[dbSystemConfiguration])

    return changes
