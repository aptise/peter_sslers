# stdlib
import datetime
import logging
from typing import Dict
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
from dateutil import parser as dateutil_parser

# localapp
from .get import get__AcmeAccount__GlobalDefault
from .get import get__AcmeAccountProvider__default
from .get import get__AcmeDnsServer__by_root_url
from .get import get__AcmeDnsServer__GlobalDefault
from .get import get__Domain__by_name
from .logger import _log_object_event
from .. import errors
from .. import utils
from ... import lib
from ...lib import events as _events  # noqa: F401
from ...model import objects as model_objects
from ...model import utils as model_utils

if TYPE_CHECKING:
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeAccountProvider
    from ...model.objects import AcmeAuthorization
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeOrder
    from ...model.objects import AcmeOrderless
    from ...model.objects import CertificateSigned
    from ...model.objects import CertificateCAPreference
    from ...model.objects import CoverageAssuranceEvent
    from ...model.objects import Domain
    from ...model.objects import DomainAutocert
    from ...model.objects import OperationsEvent
    from ...model.objects import PrivateKey
    from ...model.objects import QueueCertificate
    from ...model.objects import QueueDomain
    from ..utils import ApiContext

# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


def update_AcmeAccountProvider__activate_default(
    ctx: "ApiContext",
    dbAcmeAccountProvider_new: "AcmeAccountProvider",
) -> str:
    _objs = [
        dbAcmeAccountProvider_new,
    ]
    dbAcmeAccountProvider_default = get__AcmeAccountProvider__default(ctx)
    if dbAcmeAccountProvider_default:
        _objs.append(dbAcmeAccountProvider_default)
        if dbAcmeAccountProvider_default.id != dbAcmeAccountProvider_new.id:
            dbAcmeAccountProvider_default.is_default = False
    if not dbAcmeAccountProvider_new.is_default:
        dbAcmeAccountProvider_new.is_default = True
    if not dbAcmeAccountProvider_new.is_enabled:
        dbAcmeAccountProvider_new.is_enabled = True
    ctx.dbSession.flush(_objs)
    event_status = "AcmeAccountProvider__activate_default"
    return event_status


def update_AcmeAccountProvider__set_is_enabled(
    ctx: "ApiContext",
    dbAcmeAccountProvider: "AcmeAccountProvider",
) -> str:
    if dbAcmeAccountProvider.is_enabled:
        raise errors.InvalidTransition("Already enabled")
    dbAcmeAccountProvider.is_enabled = True
    event_status = "AcmeAccountProvider__mark__is_enabled"
    return event_status


def update_AcmeAccount_from_new_duplicate(
    ctx: "ApiContext",
    dbAcmeAccountTarget: "AcmeAccount",
    dbAcmeAccountDuplicate: "AcmeAccount",
) -> bool:
    """
    Invoke this to migrate the duplicate `AcmeAccount`'s information onto the original account

    ONLY INVOKE THIS ON A NEWLY CREATED DUPLICATE

    Account Fields:
        - account_url
        - terms_of_service
    """
    if dbAcmeAccountTarget.id == dbAcmeAccountDuplicate.id:
        raise ValueError("The Target and Duplicate `AcmeAccount` must be different")

    # make sure this is the right provider
    if (
        dbAcmeAccountTarget.acme_account_provider_id
        != dbAcmeAccountDuplicate.acme_account_provider_id
    ):
        raise ValueError(
            "New Account `deduplication` requires a single `AcmeAccountProvider`"
        )

    raise ValueError("TESTING NEEDED")
    with ctx.dbSession.no_autoflush:
        log.info("Attempting to migrate the following:")
        log.info("TARGET record:")
        log.info(" dbAcmeAccountTarget.id", dbAcmeAccountTarget.id)
        log.info(" dbAcmeAccountTarget.account_url", dbAcmeAccountTarget.account_url)
        log.info(
            " dbAcmeAccountTarget.acme_account_key.id",
            dbAcmeAccountTarget.acme_account_key.acme_account_id,
        )
        log.info("SOURCE record:")
        log.info(" dbAcmeAccountDuplicate.id", dbAcmeAccountDuplicate.id)
        log.info(
            " dbAcmeAccountDuplicate.account_url", dbAcmeAccountDuplicate.account_url
        )
        log.info(
            " dbAcmeAccountDuplicate.acme_account_key.id",
            dbAcmeAccountDuplicate.acme_account_key.acme_account_id,
        )

        # stash & clear the account_url
        account_url = dbAcmeAccountDuplicate.account_url
        dbAcmeAccountDuplicate.account_url = None
        ctx.dbSession.flush([dbAcmeAccountDuplicate])

        # Migrate the Account fields:
        dbAcmeAccountTarget.account_url = account_url
        dbAcmeAccountTarget.terms_of_service = dbAcmeAccountDuplicate.terms_of_service
        ctx.dbSession.flush([dbAcmeAccountTarget])

        # Migrate the AcmeAccountKey
        # alias the keys
        dbAcmeAccountKey_old = dbAcmeAccountTarget.acme_account_key
        dbAcmeAccountKey_new = dbAcmeAccountDuplicate.acme_account_key
        if not dbAcmeAccountKey_new.is_active:
            raise ValueError(
                "the Duplicate AcmeAccount's AcmeAccountKey should be active!"
            )
        # Step 1 - Disable the Target's OLD key
        dbAcmeAccountKey_old.is_active = None  # False violates the unique index

        # Step 2: ReAssociate the NEW key
        dbAcmeAccountKey_new.acme_account_id = dbAcmeAccountTarget.id
        dbAcmeAccountTarget.acme_account_key = dbAcmeAccountKey_new
        ctx.dbSession.flush()

        # now, handle the OperationsObject logs:
        # first, get all the logs for the Duplicate account
        logs = (
            ctx.dbSession.query(model_objects.OperationsObjectEvent)
            .filter(
                model_objects.OperationsObjectEvent.acme_account_id
                == dbAcmeAccountDuplicate.id
            )
            .all()
        )
        for _log in logs:
            if _log.acme_account_key_id == dbAcmeAccountKey_new.id:
                # if the record references the new key, upgrade the account id to the Target
                _log.acme_account_id = dbAcmeAccountTarget.id
            elif _log.acme_account_key_id is None:
                # if the record does not mention the key, it is safe to delete
                ctx.dbSession.delete(_log)
            else:
                raise ValueError("this should not happen")
        ctx.dbSession.flush()

        # finally, delete the duplicate
        ctx.dbSession.delete(dbAcmeAccountDuplicate)
        ctx.dbSession.flush()

    return True


def update_AcmeAccount__set_active(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
) -> str:
    if dbAcmeAccount.is_active:
        raise errors.InvalidTransition("Already activated.")
    if dbAcmeAccount.timestamp_deactivated:
        raise errors.InvalidTransition("AccountKey was deactivated.")
    dbAcmeAccount.is_active = True
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
    event_status = "AcmeAccount__mark__deactivated"
    return event_status


def update_AcmeAccount__unset_active(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
) -> str:
    log.debug("update_AcmeAccount__unset_active", dbAcmeAccount.id)
    if not dbAcmeAccount.is_active:
        raise errors.InvalidTransition("Already deactivated.")
    if dbAcmeAccount.is_global_default:
        raise errors.InvalidTransition(
            "You can not deactivate the global default. Set another `AcmeAccount` as the global default first."
        )
    dbAcmeAccount.is_active = False
    event_status = "AcmeAccount__mark__inactive"
    return event_status


def update_AcmeAccount__set_global_default(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
) -> Tuple[str, Dict]:
    if dbAcmeAccount.is_global_default:
        # `formStash.fatal_form(` will raise a `FormInvalid()`
        raise errors.InvalidTransition("Already global default.")

    if not dbAcmeAccount.acme_account_provider.is_default:
        raise errors.InvalidTransition(
            "This AcmeAccount is not from the default AcmeAccountProvider."
        )

    alt_info: Dict = {}
    formerDefaultAccount = get__AcmeAccount__GlobalDefault(ctx)
    if formerDefaultAccount:
        formerDefaultAccount.is_global_default = False
        alt_info["event_payload_dict"] = {
            "acme_account_id.former_default": formerDefaultAccount.id,
        }
        alt_info["event_alt"] = ("AcmeAccount__mark__notdefault", formerDefaultAccount)
    dbAcmeAccount.is_global_default = True
    event_status = "AcmeAccount__mark__default"
    return event_status, alt_info


def update_AcmeAccount__private_key_cycle(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    private_key_cycle: str,
) -> str:
    if dbAcmeAccount.private_key_cycle == private_key_cycle:
        raise errors.InvalidTransition("Already updated: `private_key_cycle`")
    try:
        private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            private_key_cycle
        )
    except KeyError:
        raise errors.InvalidTransition("Invalid option: `private_key_cycle`")
    if (
        private_key_cycle_id
        not in model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle_id
    ):
        raise errors.InvalidTransition("Invalid option: `private_key_cycle`")
    dbAcmeAccount.private_key_cycle_id = private_key_cycle_id
    event_status = "AcmeAccount__edit__private_key_cycle"
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
    event_status = "AcmeAccount__edit__private_key_technology"
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
    if (
        authorization_status
        not in model_utils.Acme_Status_Authorization.OPTIONS_X_UPDATE
    ):
        timestamp_expires = authorization_payload.get("expires")
        if timestamp_expires:
            timestamp_expires = dateutil_parser.parse(timestamp_expires)
            timestamp_expires = timestamp_expires.replace(tzinfo=None)

        identifer = authorization_payload["identifier"]
        if identifer["type"] != "dns":
            raise ValueError("unexpected authorization payload: identifier type")
        domain_name = identifer["value"]
        dbDomain = get__Domain__by_name(ctx, domain_name, preload=False)
        if not dbDomain:
            raise ValueError(
                "This `Domain` name has not been seen before. This should not be possible."
            )

        if dbAcmeAuthorization.domain_id != dbDomain.id:
            dbAcmeAuthorization.domain_id = dbDomain.id
            _updated = True
        if dbAcmeAuthorization.timestamp_expires != timestamp_expires:
            dbAcmeAuthorization.timestamp_expires = timestamp_expires
            _updated = True

    if dbAcmeAuthorization.acme_status_authorization_id != acme_status_authorization_id:
        dbAcmeAuthorization.acme_status_authorization_id = acme_status_authorization_id
        _updated = True

    if _updated:
        dbAcmeAuthorization.timestamp_updated = datetime.datetime.utcnow()
        ctx.dbSession.flush(objects=[dbAcmeAuthorization])
        return True

    return False


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
        formerDefault.is_global_default = False
        alt_info["event_payload_dict"] = {
            "acme_dns_server_id.former_default": formerDefault.id,
        }
        alt_info["event_alt"] = ("AcmeDnsServer__mark__notdefault", formerDefault)
        ctx.dbSession.flush(objects=[formerDefault])
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
    return True


def update_AcmeOrder_set_renew_auto(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
) -> str:
    if dbAcmeOrder.is_auto_renew:
        raise errors.InvalidTransition("Can not mark this `AcmeOrder` for renewal.")
    # set the renewal
    dbAcmeOrder.is_auto_renew = True
    # cleanup options
    event_status = "AcmeOrder__mark__renew_auto"
    return event_status


def update_AcmeOrder_set_renew_manual(
    ctx: "ApiContext",
    dbAcmeOrder: "AcmeOrder",
) -> str:
    if not dbAcmeOrder.is_auto_renew:
        raise errors.InvalidTransition("Can not unmark this `AcmeOrder` for renewal.")
    # unset the renewal
    dbAcmeOrder.is_auto_renew = False
    # cleanup options
    event_status = "AcmeOrder__mark__renew_manual"
    return event_status


def update_AcmeOrderless_deactivate(
    ctx: "ApiContext",
    dbAcmeOrderless: "AcmeOrderless",
) -> bool:
    """
    `deactivate` should mark the order as:
        `is_processing = False`
    """
    dbAcmeOrderless.is_processing = False
    dbAcmeOrderless.timestamp_updated = ctx.timestamp
    ctx.dbSession.flush(objects=[dbAcmeOrderless])
    return True


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
    return True


def update_Domain_disable(
    ctx: "ApiContext",
    dbDomain: "Domain",
    dbOperationsEvent: "OperationsEvent",
    event_status: str = "Domain__mark__inactive",
    action: str = "deactivated",
) -> bool:
    """
    Disables a domain

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomain: (required) A :class:`model.objects.Domain` object
    :param dbOperationsEvent: (required) A :class:`model.objects.OperationsObjectEvent` object

    :param event_status: (optional) A string event status conforming to :class:`model_utils.OperationsObjectEventStatus`
    :param action: (optional) A string action. default = "deactivated"
    """
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["domain.id"] = dbDomain.id
    event_payload_dict["action"] = action
    dbDomain.is_active = False
    ctx.dbSession.flush(objects=[dbDomain])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            event_status
        ),
        dbDomain=dbDomain,
    )
    return True


def update_Domain_enable(
    ctx: "ApiContext",
    dbDomain: "Domain",
    dbOperationsEvent: "OperationsEvent",
    event_status="Domain__mark__active",
    action="activated",
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomain: (required) A :class:`model.objects.Domain` object
    :param dbOperationsEvent: (required) A :class:`model.objects.OperationsObjectEvent` object

    :param event_status: (optional) A string event status conforming to :class:`model_utils.OperationsObjectEventStatus`
    :param action: (optional) A string action. default = "activated"
    """
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["domain.id"] = dbDomain.id
    event_payload_dict["action"] = action
    dbDomain.is_active = True
    ctx.dbSession.flush(objects=[dbDomain])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            event_status
        ),
        dbDomain=dbDomain,
    )
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_DomainAutocert_without_AcmeOrder(
    ctx: "ApiContext",
    dbDomainAutocert: "DomainAutocert",
) -> bool:
    dbDomainAutocert.timestamp_finished = datetime.datetime.utcnow()
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
    dbDomainAutocert.timestamp_finished = datetime.datetime.utcnow()
    if dbAcmeOrder.acme_status_order == "valid":
        dbDomainAutocert.is_successful = True
    else:
        dbDomainAutocert.is_successful = False
    ctx.dbSession.flush(objects=[dbDomainAutocert])
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_PrivateKey__set_active(
    ctx: "ApiContext",
    dbPrivateKey: "PrivateKey",
) -> str:
    if dbPrivateKey.is_active:
        raise errors.InvalidTransition("Already activated.")
    if dbPrivateKey.is_compromised:
        raise errors.InvalidTransition("Can not activate a compromised key")
    dbPrivateKey.is_active = True
    event_status = "PrivateKey__mark__active"
    return event_status


def update_PrivateKey__unset_active(
    ctx: "ApiContext",
    dbPrivateKey: "PrivateKey",
) -> str:
    if not dbPrivateKey.is_active:
        raise errors.InvalidTransition("Already deactivated")
    dbPrivateKey.is_active = False
    event_status = "PrivateKey__mark__inactive"
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


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_QueueCertificate__cancel(
    ctx: "ApiContext",
    dbQueueCertificate: "QueueCertificate",
) -> str:
    if dbQueueCertificate.is_active is None:
        raise errors.InvalidTransition("Already cancelled")
    elif dbQueueCertificate.is_active is False:
        raise errors.InvalidTransition("Already processed")
    dbQueueCertificate.is_active = False
    dbQueueCertificate.timestamp_processed = ctx.timestamp
    ctx.dbSession.flush(objects=[dbQueueCertificate])
    event_status = "QueueCertificate__mark__cancelled"
    return event_status


def update_QueuedDomain_dequeue(
    ctx: "ApiContext",
    dbQueueDomain: "QueueDomain",
    dbOperationsEvent: "OperationsEvent",
    event_status="QueueDomain__mark__cancelled",
    action="de-queued",
) -> bool:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbQueueDomain: (required) The :class:`model.objects.QueueDomain`
    :param dbOperationsEvent:
    :param event_status:
    :param action:
    """
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["queue_domain.id"] = dbQueueDomain.id
    event_payload_dict["action"] = action

    dbQueueDomain.is_active = None
    dbQueueDomain.timestamp_processed = ctx.timestamp
    ctx.dbSession.flush(objects=[dbQueueDomain])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            event_status
        ),
        dbQueueDomain=dbQueueDomain,
    )
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


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

    # cleanup options
    event_status = "CertificateSigned__mark__active"
    return event_status


def update_CertificateSigned__unset_active(
    ctx: "ApiContext",
    dbCertificateSigned: "CertificateSigned",
) -> str:
    if not dbCertificateSigned.is_active:
        raise errors.InvalidTransition("Already inactive.")

    # inactivate it
    dbCertificateSigned.is_active = False

    event_status = "CertificateSigned__mark__inactive"
    return event_status


"""
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

    # cleanup options
    event_status = "CertificateSigned__mark__revoked"
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

    # lead is_active and is_deactivated as-is
    # cleanup options
    event_status = "CertificateSigned__mark__unrevoked"
    return event_status
