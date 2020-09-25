from __future__ import print_function

# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime
import pdb

# pypi
from dateutil import parser as dateutil_parser

# localapp
from ...model import objects as model_objects
from ...model import utils as model_utils
from ...lib import errors
from ... import lib
from .. import utils
from .get import get__AcmeAccount__GlobalDefault
from .get import get__AcmeAccountProvider__default
from .get import get__AcmeDnsServer__GlobalDefault
from .get import get__AcmeDnsServer__by_root_url
from .get import get__Domain__by_name
from .logger import _log_object_event


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_AcmeAccountProvider__activate_default(ctx, dbAcmeAccountProvider_new):
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


def update_AcmeAccountProvider__set_is_enabled(ctx, dbAcmeAccountProvider):
    if dbAcmeAccountProvider.is_enabled:
        raise errors.InvalidTransition("Already enabled")
    dbAcmeAccountProvider.is_enabled = True
    event_status = "AcmeAccountProvider__mark__is_enabled"
    return event_status


def update_AcmeAccount_from_new_duplicate(
    ctx, dbAcmeAccountTarget, dbAcmeAccountDuplicate
):
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

    with ctx.dbSession.no_autoflush:
        print("Attempting to migrate the following:")
        print("TARGET record:")
        print(" dbAcmeAccountTarget.id", dbAcmeAccountTarget.id)
        print(" dbAcmeAccountTarget.account_url", dbAcmeAccountTarget.account_url)
        print(
            " dbAcmeAccountTarget.acme_account_key.id",
            dbAcmeAccountTarget.acme_account_key.acme_account_id,
        )
        print("SOURCE record:")
        print(" dbAcmeAccountDuplicate.id", dbAcmeAccountDuplicate.id)
        print(" dbAcmeAccountDuplicate.account_url", dbAcmeAccountDuplicate.account_url)
        print(
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
        dbAcmeAccountKey_old.is_active = False

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


def update_AcmeAccount__set_active(ctx, dbAcmeAccount):
    if dbAcmeAccount.is_active:
        raise errors.InvalidTransition("Already activated.")
    dbAcmeAccount.is_active = True
    event_status = "AcmeAccount__mark__active"
    return event_status


def update_AcmeAccount__unset_active(ctx, dbAcmeAccount):
    if not dbAcmeAccount.is_active:
        raise errors.InvalidTransition("Already deactivated.")
    if dbAcmeAccount.is_global_default:
        raise errors.InvalidTransition(
            "You can not deactivate the global default. Set another `AcmeAccount` as the global default first."
        )
    dbAcmeAccount.is_active = False
    event_status = "AcmeAccount__mark__inactive"
    return event_status


def update_AcmeAccount__set_global_default(ctx, dbAcmeAccount):
    if dbAcmeAccount.is_global_default:
        # `formStash.fatal_form(` will raise a `FormInvalid()`
        raise errors.InvalidTransition("Already global default.")

    if not dbAcmeAccount.acme_account_provider.is_default:
        raise errors.InvalidTransition(
            "This AcmeAccount is not from the default AcmeAccountProvider."
        )

    alt_info = {}
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


def update_AcmeAccount__private_key_cycle(ctx, dbAcmeAccount, private_key_cycle):
    if dbAcmeAccount.private_key_cycle == private_key_cycle:
        raise errors.InvalidTransition("Already updated")
    try:
        private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            private_key_cycle
        )
    except KeyError:
        raise errors.InvalidTransition("invalid option")
    if (
        private_key_cycle_id
        not in model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle_id
    ):
        raise errors.InvalidTransition("invalid option")
    dbAcmeAccount.private_key_cycle_id = private_key_cycle_id
    event_status = "AcmeAccount__edit__primary_key_cycle"
    return event_status


def update_AcmeAuthorization_from_payload(
    ctx, dbAcmeAuthorization, authorization_payload
):
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


def update_AcmeDnsServer__set_active(ctx, dbAcmeDnsServer):
    if dbAcmeDnsServer.is_active:
        raise errors.InvalidTransition("Already activated.")
    dbAcmeDnsServer.is_active = True
    ctx.dbSession.flush(objects=[dbAcmeDnsServer])
    event_status = "AcmeDnsServer__mark__active"
    return event_status


def update_AcmeDnsServer__unset_active(ctx, dbAcmeDnsServer):
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


def update_AcmeDnsServer__set_global_default(ctx, dbAcmeDnsServer):
    if dbAcmeDnsServer.is_global_default:
        # `formStash.fatal_form(` will raise a `FormInvalid()`
        raise errors.InvalidTransition("Already global default.")

    if not dbAcmeDnsServer.is_active:
        # `formStash.fatal_form(` will raise a `FormInvalid()`
        raise errors.InvalidTransition("This item must be active.")

    alt_info = {}
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


def update_AcmeDnsServer__root_url(ctx, dbAcmeDnsServer, root_url):
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


def update_AcmeOrder_deactivate(ctx, dbAcmeOrder):
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


def update_AcmeOrder_set_renew_auto(ctx, dbAcmeOrder):
    if dbAcmeOrder.is_auto_renew:
        raise errors.InvalidTransition("Can not mark this `AcmeOrder` for renewal.")
    # set the renewal
    dbAcmeOrder.is_auto_renew = True
    # cleanup options
    event_status = "AcmeOrder__mark__renew_auto"
    return event_status


def update_AcmeOrder_set_renew_manual(ctx, dbAcmeOrder):
    if not dbAcmeOrder.is_auto_renew:
        raise errors.InvalidTransition("Can not unmark this `AcmeOrder` for renewal.")
    # unset the renewal
    dbAcmeOrder.is_auto_renew = False
    # cleanup options
    event_status = "AcmeOrder__mark__renew_manual"
    return event_status


def update_AcmeOrderless_deactivate(ctx, dbAcmeOrderless):
    """
    `deactivate` should mark the order as:
        `is_processing = False`
    """
    dbAcmeOrderless.is_processing = False
    dbAcmeOrderless.timestamp_updated = ctx.timestamp
    ctx.dbSession.flush(objects=[dbAcmeOrderless])
    return True


def update_CoverageAssuranceEvent__set_resolution(
    ctx, dbCoverageAssuranceEvent, resolution
):
    resolution_id = model_utils.CoverageAssuranceResolution.from_string(resolution)
    if resolution == "unresolved":
        pass
    elif resolution == "abandoned":
        pass
    elif resolution == "PrivateKey_replaced":
        if dbCoverageAssuranceEvent.server_certificate_id:
            raise errors.InvalidTransition("incompatible `resolution`")
    elif resolution == "ServerCertificate_replaced":
        if not dbCoverageAssuranceEvent.server_certificate_id:
            raise errors.InvalidTransition("incompatible `resolution`")
    if resolution_id == dbCoverageAssuranceEvent.coverage_assurance_resolution_id:
        raise errors.InvalidTransition("No Change")
    dbCoverageAssuranceEvent.coverage_assurance_resolution_id = resolution_id
    return True


def update_Domain_disable(
    ctx,
    dbDomain,
    dbOperationsEvent=None,
    event_status="Domain__mark__inactive",
    action="deactivated",
):
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
    ctx,
    dbDomain,
    dbOperationsEvent=None,
    event_status="Domain__mark__active",
    action="activated",
):
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
    ctx, dbDomainAutocert,
):
    dbDomainAutocert.timestamp_finished = datetime.datetime.utcnow()
    dbDomainAutocert.is_successful = False
    ctx.dbSession.flush(objects=[dbDomainAutocert])


def update_DomainAutocert_with_AcmeOrder(
    ctx, dbDomainAutocert, dbAcmeOrder=None,
):
    if not dbAcmeOrder:
        raise errors.InvalidTransition("missing `AcmeOrder`")
    dbDomainAutocert.acme_order_id = dbAcmeOrder.id
    dbDomainAutocert.timestamp_finished = datetime.datetime.utcnow()
    if dbAcmeOrder.acme_status_order == "valid":
        dbDomainAutocert.is_successful = True
    else:
        dbDomainAutocert.is_successful = False
    ctx.dbSession.flush(objects=[dbDomainAutocert])


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_PrivateKey__set_active(ctx, dbPrivateKey):
    if dbPrivateKey.is_active:
        raise errors.InvalidTransition("Already activated.")
    if dbPrivateKey.is_compromised:
        raise errors.InvalidTransition("Can not activate a compromised key")
    dbPrivateKey.is_active = True
    event_status = "PrivateKey__mark__active"
    return event_status


def update_PrivateKey__unset_active(ctx, dbPrivateKey):
    if not dbPrivateKey.is_active:
        raise errors.InvalidTransition("Already deactivated")
    dbPrivateKey.is_active = False
    event_status = "PrivateKey__mark__inactive"
    return event_status


def update_PrivateKey__set_compromised(ctx, dbPrivateKey, dbOperationsEvent):
    if dbPrivateKey.is_compromised:
        raise errors.InvalidTransition("Already compromised")
    dbPrivateKey.is_active = False
    dbPrivateKey.is_compromised = True
    ctx.dbSession.flush(objects=[dbPrivateKey])

    lib.events.PrivateKey_compromised(
        ctx, dbPrivateKey, dbOperationsEvent=dbOperationsEvent,
    )

    event_status = "PrivateKey__mark__compromised"
    return event_status


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_QueueCertificate__cancel(
    ctx, dbQueueCertificate,
):
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
    ctx,
    dbQueueDomain,
    dbOperationsEvent=None,
    event_status="QueueDomain__mark__cancelled",
    action="de-queued",
):
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


def update_ServerCertificate__mark_compromised(
    ctx, dbServerCertificate, via_PrivateKey_compromised=None
):
    # the PrivateKey has been compromised
    dbServerCertificate.is_compromised_private_key = True
    dbServerCertificate.is_revoked = True  # NOTE: this has nothing to do with the acme-server, it is just a local marking
    if dbServerCertificate.is_active:
        dbServerCertificate.is_active = False
    event_status = "ServerCertificate__mark__compromised"
    return event_status


def update_ServerCertificate__set_active(ctx, dbServerCertificate):

    if dbServerCertificate.is_active:
        raise errors.InvalidTransition("Already active.")

    if dbServerCertificate.is_revoked:
        raise errors.InvalidTransition(
            "Certificate is revoked; `active` status can not be changed."
        )

    if dbServerCertificate.is_compromised_private_key:
        raise errors.InvalidTransition(
            "Certificate has a compromised PrivateKey; `active` status can not be changed."
        )

    if dbServerCertificate.is_deactivated:
        raise errors.InvalidTransition(
            "Certificate was deactivated; `active` status can not be changed."
        )

    # now make it active!
    dbServerCertificate.is_active = True

    # cleanup options
    event_status = "ServerCertificate__mark__active"
    return event_status


def update_ServerCertificate__unset_active(ctx, dbServerCertificate):

    if not dbServerCertificate.is_active:
        raise errors.InvalidTransition("Already inactive.")

    # inactivate it
    dbServerCertificate.is_active = False

    event_status = "ServerCertificate__mark__inactive"
    return event_status


"""
as of .40, ServerCertificates do not auto-renew. Instead, AcmeOrders do.

def update_ServerCertificate__set_renew_auto(ctx, dbServerCertificate):
    if dbServerCertificate.renewals_managed_by == "AcmeOrder":
        raise errors.InvalidTransition("auto-renew is managed by the AcmeOrder")
    if dbServerCertificate.is_auto_renew:
        raise errors.InvalidTransition("Already active.")
    # activate!
    dbServerCertificate.is_auto_renew = True
    event_status = "ServerCertificate__mark__renew_auto"
    return event_status


def update_ServerCertificate__set_renew_manual(ctx, dbServerCertificate):
    if dbServerCertificate.renewals_managed_by == "AcmeOrder":
        raise errors.InvalidTransition("auto-renew is managed by the AcmeOrder")
    if not dbServerCertificate.is_auto_renew:
        raise errors.InvalidTransition("Already inactive.")
    # deactivate!
    dbServerCertificate.is_auto_renew = False
    event_status = "ServerCertificate__mark__renew_manual"
    return event_status
"""


def update_ServerCertificate__set_revoked(ctx, dbServerCertificate):

    if dbServerCertificate.is_revoked:
        raise errors.InvalidTransition("Certificate is already revoked")

    # mark revoked
    dbServerCertificate.is_revoked = True

    # inactivate it
    dbServerCertificate.is_active = False

    # deactivate it, permanently
    dbServerCertificate.is_deactivated = True

    # cleanup options
    event_status = "ServerCertificate__mark__revoked"
    return event_status


def update_ServerCertificate__unset_revoked(ctx, dbServerCertificate):
    """
    this is currently not supported
    """

    if not dbServerCertificate.is_revoked:
        raise errors.InvalidTransition("Certificate is not revoked")

    # unset the revoke
    dbServerCertificate.is_revoked = False

    # lead is_active and is_deactivated as-is
    # cleanup options
    event_status = "ServerCertificate__mark__unrevoked"
    return event_status
