# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime

# pypi
from dateutil import parser as dateutil_parser

# localapp
from ...model import utils as model_utils
from ...lib import errors
from .get import get__AcmeAccountKey__GlobalDefault
from .get import get__AcmeAccountProvider__default
from .get import get__Domain__by_name
from .get import get__PrivateKey__GlobalDefault


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_AcmeAccountProvider__set_default(ctx, dbAcmeAccountProvider_new):
    _objs = [
        dbAcmeAccountProvider_new,
    ]
    dbAcmeAccountProvider_default = get__AcmeAccountProvider__default(ctx)
    if dbAcmeAccountProvider_default:
        _objs.append(dbAcmeAccountProvider_default)
        if dbAcmeAccountProvider_default.id != dbAcmeAccountProvider_new.id:
            dbAcmeAccountProvider_default.is_default = False
    dbAcmeAccountProvider_new.is_default = True
    ctx.dbSession.flush(_objs)


def update_AcmeAccountKey__set_active(ctx, dbAcmeAccountKey):
    if dbAcmeAccountKey.is_active:
        raise errors.InvalidTransition("Already activated")
    dbAcmeAccountKey.is_active = True
    event_status = "AcmeAccountKey__mark__active"
    return event_status


def update_AcmeAccountKey__unset_active(ctx, dbAcmeAccountKey):
    if not dbAcmeAccountKey.is_active:
        raise errors.InvalidTransition("Already deactivated.")
    if dbAcmeAccountKey.is_global_default:
        raise errors.InvalidTransition(
            "You can not deactivate the global default. Make another key as the global default first."
        )
    dbAcmeAccountKey.is_active = False
    event_status = "AcmeAccountKey__mark__inactive"
    return event_status


def update_AcmeAccountKey__set_global_default(ctx, dbAcmeAccountKey):
    if dbAcmeAccountKey.is_global_default:
        # `formStash.fatal_form(` will raise a `FormInvalid()`
        raise errors.InvalidTransition("Already global default.")

    if not dbAcmeAccountKey.acme_account_provider.is_default:
        raise errors.InvalidTransition(
            "This AccountKey is not from the default AcmeAccountProvider."
        )

    alt_info = {}
    formerDefaultKey = get__AcmeAccountKey__GlobalDefault(ctx)
    if formerDefaultKey:
        formerDefaultKey.is_global_default = False
        alt_info["event_payload_dict"] = {
            "account_key_id.former_default": formerDefaultKey.id,
        }
        alt_info["event_alt"] = ("AcmeAccountKey__mark__notdefault", formerDefaultKey)
    dbAcmeAccountKey.is_global_default = True
    event_status = "AcmeAccountKey__mark__default"
    return event_status, alt_info


def update_AcmeAccountKey__private_key_cycle(ctx, dbAcmeAccountKey, private_key_cycle):
    if dbAcmeAccountKey.private_key_cycle == private_key_cycle:
        raise errors.InvalidTransition("Already updated")
    try:
        private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            private_key_cycle
        )
    except KeyError:
        raise errors.InvalidTransition("invalid option")
    if (
        private_key_cycle_id
        not in model_utils.PrivateKeyCycle._options_AcmeAccountKey_private_key_cycle_id
    ):
        raise errors.InvalidTransition("invalid option")
    dbAcmeAccountKey.private_key_cycle_id = private_key_cycle_id
    event_status = "AcmeAccountKey__edit__primary_key_cycle"
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
                "this domain name has not been seen before. this should not be possible."
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


def update_PrivateKey__set_active(ctx, dbPrivateKey):
    if dbPrivateKey.is_active:
        raise errors.InvalidTransition("Already activated")
    if dbPrivateKey.is_compromised:
        raise errors.InvalidTransition("Can not activate a compromised key")
    dbPrivateKey.is_active = True
    event_status = "PrivateKey__mark__active"
    return event_status


def update_PrivateKey__unset_active(ctx, dbPrivateKey):
    if not dbPrivateKey.is_active:
        raise errors.InvalidTransition("Already deactivated")
    if dbPrivateKey.is_global_default:
        raise errors.InvalidTransition(
            "You can not deactivate the Global Default. Make another key as the Global Default first."
        )
    dbPrivateKey.is_active = False
    event_status = "PrivateKey__mark__inactive"
    return event_status


def update_PrivateKey__set_compromised(ctx, dbPrivateKey):
    if dbPrivateKey.is_compromised:
        raise errors.InvalidTransition("Already compromised")
    dbPrivateKey.is_active = False
    dbPrivateKey.is_compromised = True
    if dbPrivateKey.is_global_default:
        dbPrivateKey.is_global_default = False
    event_status = "PrivateKey__mark__compromised"
    return event_status


def update_PrivateKey__set_global_default(ctx, dbPrivateKey):
    if dbPrivateKey.is_global_default:
        raise errors.InvalidTransition("Already default")

    if not dbPrivateKey.is_active:
        raise errors.InvalidTransition("Key not active")

    if dbPrivateKey.acme_account_key_id__owner:
        raise errors.InvalidTransition("Key belongs to an AcmeAccount")

    alt_info = {}
    formerDefaultKey = get__PrivateKey__GlobalDefault(ctx)
    if formerDefaultKey:
        formerDefaultKey.is_global_default = False
        alt_info["event_payload_dict"] = {
            "private_key_id.former_default": formerDefaultKey.id,
        }
        alt_info["event_alt"] = ("PrivateKey__mark__notdefault", formerDefaultKey)
    dbPrivateKey.is_global_default = True
    event_status = "PrivateKey__mark__default"
    return event_status, alt_info


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

    if not dbServerCertificate.is_deactivated:
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

    # deactivate it
    dbServerCertificate.is_active = False

    event_status = "ServerCertificate__mark__inactive"
    return event_status


def update_ServerCertificate__set_revoked(ctx, dbServerCertificate):

    if dbServerCertificate.is_revoked:
        raise errors.InvalidTransition("Certificate is already revoked")

    # mark revoked
    dbServerCertificate.is_revoked = True

    # deactivate it
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
