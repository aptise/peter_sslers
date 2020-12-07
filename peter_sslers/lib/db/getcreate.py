from __future__ import print_function

# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime
import json
import pdb

# pypi
from dateutil import parser as dateutil_parser
import sqlalchemy

# localapp
from ... import lib
from .. import cert_utils
from .. import utils
from ...lib import errors
from ...model import utils as model_utils
from ...model import objects as model_objects
from .create import create__AcmeChallenge
from .create import create__CertificateRequest
from .create import create__PrivateKey
from .create import create__ServerCertificate
from .get import get__AcmeAccountProvider__by_server
from .get import get__AcmeAuthorization__by_authorization_url
from .get import get__AcmeChallenge__by_challenge_url
from .get import get__AcmeDnsServer__by_root_url
from .get import get__CACertificate__by_pem_text
from .get import get__CertificateRequest__by_pem_text
from .get import get__Domain__by_name
from .get import get__DomainBlocklisted__by_name
from .get import get__PrivateKey_CurrentDay_AcmeAccount
from .get import get__PrivateKey_CurrentDay_Global
from .get import get__PrivateKey_CurrentWeek_AcmeAccount
from .get import get__PrivateKey_CurrentWeek_Global
from .logger import log__OperationsEvent
from .logger import _log_object_event
from .helpers import _certificate_parse_to_record
from .update import update_AcmeAuthorization_from_payload
from .update import update_AcmeDnsServer__set_global_default
from .validate import validate_domain_names


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__AcmeAccount(
    ctx,
    key_pem=None,
    le_meta_jsons=None,
    le_pkey_jsons=None,
    le_reg_jsons=None,
    acme_account_provider_id=None,
    acme_account_key_source_id=None,
    contact=None,
    terms_of_service=None,
    account_url=None,
    event_type="AcmeAccount__insert",
    private_key_cycle_id=None,
):
    """
    Gets or Creates AcmeAccount+AcmeAccountKey for LetsEncrypts' ACME server

    returns:
        tuple(`model.utils.AcmeAccount`, `is_created[Boolean]`)

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param key_pem: (optional) an account key in PEM format.
        if not provided, all of the following must be supplied:
        * le_meta_jsons
        * le_pkey_jsons
        * le_reg_jsons
    :param le_meta_jsons: (optional) data from certbot account key format
        if not provided, `key_pem` must be supplied
    :param le_pkey_jsons: (optional) data from certbot account key format
        if not provided, `key_pem` must be supplied
    :param le_reg_jsons: (optional) data from certbot account key format
        if not provided, `key_pem` must be supplied
    :param acme_account_provider_id: (optional) id corresponding to a :class:`model.objects.AcmeAccountProvider` server. required if `key_pem``; do not submit if `le_*` kwargs are provided.
    :param acme_account_key_source_id: (required) id corresponding to a :class:`model.utils.AcmeAccountKeySource`
    :param contact: (optional) contact info from acme server
    :param terms_of_service: (optional)
    :param account_url: (optional)
    :param private_key_cycle_id: (required) id corresponding to a :class:`model.utils.PrivateKeyCycle`
    """
    if (key_pem) and any((le_meta_jsons, le_pkey_jsons, le_reg_jsons)):
        raise ValueError(
            "Must supply `key_pem` OR all of `le_meta_jsons, le_pkey_jsons, le_reg_jsons`."
        )
    if not (key_pem) and not all((le_meta_jsons, le_pkey_jsons, le_reg_jsons)):
        raise ValueError(
            "Must supply `key_pem` OR all of `le_meta_jsons, le_pkey_jsons, le_reg_jsons`."
        )
    # how are we submitting this data?
    _strategy = None

    _event_type_key = None
    if event_type == "AcmeAccount__create":
        _event_type_key = "AcmeAccountKey__create"
    elif event_type == "AcmeAccount__insert":
        _event_type_key = "AcmeAccountKey__insert"
    else:
        raise ValueError("invalid `event_type`")

    if private_key_cycle_id is None:
        private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            model_utils.PrivateKeyCycle._DEFAULT_AcmeAccount
        )
    if private_key_cycle_id not in model_utils.PrivateKeyCycle._mapping:
        raise ValueError("invalid `private_key_cycle_id`")

    # scoping
    _letsencrypt_data = None

    # quickly audit args/derive info
    if key_pem:
        _strategy = "key_pem"
        if not contact:
            raise ValueError("must supply `contact` when submitting `key_pem`")
        if not acme_account_provider_id:
            raise ValueError(
                "no `acme_account_provider_id`; required if PEM key is submitted."
            )

        dbAcmeAccountProvider = ctx.dbSession.query(
            model_objects.AcmeAccountProvider
        ).get(acme_account_provider_id)
        if not dbAcmeAccountProvider:
            raise ValueError("invalid `acme_account_provider_id`.")

        # cleanup these
        key_pem = cert_utils.cleanup_pem_text(key_pem)
        key_pem_md5 = utils.md5_text(key_pem)

    elif not key_pem:
        _strategy = "LetsEncrypt payload"
        if contact:
            raise ValueError("do not submit `contact` with LetsEncrypt payload")
        if acme_account_provider_id:
            raise ValueError(
                "do not submit `acme_account_provider_id` with LetsEncrypt payload"
            )
        if terms_of_service:
            raise ValueError(
                "do not submit `terms_of_service` with LetsEncrypt payload"
            )
        if account_url:
            raise ValueError("do not submit `account_url` with LetsEncrypt payload")

        """
        There is some useful data in here...
            meta.json = creation_dt DATETIME; save as created
            meta.json = creation_host STRING; save for info
            regr.json = contact: email, save for info
            regr.json = agreement: url, save for info
            regr.json = key, save for info
            regr.json = uri, save for info
            regr.json = tos, save for info
        """
        le_meta_json = json.loads(le_meta_jsons)
        le_reg_json = json.loads(le_reg_jsons)
        _letsencrypt_data = {"meta.json": le_meta_json, "regr.json": le_reg_json}
        _letsencrypt_data = json.dumps(_letsencrypt_data, sort_keys=True)
        try:
            contact = le_reg_json["body"]["contact"][0]
            if contact.startswith("mailto:"):
                contact = contact[7:]
        except Exception as exc:
            log.critical("Could not parse `contact` from LetsEncrypt payload")
            contact = "invalid.contact.import@example.com"

        terms_of_service = le_reg_json.get("terms_of_service")
        account_url = le_reg_json.get("uri")
        _account_server = lib.utils.url_to_server(account_url)
        if not _account_server:
            raise ValueError(
                "could not detect an AcmeAccountProvider server from LetsEncrypt payload"
            )

        # derive the api server
        dbAcmeAccountProvider = get__AcmeAccountProvider__by_server(
            ctx, _account_server
        )
        if not dbAcmeAccountProvider:
            raise ValueError(
                "invalid AcmeAccountProvider detected from LetsEncrypt payload"
            )
        acme_account_provider_id = dbAcmeAccountProvider.id

        key_pem = cert_utils.convert_lejson_to_pem(le_pkey_jsons)
        key_pem = cert_utils.cleanup_pem_text(key_pem)
        key_pem_md5 = utils.md5_text(key_pem)

    # now proceed with a single path of logic

    # check for an AcmeAccount and AcmeAccountKey separately
    # SCENARIOS:
    # 1. No AcmeAccount or AcmeAccountKey - CREATE BOTH
    # 2. Existing AcmeAccount, new AcmeAccountKey - CREATE NONE. ERROR.
    # 3. Existing AcmeAccountKey, new AcmeAccount - CREATE NONE. ERROR.

    dbAcmeAccount = (
        ctx.dbSession.query(model_objects.AcmeAccount)
        .filter(
            sqlalchemy.func.lower(model_objects.AcmeAccount.contact) == contact.lower(),
            model_objects.AcmeAccount.acme_account_provider_id
            == acme_account_provider_id,
        )
        .first()
    )
    dbAcmeAccountKey = (
        ctx.dbSession.query(model_objects.AcmeAccountKey)
        .filter(
            model_objects.AcmeAccountKey.key_pem_md5 == key_pem_md5,
            model_objects.AcmeAccountKey.key_pem == key_pem,
        )
        .first()
    )
    if dbAcmeAccount:
        if dbAcmeAccountKey:
            return (dbAcmeAccount, False)
        else:
            raise errors.ConflictingObject(
                (
                    dbAcmeAccount,
                    "The submitted AcmeAccountProvider and contact ino is already associated with another AcmeAccountKey.",
                )
            )
    elif dbAcmeAccountKey:
        raise errors.ConflictingObject(
            (
                dbAcmeAccountKey,
                "The submited AcmeAccountKey is already associated with another AcmeAccount.",
            )
        )

    try:
        _tmpfile = cert_utils.new_pem_tempfile(key_pem)

        # validate
        cert_utils.validate_key(key_pem=key_pem, key_pem_filepath=_tmpfile.name)

        # grab the technology
        key_technology = cert_utils.modulus_md5_key(
            key_pem=key_pem,
            key_pem_filepath=_tmpfile.name,
        )

        # grab the modulus
        key_pem_modulus_md5 = cert_utils.modulus_md5_key(
            key_pem=key_pem,
            key_pem_filepath=_tmpfile.name,
        )

    finally:
        _tmpfile.close()

    dbOperationsEvent_AcmeAccount = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(event_type),
    )
    dbOperationsEvent_AcmeAccountKey = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string(_event_type_key),
        dbOperationsEvent_child_of=dbOperationsEvent_AcmeAccount,
    )

    # first, create the AcmeAccount
    dbAcmeAccount = model_objects.AcmeAccount()
    dbAcmeAccount.timestamp_created = ctx.timestamp
    dbAcmeAccount.contact = contact
    dbAcmeAccount.terms_of_service = terms_of_service
    dbAcmeAccount.account_url = account_url
    dbAcmeAccount.acme_account_provider_id = acme_account_provider_id
    dbAcmeAccount.private_key_cycle_id = private_key_cycle_id
    dbAcmeAccount.operations_event_id__created = dbOperationsEvent_AcmeAccount.id
    ctx.dbSession.add(dbAcmeAccount)
    ctx.dbSession.flush(objects=[dbAcmeAccount])

    # next, create the AcmeAccountKey
    dbAcmeAccountKey = model_objects.AcmeAccountKey()
    dbAcmeAccountKey.acme_account_id = dbAcmeAccount.id
    dbAcmeAccountKey.timestamp_created = ctx.timestamp
    dbAcmeAccountKey.key_pem = key_pem
    dbAcmeAccountKey.key_pem_md5 = key_pem_md5
    dbAcmeAccountKey.key_pem_modulus_md5 = key_pem_modulus_md5
    dbAcmeAccountKey.acme_account_key_source_id = acme_account_key_source_id
    dbAcmeAccountKey.operations_event_id__created = dbOperationsEvent_AcmeAccountKey.id
    ctx.dbSession.add(dbAcmeAccountKey)
    ctx.dbSession.flush(objects=[dbAcmeAccountKey])

    # recordkeeping - AcmeAccount
    _epd__AcmeAccount = utils.new_event_payload_dict()
    _epd__AcmeAccount["acme_account.id"] = dbAcmeAccount.id
    dbOperationsEvent_AcmeAccount.set_event_payload(_epd__AcmeAccount)
    ctx.dbSession.flush(objects=[dbOperationsEvent_AcmeAccount])
    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent_AcmeAccount,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(event_type),
        dbAcmeAccount=dbAcmeAccount,
    )

    # recordkeeping - AcmeAccountKey
    _epd__AcmeAccountKey = utils.new_event_payload_dict()
    _epd__AcmeAccountKey["acme_account_key.id"] = dbAcmeAccountKey.id
    dbOperationsEvent_AcmeAccountKey.set_event_payload(_epd__AcmeAccountKey)
    ctx.dbSession.flush(objects=[dbOperationsEvent_AcmeAccountKey])
    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent_AcmeAccountKey,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            _event_type_key
        ),
        dbAcmeAccountKey=dbAcmeAccountKey,
    )

    return (dbAcmeAccount, True)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__AcmeAuthorizationUrl(
    ctx, authorization_url=None, dbAcmeOrder=None, is_via_new_order=None
):
    """
    used to create auth objects
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authorization_url: (required) the url of an RFC-8555 authorization
    :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the discovered item
    :param is_via_new_order: Boolean was this discovered during a new AcmeOrder? It should always be yes.
    """
    log.info("getcreate__AcmeAuthorizationUrl(")
    if not dbAcmeOrder:
        raise ValueError("`dbAcmeOrder` is required")
    is_created__AcmeAuthorization = False
    is_created__AcmeAuthorization2Order = None
    _needs_association = None
    dbAcmeAuthorization = get__AcmeAuthorization__by_authorization_url(
        ctx, authorization_url
    )
    if not dbAcmeAuthorization:
        dbAcmeAuthorization = model_objects.AcmeAuthorization()
        dbAcmeAuthorization.authorization_url = authorization_url
        dbAcmeAuthorization.timestamp_created = ctx.timestamp
        dbAcmeAuthorization.acme_status_authorization_id = (
            model_utils.Acme_Status_Authorization.ID_DEFAULT
        )
        dbAcmeAuthorization.acme_order_id__created = dbAcmeOrder.id
        ctx.dbSession.add(dbAcmeAuthorization)
        ctx.dbSession.flush(objects=[dbAcmeAuthorization])
        is_created__AcmeAuthorization = True
        _needs_association = True

    else:
        # poop, this
        # raise ValueError("this should be unique!")

        _existingAssociation = (
            ctx.dbSession.query(model_objects.AcmeOrder2AcmeAuthorization)
            .filter(
                model_objects.AcmeOrder2AcmeAuthorization.acme_order_id
                == dbAcmeOrder.id,
                model_objects.AcmeOrder2AcmeAuthorization.acme_authorization_id
                == dbAcmeAuthorization.id,
            )
            .first()
        )
        if not _existingAssociation:
            _needs_association = True

    if _needs_association:
        dbOrder2Auth = model_objects.AcmeOrder2AcmeAuthorization()
        dbOrder2Auth.acme_order_id = dbAcmeOrder.id
        dbOrder2Auth.acme_authorization_id = dbAcmeAuthorization.id
        dbOrder2Auth.is_present_on_new_order = is_via_new_order
        ctx.dbSession.add(dbOrder2Auth)
        ctx.dbSession.flush(
            objects=[
                dbOrder2Auth,
            ]
        )
        is_created__AcmeAuthorization2Order = True

    log.info(") getcreate__AcmeAuthorizationUrl")
    return (
        dbAcmeAuthorization,
        is_created__AcmeAuthorization,
        is_created__AcmeAuthorization2Order,
    )


def getcreate__AcmeAuthorization(
    ctx,
    authorization_url=None,
    authorization_payload=None,
    authenticatedUser=None,
    dbAcmeOrder=None,
    transaction_commit=None,
    is_via_new_order=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authorization_url: (required) the url of an RFC-8555 authorization
    :param authorization_payload: (required) an RFC-8555 authorization payload
    :param authenticatedUser: (optional) an object which contains a `accountkey_thumbprint` attribute
    :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the discovered item
    :param transaction_commit: (required) Boolean value. required to indicate this persists to the database.
    :param is_via_new_order: Boolean was this discovered during a new AcmeOrder? It should always be yes.

    https://tools.ietf.org/html/rfc8555#section-7.1.4
    Authorization Payload Contents:
        identifier (required, object):  The identifier that the account is authorized to represent.
              type (required, string):  The type of identifier (see below and Section 9.7.7).
              value (required, string):  The identifier itself.
       expires (optional, string):  The timestamp after which the server will consider this authorization invalid, encoded in the format specified in [RFC3339].  This field is REQUIRED for objects with "valid" in the "status" field.
        status (required, string):
        challenges (required, array of objects):
        wildcard (optional, boolean)

    potentially raises:
        errors.AcmeMissingChallenges
    """
    log.info("getcreate__AcmeAuthorization(")
    if not dbAcmeOrder:
        raise ValueError("do not invoke this without a `dbAcmeOrder`")

    is_created__AcmeAuthorization = None
    dbAcmeAuthorization = get__AcmeAuthorization__by_authorization_url(
        ctx, authorization_url
    )
    if not dbAcmeAuthorization:
        #
        dbAcmeAuthorization = model_objects.AcmeAuthorization()
        dbAcmeAuthorization.authorization_url = authorization_url
        dbAcmeAuthorization.timestamp_created = ctx.timestamp
        dbAcmeAuthorization.acme_status_authorization_id = (
            model_utils.Acme_Status_Authorization.ID_DEFAULT
        )
        dbAcmeAuthorization.acme_order_id__created = dbAcmeOrder.id
        ctx.dbSession.add(dbAcmeAuthorization)
        ctx.dbSession.flush(
            objects=[
                dbAcmeAuthorization,
            ]
        )
        is_created__AcmeAuthorization = True

        dbOrder2Auth = model_objects.AcmeOrder2AcmeAuthorization()
        dbOrder2Auth.acme_order_id = dbAcmeOrder.id
        dbOrder2Auth.acme_authorization_id = dbAcmeAuthorization.id
        dbOrder2Auth.is_present_on_new_order = is_via_new_order
        ctx.dbSession.add(dbOrder2Auth)
        ctx.dbSession.flush(
            objects=[
                dbOrder2Auth,
            ]
        )
        is_created__AcmeAuthorization2Order = True

    _result = process__AcmeAuthorization_payload(
        ctx,
        authorization_payload=authorization_payload,
        authenticatedUser=authenticatedUser,
        dbAcmeAuthorization=dbAcmeAuthorization,
        dbAcmeOrder=dbAcmeOrder,
        transaction_commit=transaction_commit,
    )

    # persist this to the db
    if transaction_commit:
        ctx.pyramid_transaction_commit()

    return (dbAcmeAuthorization, is_created__AcmeAuthorization)


def process__AcmeAuthorization_payload(
    ctx,
    authorization_payload=None,
    authenticatedUser=None,
    dbAcmeAuthorization=None,
    dbAcmeOrder=None,
    transaction_commit=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authorization_payload: (required) an RFC-8555 authorization payload
    :param authenticatedUser: (optional) an object which contains a `accountkey_thumbprint` attribute
    :param dbAcmeAuthorization: (required) The :class:`model.objects.AcmeAuthorization` associated with the discovered item
    :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the discovered item
    :param transaction_commit: (required) Boolean value. required to indicate this persists to the database.
    """
    log.info("process__AcmeAuthorization_payload")
    is_created__AcmeAuthorization2Order = None

    # is this associated?
    dbOrder2Auth = (
        ctx.dbSession.query(model_objects.AcmeOrder2AcmeAuthorization)
        .filter(
            model_objects.AcmeOrder2AcmeAuthorization.acme_order_id == dbAcmeOrder.id,
            model_objects.AcmeOrder2AcmeAuthorization.acme_authorization_id
            == dbAcmeAuthorization.id,
        )
        .first()
    )
    if not dbOrder2Auth:
        dbOrder2Auth = model_objects.AcmeOrder2AcmeAuthorization()
        dbOrder2Auth.acme_order_id = dbAcmeOrder.id
        dbOrder2Auth.acme_authorization_id = dbAcmeAuthorization.id
        dbOrder2Auth.is_present_on_new_order = False
        ctx.dbSession.add(dbOrder2Auth)
        ctx.dbSession.flush(
            objects=[
                dbOrder2Auth,
            ]
        )
        is_created__AcmeAuthorization2Order = True

    # no matter what, update
    # this will set the following:
    # `dbAcmeAuthorization.timestamp_expires`
    # `dbAcmeAuthorization.domain_id`
    # `dbAcmeAuthorization.acme_status_authorization_id`
    # `dbAcmeAuthorization.timestamp_updated`
    _updated = update_AcmeAuthorization_from_payload(
        ctx, dbAcmeAuthorization, authorization_payload
    )

    # parse the payload for our http01 challenge
    try:
        dbAcmeChallenges = getcreate__AcmeChallenges_via_payload(
            ctx,
            authenticatedUser=authenticatedUser,
            dbAcmeAuthorization=dbAcmeAuthorization,
            authorization_payload=authorization_payload,
        )
    except errors.AcmeMissingChallenges as exc:
        pass

    # persist this to the db
    if transaction_commit:
        ctx.pyramid_transaction_commit()

    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__AcmeChallenges_via_payload(
    ctx,
    authenticatedUser=None,
    dbAcmeAuthorization=None,
    authorization_payload=None,
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authenticatedUser: (optional) an object which contains a `accountkey_thumbprint` attribute
    :param dbAcmeAuthorization: (required) The :class:`model.objects.AcmeAuthorization` associated with the payload
    :param authorization_payload: (required) an RFC-8555 authorization payload

    returns:
        dbAcmeChallenges: a list of tuples, each tuple being  (`model.objects.AcmeChallenge`, is_created)
    potentially raises:
        errors.AcmeMissingChallenges
    """
    dbAcmeChallenges = []
    acme_challenges = lib.acme_v2.get_authorization_challenges(
        authorization_payload,
        required_challenges=[
            "http-01",
        ],
    )
    for acme_challenge in acme_challenges.values():
        if acme_challenge is None:
            continue
        challenge_url = acme_challenge["url"]
        challenge_status = acme_challenge["status"]
        acme_challenge_type_id = model_utils.AcmeChallengeType.from_string(
            acme_challenge["type"]
        )
        acme_status_challenge_id = model_utils.Acme_Status_Challenge.from_string(
            challenge_status
        )
        _dbAcmeChallenge = get__AcmeChallenge__by_challenge_url(ctx, challenge_url)
        _is_created_AcmeChallenge = False
        if not _dbAcmeChallenge:
            challenge_token = acme_challenge["token"]
            keyauthorization = (
                lib.acme_v2.create_challenge_keyauthorization(
                    challenge_token, authenticatedUser.accountkey_thumbprint
                )
                if authenticatedUser
                else None
            )
            _dbAcmeChallenge = create__AcmeChallenge(
                ctx,
                dbAcmeAuthorization=dbAcmeAuthorization,
                dbDomain=dbAcmeAuthorization.domain,
                challenge_url=challenge_url,
                token=challenge_token,
                keyauthorization=keyauthorization,
                acme_challenge_type_id=acme_challenge_type_id,
                acme_status_challenge_id=acme_status_challenge_id,
                is_via_sync=True,
            )
            _is_created_AcmeChallenge = True
        else:
            if _dbAcmeChallenge.acme_status_challenge_id != acme_status_challenge_id:
                _dbAcmeChallenge.acme_status_challenge_id = acme_status_challenge_id
                _dbAcmeChallenge.timestamp_updated = datetime.datetime.utcnow()
                ctx.dbSession.add(_dbAcmeChallenge)
                ctx.dbSession.flush(objects=[_dbAcmeChallenge])
        dbAcmeChallenges.append((_dbAcmeChallenge, _is_created_AcmeChallenge))
    return dbAcmeChallenges


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__AcmeDnsServer(ctx, root_url, is_global_default=None):
    """
    getcreate wrapping an acms-dns Server (AcmeDnsServer)

    return dbAcmeDnsServer, is_created

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param root_url:
    """
    is_created = False
    dbAcmeDnsServer = get__AcmeDnsServer__by_root_url(ctx, root_url)
    if not dbAcmeDnsServer:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(
            ctx, model_utils.OperationsEventType.from_string("AcmeDnsServer__insert")
        )
        dbAcmeDnsServer = model_objects.AcmeDnsServer()
        dbAcmeDnsServer.root_url = root_url
        dbAcmeDnsServer.timestamp_created = ctx.timestamp
        dbAcmeDnsServer.operations_event_id__created = dbOperationsEvent.id
        dbAcmeDnsServer.is_active = True
        ctx.dbSession.add(dbAcmeDnsServer)
        ctx.dbSession.flush(objects=[dbAcmeDnsServer])
        is_created = True

        event_payload_dict["domain.id"] = dbAcmeDnsServer.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "AcmeDnsServer__insert"
            ),
            dbAcmeDnsServer=dbAcmeDnsServer,
        )

    if is_global_default:
        _res = update_AcmeDnsServer__set_global_default(ctx, dbAcmeDnsServer)

    return (dbAcmeDnsServer, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__CACertificate__by_pem_text(
    ctx,
    cert_pem,
    ca_chain_name=None,
    le_authority_name=None,
    is_trusted_root=None,
    key_technology_id=None,
):
    """
    Gets or Creates CACertificates

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param cert_pem: (required)
    :param ca_chain_name:
    :param le_authority_name:
    :param is_trusted_root:
    :param key_technology_id:  :class:`lib.utils.KeyTechnology` value

    """
    is_created = False
    dbCACertificate = get__CACertificate__by_pem_text(ctx, cert_pem)
    if not dbCACertificate:
        cert_pem = cert_utils.cleanup_pem_text(cert_pem)
        cert_pem_md5 = utils.md5_text(cert_pem)
        try:
            _tmpfile = cert_utils.new_pem_tempfile(cert_pem)

            # validate
            cert_utils.validate_cert(cert_pem=cert_pem, cert_pem_filepath=_tmpfile.name)

            # grab the modulus
            _cert_pem_modulus_md5 = cert_utils.modulus_md5_cert(
                cert_pem=cert_pem,
                cert_pem_filepath=_tmpfile.name,
            )

            # bookkeeping
            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__OperationsEvent(
                ctx,
                model_utils.OperationsEventType.from_string("CaCertificate__insert"),
            )

            dbCACertificate = model_objects.CACertificate()
            dbCACertificate.name = ca_chain_name or "unknown"
            dbCACertificate.key_technology_id = key_technology_id
            dbCACertificate.le_authority_name = le_authority_name
            dbCACertificate.is_trusted_root = is_trusted_root
            dbCACertificate.id_cross_signed_by = None
            dbCACertificate.timestamp_created = ctx.timestamp
            dbCACertificate.cert_pem = cert_pem
            dbCACertificate.cert_pem_md5 = cert_pem_md5
            dbCACertificate.cert_pem_modulus_md5 = _cert_pem_modulus_md5

            _cert_data = cert_utils.parse_cert(
                cert_pem=cert_pem, cert_pem_filepath=_tmpfile.name
            )
            dbCACertificate.timestamp_not_before = _cert_data["startdate"]
            dbCACertificate.timestamp_not_after = _cert_data["enddate"]
            dbCACertificate.cert_subject = _cert_data["subject"]
            dbCACertificate.cert_issuer = _cert_data["issuer"]
            dbCACertificate.key_technology_id = model_utils.KeyTechnology.from_string(
                _cert_data["key_type"]
            )
            dbCACertificate.operations_event_id__created = dbOperationsEvent.id

            ctx.dbSession.add(dbCACertificate)
            ctx.dbSession.flush(objects=[dbCACertificate])
            is_created = True

            event_payload_dict["ca_certificate.id"] = dbCACertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    "CaCertificate__insert"
                ),
                dbCACertificate=dbCACertificate,
            )

        except Exception as exc:
            raise
        finally:
            _tmpfile.close()

    return (dbCACertificate, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__CertificateRequest__by_pem_text(
    ctx,
    csr_pem,
    certificate_request_source_id=None,
    dbPrivateKey=None,
    dbServerCertificate__issued=None,
    domain_names=None,
):
    """
    getcreate for a CSR

    This is only used for inserting test records.
    If uploading CSR is enabled, ensure it conforms to LetsEncrypt practices:
        * CN=/
        * all domains in SubjectAlternateNames
    LetsEncrypt will not process a CSR if the domain in CN is not duplicated as a SAN

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param csr_pem:
    :param certificate_request_source_id: Must match an option in :class:`model.utils.CertificateRequestSource`
    :param dbPrivateKey: (required) The :class:`model.objects.PrivateKey` that signed the certificate
    :param dbServerCertificate__issued: (required) The :class:`model.objects.ServerCertificate` this issued as
    :param domain_names: (required) A list of fully qualified domain names

    log__OperationsEvent takes place in `create__CertificateRequest`
    """
    is_created = False
    dbCertificateRequest = get__CertificateRequest__by_pem_text(ctx, csr_pem)
    if not dbCertificateRequest:
        dbCertificateRequest = create__CertificateRequest(
            ctx,
            csr_pem,
            certificate_request_source_id=certificate_request_source_id,
            dbPrivateKey=dbPrivateKey,
            dbServerCertificate__issued=dbServerCertificate__issued,
            domain_names=domain_names,
        )
        is_created = True

    return (dbCertificateRequest, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__Domain__by_domainName(ctx, domain_name, is_from_queue_domain=None):
    """
    getcreate wrapping a domain

    return dbDomain, is_created

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_name:
    :param is_from_queue_domain:
    """
    is_created = False
    dbDomain = get__Domain__by_name(ctx, domain_name, preload=False)
    if not dbDomain:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(
            ctx, model_utils.OperationsEventType.from_string("Domain__insert")
        )
        dbDomain = model_objects.Domain()
        dbDomain.domain_name = domain_name
        dbDomain.timestamp_created = ctx.timestamp
        dbDomain.is_from_queue_domain = is_from_queue_domain
        dbDomain.operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbDomain)
        ctx.dbSession.flush(objects=[dbDomain])
        is_created = True

        event_payload_dict["domain.id"] = dbDomain.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "Domain__insert"
            ),
            dbDomain=dbDomain,
        )

    return (dbDomain, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__PrivateKey__by_pem_text(
    ctx,
    key_pem,
    acme_account_id__owner=None,
    private_key_source_id=None,
    private_key_type_id=None,
    private_key_id__replaces=None,
):
    """
    getcreate wrapping private keys

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param str key_pem:
    :param int acme_account_id__owner: (optional) the id of a :class:`model.objects.AcmeAccount` which owns this :class:`model.objects.PrivateKey`
    :param int private_key_source_id: (required) A string matching a source in A :class:`lib.utils.PrivateKeySource`
    :param int private_key_type_id: (required) Valid options are in :class:`model.utils.PrivateKeyType`
    :param int private_key_id__replaces: (required) if this key replaces a compromised key, note it.
    """
    is_created = False
    key_pem = cert_utils.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    dbPrivateKey = (
        ctx.dbSession.query(model_objects.PrivateKey)
        .filter(
            model_objects.PrivateKey.key_pem_md5 == key_pem_md5,
            model_objects.PrivateKey.key_pem == key_pem,
        )
        .first()
    )
    if not dbPrivateKey:
        try:
            _tmpfile = cert_utils.new_pem_tempfile(key_pem)

            # validate
            cert_utils.validate_key(key_pem=key_pem, key_pem_filepath=_tmpfile.name)

            # grab the modulus
            key_pem_modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=key_pem,
                key_pem_filepath=_tmpfile.name,
            )
        except Exception as exc:
            raise
        finally:
            _tmpfile.close()

        event_payload_dict = utils.new_event_payload_dict()
        _event_type_id = model_utils.OperationsEventType.from_string(
            "PrivateKey__insert"
        )
        if private_key_type_id in model_utils.PrivateKeyType._options_calendar:
            _event_type_id = model_utils.OperationsEventType.from_string(
                "PrivateKey__insert_autogenerated_calendar"
            )
        dbOperationsEvent = log__OperationsEvent(ctx, _event_type_id)

        dbPrivateKey = model_objects.PrivateKey()
        dbPrivateKey.timestamp_created = ctx.timestamp
        dbPrivateKey.key_pem = key_pem
        dbPrivateKey.key_pem_md5 = key_pem_md5
        dbPrivateKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbPrivateKey.operations_event_id__created = dbOperationsEvent.id
        dbPrivateKey.acme_account_id__owner = acme_account_id__owner
        dbPrivateKey.private_key_source_id = private_key_source_id
        dbPrivateKey.private_key_type_id = private_key_type_id
        dbPrivateKey.private_key_id__replaces = private_key_id__replaces
        ctx.dbSession.add(dbPrivateKey)
        ctx.dbSession.flush(objects=[dbPrivateKey])
        is_created = True

        event_payload_dict["private_key.id"] = dbPrivateKey.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "PrivateKey__insert"
            ),
            dbPrivateKey=dbPrivateKey,
        )

    return (dbPrivateKey, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__PrivateKey_for_AcmeAccount(ctx, dbAcmeAccount=None):
    """
    getcreate wrapping a RemoteIpAddress

    returns: The :class:`model.objects.PrivateKey`
    raises: ValueError

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) The :class:`model.objects.AcmeAccount` that owns the certificate
    """
    private_key_cycle = dbAcmeAccount.private_key_cycle
    acme_account_id__owner = dbAcmeAccount.id
    if private_key_cycle == "single_certificate":
        # NOTE: AcmeAccountNeedsPrivateKey ; single_certificate
        dbPrivateKey_new = create__PrivateKey(
            ctx,
            acme_account_id__owner=acme_account_id__owner,
            private_key_source_id=model_utils.PrivateKeySource.from_string("generated"),
            private_key_type_id=model_utils.PrivateKeyType.from_string(
                "single_certificate"
            ),
        )
        return dbPrivateKey_new

    elif private_key_cycle == "account_daily":
        # NOTE: AcmeAccountNeedsPrivateKey ; account_daily
        dbPrivateKey_new = get__PrivateKey_CurrentDay_AcmeAccount(
            ctx, acme_account_id__owner
        )
        if not dbPrivateKey_new:
            dbPrivateKey_new = create__PrivateKey(
                ctx,
                acme_account_id__owner=acme_account_id__owner,
                private_key_source_id=model_utils.PrivateKeySource.from_string(
                    "generated"
                ),
                private_key_type_id=model_utils.PrivateKeyType.from_string(
                    "account_daily"
                ),
            )
        return dbPrivateKey_new

    elif private_key_cycle == "global_daily":
        # NOTE: AcmeAccountNeedsPrivateKey ; global_daily
        dbPrivateKey_new = get__PrivateKey_CurrentDay_Global(ctx)
        if not dbPrivateKey_new:
            dbPrivateKey_new = create__PrivateKey(
                ctx,
                private_key_source_id=model_utils.PrivateKeySource.from_string(
                    "generated"
                ),
                private_key_type_id=model_utils.PrivateKeyType.from_string(
                    "global_daily"
                ),
            )
        return dbPrivateKey_new

    elif private_key_cycle == "account_weekly":
        # NOTE: AcmeAccountNeedsPrivateKey ; account_weekly
        dbPrivateKey_new = get__PrivateKey_CurrentWeek_AcmeAccount(
            ctx, acme_account_id__owner
        )
        if not dbPrivateKey_new:
            dbPrivateKey_new = create__PrivateKey(
                ctx,
                acme_account_id__owner=acme_account_id__owner,
                private_key_source_id=model_utils.PrivateKeySource.from_string(
                    "generated"
                ),
                private_key_type_id=model_utils.PrivateKeyType.from_string(
                    "account_weekly"
                ),
            )
        return dbPrivateKey_new

    elif private_key_cycle == "global_weekly":
        # NOTE: AcmeAccountNeedsPrivateKey ; global_weekly
        dbPrivateKey_new = get__PrivateKey_CurrentWeek_Global(ctx)
        if not dbPrivateKey_new:
            dbPrivateKey_new = create__PrivateKey(
                ctx,
                private_key_source_id=model_utils.PrivateKeySource.from_string(
                    "generated"
                ),
                private_key_type_id=model_utils.PrivateKeyType.from_string(
                    "global_weekly"
                ),
            )
        return dbPrivateKey_new

    elif private_key_cycle == "account_key_default":
        # NOTE: AcmeAccountNeedsPrivateKey ; account_key_default | INVALID
        raise ValueError("invalid option `account_key_default`")

    else:
        # NOTE: AcmeAccountNeedsPrivateKey | INVALID
        raise ValueError("invalid option")


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__RemoteIpAddress(ctx, remote_ip_address):
    """
    getcreate wrapping a RemoteIpAddress

    returns (dbRemoteIpAddress, is_created)

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_name:
    :param is_from_queue_domain:
    """
    is_created = None

    # we're not doing anything to ensure the `remote_ip_address` is in IPV4 or IPV6 or anythiner
    # so just lowercase this
    dbRemoteIpAddress = (
        ctx.dbSession.query(model_objects.RemoteIpAddress)
        .filter(
            sqlalchemy.func.lower(model_objects.RemoteIpAddress.remote_ip_address)
            == sqlalchemy.func.lower(remote_ip_address)
        )
        .first()
    )
    if not dbRemoteIpAddress:
        dbRemoteIpAddress = model_objects.RemoteIpAddress()
        dbRemoteIpAddress.remote_ip_address = remote_ip_address
        dbRemoteIpAddress.timestamp_created = ctx.timestamp
        ctx.dbSession.add(dbRemoteIpAddress)
        ctx.dbSession.flush(objects=[dbRemoteIpAddress])
        is_created = True
    return (dbRemoteIpAddress, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__ServerCertificate(
    ctx,
    cert_pem,
    cert_domains_expected=None,
    is_active=None,
    dbAcmeOrder=None,
    dbCACertificate=None,
    dbCACertificates_alt=None,
    dbCertificateRequest=None,
    dbPrivateKey=None,
    dbUniqueFQDNSet=None,
):
    """
    getcreate wrapping issued certs

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param cert_pem: (required) The certificate in PEM encoding
    :param cert_domains_expected: (required) a list of domains in the cert we expect to see
    :param is_active: (optional) default `None`; do not activate a certificate when uploading unless specified.

    :param dbAcmeOrder: (optional) The :class:`model.objects.AcmeOrder` the certificate was generated through.
        if provivded, do not submit `dbCertificateRequest` or `dbPrivateKey`
    :param dbCACertificate: (required) The upstream :class:`model.objects.CACertificate` that signed the certificate
    :param dbCACertificates_alt: (optional) Iterable. Alternate :class:`model.objects.CACertificate`s that signed this certificate
    :param dbCertificateRequest: (optional) The :class:`model.objects.CertificateRequest` the certificate was generated through.
        if provivded, do not submit `dbAcmeOrder`
    :param dbPrivateKey: (required) The :class:`model.objects.PrivateKey` that signed the certificate
    :param dbUniqueFQDNSet: (optional) required if there is no `dbAcmeOrder` or `dbCertificateRequest` The :class:`model.objects.UniqueFQDNSet` representing domains on the certificate

    returns:

    tuple (dbServerCertificate, is_created)
    """
    if not any((dbAcmeOrder, dbCertificateRequest, dbUniqueFQDNSet)):
        raise ValueError(
            "getcreate__ServerCertificate must be provided with `dbCertificateRequest`, `dbAcmeOrder` or `dbUniqueFQDNSet`"
        )
    if dbUniqueFQDNSet:
        if any(
            (
                dbAcmeOrder,
                dbCertificateRequest,
            )
        ):
            raise ValueError(
                "getcreate__ServerCertificate must not be provided with `dbCertificateRequest` or `dbAcmeOrder` when `dbUniqueFQDNSet` is provided."
            )

    if not any((dbAcmeOrder, dbCertificateRequest, dbUniqueFQDNSet)):
        if not dbUniqueFQDNSet:
            raise ValueError(
                "must submit `dbUniqueFQDNSet` if there is no `dbAcmeOrder` or `dbUniqueFQDNSet`"
            )

    if not all(
        (
            cert_pem,
            dbCACertificate,
            dbPrivateKey,
        )
    ):
        raise ValueError(
            "getcreate__ServerCertificate must be provided with all of (cert_pem, dbCACertificate, dbPrivateKey)"
        )

    is_created = None
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)

    # make sure the Certificate Elements match
    _cert_pem_modulus_md5 = None
    _csr_pem_modulus_md5 = None
    _pkey_pem_modulus_md5 = None
    try:
        _tmpfile = cert_utils.new_pem_tempfile(cert_pem)
        # grab the modulus
        _cert_pem_modulus_md5 = cert_utils.modulus_md5_cert(
            cert_pem=cert_pem, cert_pem_filepath=_tmpfile.name
        )
    finally:
        _tmpfile.close()
    try:
        _tmpfile = cert_utils.new_pem_tempfile(dbPrivateKey.key_pem)
        # grab the modulus
        _pkey_pem_modulus_md5 = cert_utils.modulus_md5_key(
            key_pem=dbPrivateKey.key_pem, key_pem_filepath=_tmpfile.name
        )
    finally:
        _tmpfile.close()

    if not all((_cert_pem_modulus_md5, _pkey_pem_modulus_md5)):
        raise ValueError("Could not compute the Certificate or Key's elements")
    if _cert_pem_modulus_md5 != _pkey_pem_modulus_md5:
        raise ValueError("The PrivateKey did not sign the ServerCertificate")

    if dbCertificateRequest:
        if _cert_pem_modulus_md5 != dbCertificateRequest.csr_pem_modulus_md5:
            raise ValueError("The PrivateKey did not sign the CertificateRequest")

    dbServerCertificate = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(
            model_objects.ServerCertificate.cert_pem_md5 == cert_pem_md5,
            model_objects.ServerCertificate.cert_pem == cert_pem,
        )
        .first()
    )
    if dbServerCertificate:
        is_created = False
        if dbUniqueFQDNSet:
            if dbServerCertificate.unique_fqdn_set_id != dbUniqueFQDNSet.id:
                raise ValueError("Integrity Error. UniqueFQDNSet differs.")
        if dbPrivateKey and (dbServerCertificate.private_key_id != dbPrivateKey.id):
            if dbServerCertificate.private_key_id:
                raise ValueError("Integrity Error. Competing PrivateKey (!?)")
            elif dbServerCertificate.private_key_id is None:
                dbServerCertificate.private_key_id = dbPrivateKey.id
                dbPrivateKey.count_server_certificates += 1
                if not dbPrivateKey.timestamp_last_certificate_issue or (
                    dbPrivateKey.timestamp_last_certificate_issue < ctx.timestamp
                ):
                    dbPrivateKey.timestamp_last_certificate_issue = ctx.timestamp
                ctx.dbSession.flush(objects=[dbServerCertificate, dbPrivateKey])

        # ensure we have all the Alternate Chains connected to this ServerCerticiate
        if dbCACertificates_alt:
            _alts_existing = dbServerCertificate.certificate_upchain_alternate_ids
            _alts_needed = []
            # check the primary
            if dbCACertificate.id != dbServerCertificate.ca_certificate_id__upchain:
                if dbCACertificate.id not in _alts_existing:
                    _alts_needed.append(dbCACertificate.id)
            # check the alts
            for _dbCACertificate_alt in dbCACertificates_alt:
                if (
                    _dbCACertificate_alt.id
                    != dbServerCertificate.ca_certificate_id__upchain
                ):
                    if _dbCACertificate_alt.id not in _alts_existing:
                        _alts_needed.append(_dbCACertificate_alt.id)
            for _alt_needed in _alts_needed:
                dbServerCertificateAlternateChain = (
                    model_objects.ServerCertificateAlternateChain()
                )
                dbServerCertificateAlternateChain.server_certificate_id = (
                    dbServerCertificate.id
                )
                dbServerCertificateAlternateChain.ca_certificate_id = _alt_needed
                ctx.dbSession.add(dbServerCertificateAlternateChain)
                ctx.dbSession.flush(objects=[dbServerCertificateAlternateChain])

    elif not dbServerCertificate:
        dbServerCertificate = create__ServerCertificate(
            ctx,
            cert_pem=cert_pem,
            cert_domains_expected=cert_domains_expected,
            is_active=is_active,
            dbAcmeOrder=dbAcmeOrder,
            dbCACertificate=dbCACertificate,
            dbCACertificates_alt=dbCACertificates_alt,
            dbCertificateRequest=dbCertificateRequest,
            dbPrivateKey=dbPrivateKey,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
        )
        is_created = True

    return (dbServerCertificate, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__UniqueFQDNSet__by_domains(
    ctx, domain_names, allow_blocklisted_domains=False
):
    """
    getcreate wrapping unique fqdn

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_names: a list of domains names (strings)
    :param allow_blocklisted_domains: boolean, default `False`. If `True`, disables check against domains blocklist

    :returns: A tuple consisting of (:class:`model.objects.UniqueFQDNSet`, :bool:`is_created`)
    :raises: `errors.AcmeDomainsBlocklisted`
    """
    # we should have cleaned this up before submitting, but just be safe!
    domain_names = [i.lower() for i in [d.strip() for d in domain_names] if i]
    domain_names = list(set(domain_names))
    if not domain_names:
        raise ValueError("no domain names!")

    if not allow_blocklisted_domains:
        # ensure they are not blocklisted:
        # this may raise errors.AcmeDomainsBlocklisted
        validate_domain_names(ctx, domain_names)

    # ensure the domains are registered into our system
    domain_objects = {
        _domain_name: getcreate__Domain__by_domainName(ctx, _domain_name)[
            0
        ]  # (dbDomain, _is_created)
        for _domain_name in domain_names
    }
    # we'll use this tuple in a bit...
    # getcreate__Domain__by_domainName returns a tuple of (domainObject, is_created)
    (
        dbUniqueFQDNSet,
        is_created_fqdn,
    ) = getcreate__UniqueFQDNSet__by_domainObjects(ctx, domain_objects.values())

    return (dbUniqueFQDNSet, is_created_fqdn)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__UniqueFQDNSet__by_domainObjects(ctx, domainObjects):
    """
    getcreate wrapping unique fqdn

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domainObjects:
    """
    is_created = False

    domain_ids = [dbDomain.id for dbDomain in domainObjects]
    domain_ids.sort()
    domain_ids_string = ",".join([str(id_) for id_ in domain_ids])

    dbUniqueFQDNSet = (
        ctx.dbSession.query(model_objects.UniqueFQDNSet)
        .filter(model_objects.UniqueFQDNSet.domain_ids_string == domain_ids_string)
        .first()
    )

    if not dbUniqueFQDNSet:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(
            ctx, model_utils.OperationsEventType.from_string("UniqueFQDNSet__insert")
        )

        dbUniqueFQDNSet = model_objects.UniqueFQDNSet()
        dbUniqueFQDNSet.domain_ids_string = domain_ids_string
        dbUniqueFQDNSet.count_domains = len(domain_ids)
        dbUniqueFQDNSet.timestamp_created = ctx.timestamp
        dbUniqueFQDNSet.operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbUniqueFQDNSet)
        ctx.dbSession.flush(objects=[dbUniqueFQDNSet])

        for dbDomain in domainObjects:
            dbAssoc = model_objects.UniqueFQDNSet2Domain()
            dbAssoc.unique_fqdn_set_id = dbUniqueFQDNSet.id
            dbAssoc.domain_id = dbDomain.id
            ctx.dbSession.add(dbAssoc)
            ctx.dbSession.flush(objects=[dbAssoc])
        is_created = True

        event_payload_dict["unique_fqdn_set.id"] = dbUniqueFQDNSet.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "UniqueFQDNSet__insert"
            ),
            dbUniqueFQDNSet=dbUniqueFQDNSet,
        )

    return (dbUniqueFQDNSet, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "getcreate__AcmeAccount",
    "getcreate__CACertificate__by_pem_text",
    "getcreate__CertificateRequest__by_pem_text",
    "getcreate__Domain__by_domainName",
    "getcreate__PrivateKey__by_pem_text",
    "getcreate__ServerCertificate",
    "getcreate__UniqueFQDNSet__by_domainObjects",
)
