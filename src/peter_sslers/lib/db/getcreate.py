# stdlib
import datetime
import json
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
import cert_utils
import sqlalchemy
from typing_extensions import Literal
from typing_extensions import TypedDict


# localapp
from .create import create__AcmeChallenge
from .create import create__CertificateRequest
from .create import create__CertificateSigned
from .create import create__PrivateKey
from .get import get__AcmeAuthorization__by_authorization_url
from .get import get__AcmeChallenge__by_challenge_url
from .get import get__AcmeDnsServer__by_root_url
from .get import get__AcmeServer__by_server
from .get import get__CertificateCA__by_pem_text
from .get import get__CertificateCAChain__by_pem_text
from .get import get__CertificateRequest__by_pem_text
from .get import get__Domain__by_name
from .get import get__PrivateKey_CurrentDay_AcmeAccount
from .get import get__PrivateKey_CurrentDay_Global
from .get import get__PrivateKey_CurrentWeek_AcmeAccount
from .get import get__PrivateKey_CurrentWeek_Global
from .logger import _log_object_event
from .logger import log__OperationsEvent
from .update import update_AcmeAuthorization_from_payload
from .update import update_AcmeDnsServer__set_global_default
from .validate import validate_domain_names
from .. import errors
from .. import utils
from ... import lib
from ...model import objects as model_objects
from ...model import utils as model_utils

# from .get import get__DomainBlocklisted__by_name

if TYPE_CHECKING:
    from ..acme_v2 import AuthenticatedUser
    from ..utils import ApiContext
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeAuthorization
    from ...model.objects import AcmeChallenge
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeOrder
    from ...model.objects import CertificateCA
    from ...model.objects import CertificateCAChain
    from ...model.objects import CertificateRequest
    from ...model.objects import CertificateSigned
    from ...model.objects import Domain
    from ...model.objects import PrivateKey
    from ...model.objects import RemoteIpAddress
    from ...model.objects import UniqueFQDNSet
    from ...model.objects import UniquelyChallengedFQDNSet
    from ...model.utils import DomainsChallenged


# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


class getcreate__AcmeAccount__kwargs(TypedDict, total=False):
    """
    this class is used for typing a dict submitted to `getcreate__AcmeAccount`
    """

    acme_account_key_source_id: int
    key_pem: Optional[str]
    le_meta_jsons: Optional[str]
    le_pkey_jsons: Optional[str]
    le_reg_jsons: Optional[str]
    acme_server_id: Optional[int]
    contact: Optional[str]
    terms_of_service: Optional[str]
    account_url: Optional[str]
    event_type: str
    private_key_technology_id: Optional[int]
    order_default_private_key_cycle_id: Optional[int]
    order_default_private_key_technology_id: Optional[int]


def getcreate__AcmeAccount(
    ctx: "ApiContext",
    acme_account_key_source_id: int,
    key_pem: Optional[str] = None,
    le_meta_jsons: Optional[str] = None,
    le_pkey_jsons: Optional[str] = None,
    le_reg_jsons: Optional[str] = None,
    acme_server_id: Optional[int] = None,
    contact: Optional[str] = None,
    terms_of_service: Optional[str] = None,
    account_url: Optional[str] = None,
    event_type: str = "AcmeAccount__insert",
    private_key_technology_id: Optional[int] = None,
    order_default_private_key_cycle_id: Optional[int] = None,
    order_default_private_key_technology_id: Optional[int] = None,
) -> Tuple["AcmeAccount", bool]:
    """
    Gets or Creates AcmeAccount+AcmeAccountKey for LetsEncrypts' ACME server

    returns:
        tuple(`model.utils.AcmeAccount`, `is_created[Boolean]`)

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param acme_account_key_source_id: (required) id corresponding to a :class:`model.utils.AcmeAccountKeySource`
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
    :param acme_server_id: (optional) id corresponding to a :class:`model.objects.AcmeServer` server. required if `key_pem``; do not submit if `le_*` kwargs are provided.
    :param contact: (optional) contact info from acme server
    :param terms_of_service: (optional) str
    :param account_url: (optional)
    :param private_key_technology_id: (optional) id corresponding to a :class:`model.utils.KeyTechnology`
    :param order_default_private_key_cycle_id: (optional) id corresponding to a :class:`model.utils.PrivateKeyCycle`
    :param order_default_private_key_technology_id: (optional) id corresponding to a :class:`model.utils.KeyTechnology`
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
    # _strategy = None

    _event_type_key = None
    if event_type == "AcmeAccount__create":
        _event_type_key = "AcmeAccountKey__create"
    elif event_type == "AcmeAccount__insert":
        _event_type_key = "AcmeAccountKey__insert"
    else:
        raise ValueError("invalid `event_type`")

    # KeyTechnology
    if private_key_technology_id is None:
        private_key_technology_id = model_utils.KeyTechnology._DEFAULT_AcmeAccount_id
    if (
        private_key_technology_id
        not in model_utils.KeyTechnology._options_AcmeAccount_private_key_technology_id
    ):
        raise ValueError("invalid `private_key_technology_id`")

    # AcmeOrder Defaults
    if order_default_private_key_cycle_id is None:
        order_default_private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
            model_utils.PrivateKeyCycle._DEFAULT_AcmeAccount_order_default
        )
    if (
        order_default_private_key_cycle_id
        not in model_utils.PrivateKeyCycle._options_AcmeAccount_order_default_id
    ):
        raise ValueError("invalid `order_default_private_key_cycle_id`")

    if order_default_private_key_technology_id is None:
        order_default_private_key_technology_id = (
            model_utils.KeyTechnology._DEFAULT_AcmeAccount_order_default_id
        )
    if (
        order_default_private_key_technology_id
        not in model_utils.KeyTechnology._options_AcmeAccount_order_default_id
    ):
        raise ValueError("invalid `order_default_private_key_technology_id`")

    # scoping
    # _letsencrypt_data = None

    # quickly audit args/derive info
    if key_pem:
        # _strategy = "key_pem"
        if not contact:
            raise ValueError("must supply `contact` when submitting `key_pem`")
        if not acme_server_id:
            raise ValueError("no `acme_server_id`; required if PEM key is submitted.")

        dbAcmeServer = ctx.dbSession.query(model_objects.AcmeServer).get(acme_server_id)
        if not dbAcmeServer:
            raise ValueError("invalid `acme_server_id`.")

        # cleanup these
        key_pem = cert_utils.cleanup_pem_text(key_pem)
        key_pem_md5 = cert_utils.utils.md5_text(key_pem)

    elif not key_pem:
        # _strategy = "LetsEncrypt payload"
        if contact:
            raise ValueError("do not submit `contact` with LetsEncrypt payload")
        if acme_server_id:
            raise ValueError("do not submit `acme_server_id` with LetsEncrypt payload")
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
        if TYPE_CHECKING:
            assert le_reg_jsons is not None
            assert le_pkey_jsons is not None
            assert le_meta_jsons is not None
        le_reg_json = json.loads(le_reg_jsons)
        # le_meta_json = json.loads(le_meta_jsons)
        # _letsencrypt_data = {"meta.json": le_meta_json, "regr.json": le_reg_json}
        # _letsencrypt_data = json.dumps(_letsencrypt_data, sort_keys=True)
        try:
            contact = le_reg_json["body"]["contact"][0]
            if contact and contact.startswith("mailto:"):
                contact = contact[7:]
        except Exception as exc:  # noqa: F841
            log.critical("Could not parse `contact` from LetsEncrypt payload")
            contact = "invalid.contact.import@example.com"

        account_url = le_reg_json.get("uri")
        if not account_url:
            raise ValueError("could not detect an uri from LetsEncrypt payload")
        _account_server = lib.utils.url_to_server(account_url)
        if not _account_server:
            raise ValueError(
                "could not detect an AcmeServer server from LetsEncrypt payload"
            )
        terms_of_service = le_reg_json.get("terms_of_service", "").strip()

        # derive the api server
        dbAcmeServer = get__AcmeServer__by_server(ctx, _account_server)
        if not dbAcmeServer:
            raise ValueError("invalid AcmeServer detected from LetsEncrypt payload")
        acme_server_id = dbAcmeServer.id

        key_pem = cert_utils.convert_lejson_to_pem(le_pkey_jsons)
        key_pem = cert_utils.cleanup_pem_text(key_pem)
        key_pem_md5 = cert_utils.utils.md5_text(key_pem)

    if acme_server_id is None:
        raise ValueError("Could not derive, or missing supplied, `acme_server_id`")

    # now proceed with a single path of logic

    # check for an AcmeAccount and AcmeAccountKey separately
    # SCENARIOS:
    # 1. No AcmeAccount or AcmeAccountKey - CREATE BOTH
    # 2. Existing AcmeAccount, new AcmeAccountKey - CREATE NONE. ERROR.
    # 3. Existing AcmeAccountKey, new AcmeAccount - CREATE NONE. ERROR.

    if contact:
        dbAcmeAccount = (
            ctx.dbSession.query(model_objects.AcmeAccount)
            .filter(
                sqlalchemy.func.lower(model_objects.AcmeAccount.contact)
                == contact.lower(),
                model_objects.AcmeAccount.acme_server_id == acme_server_id,
            )
            .first()
        )
    else:
        dbAcmeAccount = (
            ctx.dbSession.query(model_objects.AcmeAccount)
            .filter(
                sqlalchemy.or_(
                    sqlalchemy.func.lower(model_objects.AcmeAccount.contact) == "",
                    model_objects.AcmeAccount.contact.is_(None),
                ),
                model_objects.AcmeAccount.acme_server_id == acme_server_id,
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
                    "The submitted AcmeServer and contact info is already associated with another AcmeAccountKey.",
                )
            )
    elif dbAcmeAccountKey:
        raise errors.ConflictingObject(
            (
                dbAcmeAccountKey,
                "The submited AcmeAccountKey is already associated with another AcmeAccount.",
            )
        )

    # scoping
    cu_key_technology = None
    key_technology_id: Optional[int] = None
    acckey__spki_sha256 = None
    _tmpfile = None
    try:
        if cert_utils.NEEDS_TEMPFILES:
            _tmpfile = cert_utils.new_pem_tempfile(key_pem)

        # validate + grab the technology
        cu_key_technology = cert_utils.validate_key(
            key_pem=key_pem,
            key_pem_filepath=_tmpfile.name if _tmpfile else None,
        )
        if TYPE_CHECKING:
            assert cu_key_technology is not None
        key_technology_id = model_utils.KeyTechnology.from_cert_utils_tuple(
            cu_key_technology
        )
        assert key_technology_id

        # grab the spki
        acckey__spki_sha256 = cert_utils.parse_key__spki_sha256(
            key_pem=key_pem,
            key_pem_filepath=_tmpfile.name if _tmpfile else None,
        )

    finally:
        if _tmpfile is not None:
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
    dbAcmeAccount.account_url = account_url
    dbAcmeAccount.acme_server_id = acme_server_id
    dbAcmeAccount.private_key_technology_id = private_key_technology_id
    dbAcmeAccount.order_default_private_key_cycle_id = (
        order_default_private_key_cycle_id
    )
    dbAcmeAccount.order_default_private_key_technology_id = (
        order_default_private_key_technology_id
    )
    dbAcmeAccount.operations_event_id__created = dbOperationsEvent_AcmeAccount.id
    ctx.dbSession.add(dbAcmeAccount)
    ctx.dbSession.flush(objects=[dbAcmeAccount])

    if terms_of_service:
        dbTermsOfService = model_objects.AcmeAccount_2_TermsOfService()
        dbTermsOfService.acme_account_id = dbAcmeAccount.id
        dbTermsOfService.is_active = True
        dbTermsOfService.timestamp_created = ctx.timestamp
        dbTermsOfService.terms_of_service = terms_of_service
        ctx.dbSession.add(dbTermsOfService)
        ctx.dbSession.flush(objects=[dbTermsOfService])

    # next, create the AcmeAccountKey
    dbAcmeAccountKey = model_objects.AcmeAccountKey()
    dbAcmeAccountKey.is_active = True
    dbAcmeAccountKey.acme_account_id = dbAcmeAccount.id
    dbAcmeAccountKey.timestamp_created = ctx.timestamp
    dbAcmeAccountKey.key_pem = key_pem
    dbAcmeAccountKey.key_pem_md5 = key_pem_md5
    dbAcmeAccountKey.key_technology_id = key_technology_id
    dbAcmeAccountKey.spki_sha256 = acckey__spki_sha256
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
    ctx: "ApiContext",
    authorization_url: str,
    dbAcmeOrder: "AcmeOrder",
    is_via_new_order: Optional[bool] = None,
) -> Tuple["AcmeAuthorization", bool, bool]:
    """
    used to create auth objects
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authorization_url: (required) the url of an RFC-8555 authorization
    :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the discovered item
    :param is_via_new_order: Boolean was this discovered during a new AcmeOrder? It should always be yes.
    """
    log.info("getcreate__AcmeAuthorizationUrl(")
    if not authorization_url:
        raise ValueError("`authorization_url` is required")
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
        bool(is_created__AcmeAuthorization2Order),
    )


def getcreate__AcmeAuthorization(
    ctx: "ApiContext",
    authorization_url: str,
    authorization_payload: Dict,
    authenticatedUser: "AuthenticatedUser",
    dbAcmeOrder: "AcmeOrder",
    transaction_commit: Optional[bool] = None,
    is_via_new_order: Optional[bool] = None,
) -> Tuple["AcmeAuthorization", bool]:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authorization_url: (required) the url of an RFC-8555 authorization
    :param authorization_payload: (required) an RFC-8555 authorization payload
    :param authenticatedUser: (required) an object which contains a `accountKeyData` attribute
    :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the discovered item
    :param transaction_commit: (optional) Boolean value. `True` to commit.
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

    is_created__AcmeAuthorization = False
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
        # is_created__AcmeAuthorization2Order = True

    _result = process__AcmeAuthorization_payload(  # noqa: F841
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
    ctx: "ApiContext",
    authorization_payload: Dict,
    authenticatedUser: "AuthenticatedUser",
    dbAcmeAuthorization: "AcmeAuthorization",
    dbAcmeOrder: "AcmeOrder",
    transaction_commit: Optional[bool] = None,
) -> Literal[True]:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authorization_payload: (required) an RFC-8555 authorization payload
    :param authenticatedUser: (required) an object which contains a `accountKeyData` attribute
    :param dbAcmeAuthorization: (required) The :class:`model.objects.AcmeAuthorization` associated with the discovered item
    :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the discovered item
    :param transaction_commit: (optional) Boolean value. `True` to persist to the database.
    """
    log.info("process__AcmeAuthorization_payload")
    # is_created__AcmeAuthorization2Order = None

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
        # is_created__AcmeAuthorization2Order = True

    # no matter what, update
    # this will set the following:
    # `dbAcmeAuthorization.timestamp_expires`
    # `dbAcmeAuthorization.domain_id`
    # `dbAcmeAuthorization.acme_status_authorization_id`
    # `dbAcmeAuthorization.timestamp_updated`
    _updated = update_AcmeAuthorization_from_payload(  # noqa: F841
        ctx, dbAcmeAuthorization, authorization_payload
    )

    # parse the payload for our http01 challenge
    try:
        dbAcmeChallenges = getcreate__AcmeChallenges_via_payload(  # noqa: F841
            ctx,
            authenticatedUser=authenticatedUser,
            dbAcmeAuthorization=dbAcmeAuthorization,
            authorization_payload=authorization_payload,
        )
    except errors.AcmeMissingChallenges as exc:  # noqa: F841
        pass

    # persist this to the db
    if transaction_commit:
        ctx.pyramid_transaction_commit()

    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__AcmeChallenges_via_payload(
    ctx: "ApiContext",
    authenticatedUser: "AuthenticatedUser",
    dbAcmeAuthorization: "AcmeAuthorization",
    authorization_payload: Dict,
) -> List[Tuple["AcmeChallenge", bool]]:
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param authenticatedUser: (required) an object which contains a `accountKeyData` attribute
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
            # TODO: should we build an authenticatedUser here?
            keyauthorization = (
                lib.acme_v2.create_challenge_keyauthorization(
                    challenge_token, authenticatedUser.accountKeyData
                )
                if authenticatedUser
                else None
            )
            _dbAcmeChallenge = create__AcmeChallenge(
                ctx,
                dbDomain=dbAcmeAuthorization.domain,
                acme_challenge_type_id=acme_challenge_type_id,
                # optionals
                dbAcmeAuthorization=dbAcmeAuthorization,
                challenge_url=challenge_url,
                token=challenge_token,
                keyauthorization=keyauthorization,
                acme_status_challenge_id=acme_status_challenge_id,
                is_via_sync=True,
            )
            _is_created_AcmeChallenge = True
        else:
            if _dbAcmeChallenge.acme_status_challenge_id != acme_status_challenge_id:
                _dbAcmeChallenge.acme_status_challenge_id = acme_status_challenge_id
                _dbAcmeChallenge.timestamp_updated = datetime.datetime.now(
                    datetime.timezone.utc
                )
                ctx.dbSession.add(_dbAcmeChallenge)
                ctx.dbSession.flush(objects=[_dbAcmeChallenge])
        dbAcmeChallenges.append((_dbAcmeChallenge, _is_created_AcmeChallenge))
    return dbAcmeChallenges


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__AcmeDnsServer(
    ctx: "ApiContext",
    root_url: str,
    is_global_default: Optional[bool] = None,
) -> Tuple["AcmeDnsServer", bool]:
    """
    getcreate wrapping an acms-dns Server (AcmeDnsServer)

    return dbAcmeDnsServer, is_created

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param root_url:
    """
    if not root_url:
        raise ValueError("`root_url` is required")
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
        _res = update_AcmeDnsServer__set_global_default(  # noqa: F841
            ctx, dbAcmeDnsServer
        )

    return (dbAcmeDnsServer, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__CertificateCAChain__by_pem_text(
    ctx: "ApiContext",
    chain_pem: str,
    display_name: Optional[str] = None,
    discovery_type: Optional[str] = None,
) -> Tuple["CertificateCAChain", bool]:
    chain_pem = cert_utils.cleanup_pem_text(chain_pem)
    chain_certs = cert_utils.split_pem_chain(chain_pem)  # this will clean it
    if len(chain_certs) < 1:
        raise ValueError("Did not find at least 1 Certificate in this Chain.")
    is_created = False

    # Ensure the certificate chain is structured front to back
    # this will raise an error
    if len(chain_certs) > 1:
        cert_utils.ensure_chain_order(chain_certs)

    dbCertificateCAChain = get__CertificateCAChain__by_pem_text(ctx, chain_pem)
    if not dbCertificateCAChain:
        chain_pem_md5 = cert_utils.utils.md5_text(chain_pem)
        dbCertificateCAs = []
        for cert_pem in chain_certs:
            (_dbCertificateCA, _is_created) = getcreate__CertificateCA__by_pem_text(
                ctx,
                cert_pem,
                display_name=display_name,
                discovery_type=discovery_type,
            )
            dbCertificateCAs.append(_dbCertificateCA)

        if not display_name:
            display_name = dbCertificateCAs[0].display_name
            if len(dbCertificateCAs) > 1:
                display_name += " > " + dbCertificateCAs[-1].display_name

        # bookkeeping
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(
            ctx,
            model_utils.OperationsEventType.from_string("CertificateCAChain__insert"),
        )

        dbCertificateCAChain = model_objects.CertificateCAChain()
        dbCertificateCAChain.display_name = display_name
        dbCertificateCAChain.discovery_type = discovery_type
        dbCertificateCAChain.timestamp_created = ctx.timestamp
        dbCertificateCAChain.chain_pem = chain_pem
        dbCertificateCAChain.chain_pem_md5 = chain_pem_md5
        dbCertificateCAChain.certificate_ca_0_id = dbCertificateCAs[0].id
        dbCertificateCAChain.certificate_ca_n_id = dbCertificateCAs[-1].id
        dbCertificateCAChain.chain_length = len(dbCertificateCAs)
        dbCertificateCAChain.certificate_ca_ids_string = ",".join(
            [str(i.id) for i in dbCertificateCAs]
        )
        dbCertificateCAChain.operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbCertificateCAChain)
        ctx.dbSession.flush(objects=[dbCertificateCAChain])
        is_created = True

        event_payload_dict["certificate_ca_chain.id"] = dbCertificateCAChain.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "CertificateCAChain__insert"
            ),
            dbCertificateCAChain=dbCertificateCAChain,
        )

    return (dbCertificateCAChain, is_created)


def getcreate__CertificateCA__by_pem_text(
    ctx: "ApiContext",
    cert_pem: str,
    display_name: Optional[str] = None,
    discovery_type: Optional[str] = None,
    is_trusted_root: Optional[bool] = None,
    key_technology_id: Optional[int] = None,
) -> Tuple["CertificateCA", bool]:
    """
    Gets or Creates CertificateCAs

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param cert_pem: (required)
    :param display_name: a name to display this as
    :param discovery_type:
    :param is_trusted_root:
    :param key_technology_id:  :class:`lib.utils.KeyTechnology` value

    """
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    _certs = cert_utils.split_pem_chain(cert_pem)  # this will clean it
    if len(_certs) > 1:
        raise ValueError("More than 1 Certificate in this PEM.")
    elif len(_certs) != 1:
        raise ValueError("Did not find 1 Certificate in this PEM.")
    is_created = False
    dbCertificateCA = get__CertificateCA__by_pem_text(ctx, cert_pem)
    if not dbCertificateCA:
        cert_pem_md5 = cert_utils.utils.md5_text(cert_pem)

        # validate
        _validated = cert_utils.validate_cert(cert_pem=cert_pem)  # noqa: F841

        _key_technology = cert_utils.parse_cert__key_technology(cert_pem=cert_pem)
        if TYPE_CHECKING:
            assert _key_technology is not None

        _key_technology_id = model_utils.KeyTechnology.from_cert_utils_tuple(
            _key_technology
        )
        if key_technology_id is None:
            key_technology_id = _key_technology_id
        else:
            if key_technology_id != _key_technology_id:
                raise ValueError(
                    "Detected a different `key_technology_id` than submitted"
                )

        # bookkeeping
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(
            ctx,
            model_utils.OperationsEventType.from_string("CertificateCA__insert"),
        )

        _cert_data = cert_utils.parse_cert(cert_pem=cert_pem)
        if not display_name:
            display_name = _cert_data["subject"] or "unknown"

        dbCertificateCA = model_objects.CertificateCA()
        dbCertificateCA.display_name = display_name
        dbCertificateCA.discovery_type = discovery_type
        dbCertificateCA.key_technology_id = key_technology_id
        dbCertificateCA.is_trusted_root = is_trusted_root
        dbCertificateCA.timestamp_created = ctx.timestamp
        dbCertificateCA.cert_pem = cert_pem
        dbCertificateCA.cert_pem_md5 = cert_pem_md5
        dbCertificateCA.timestamp_not_before = _cert_data["startdate"]
        dbCertificateCA.timestamp_not_after = _cert_data["enddate"]
        dbCertificateCA.cert_subject = _cert_data["subject"]
        dbCertificateCA.cert_issuer = _cert_data["issuer"]
        dbCertificateCA.fingerprint_sha1 = _cert_data["fingerprint_sha1"]
        dbCertificateCA.key_technology_id = (
            model_utils.KeyTechnology.from_cert_utils_tuple(
                _cert_data["key_technology"]
            )
        )
        dbCertificateCA.spki_sha256 = _cert_data["spki_sha256"]
        dbCertificateCA.cert_issuer_uri = _cert_data["issuer_uri"]
        dbCertificateCA.cert_authority_key_identifier = _cert_data[
            "authority_key_identifier"
        ]
        dbCertificateCA.operations_event_id__created = dbOperationsEvent.id

        ctx.dbSession.add(dbCertificateCA)
        ctx.dbSession.flush(objects=[dbCertificateCA])
        is_created = True

        event_payload_dict["certificate_ca.id"] = dbCertificateCA.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "CertificateCA__insert"
            ),
            dbCertificateCA=dbCertificateCA,
        )

    return (dbCertificateCA, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__CertificateRequest__by_pem_text(
    ctx: "ApiContext",
    csr_pem: str,
    certificate_request_source_id: int,
    dbPrivateKey: "PrivateKey",
    domain_names: List[str],
    dbCertificateSigned__issued: Optional["CertificateSigned"] = None,
    discovery_type: Optional[str] = None,
) -> Tuple["CertificateRequest", bool]:
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
    :param domain_names: (required) A list of fully qualified domain names
    :param dbCertificateSigned__issued: (optional) The :class:`model.objects.CertificateSigned` this issued as
    :param str discovery_type:

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
            domain_names=domain_names,
            dbCertificateSigned__issued=dbCertificateSigned__issued,
            discovery_type=discovery_type,
        )
        is_created = True

    return (dbCertificateRequest, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__CertificateSigned(
    ctx: "ApiContext",
    cert_pem: str,
    cert_domains_expected: List[str],
    dbCertificateCAChain: "CertificateCAChain",
    dbPrivateKey: "PrivateKey",
    certificate_type_id: int,
    dbAcmeOrder: Optional["AcmeOrder"] = None,
    dbCertificateCAChains_alt: Optional[List["CertificateCAChain"]] = None,
    dbCertificateRequest: Optional["CertificateRequest"] = None,
    dbUniqueFQDNSet: Optional["UniqueFQDNSet"] = None,
    discovery_type: Optional[str] = None,
    is_active: bool = False,
) -> Tuple["CertificateSigned", bool]:
    """
    getcreate wrapping issued certs

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param cert_pem: (required) The certificate in PEM encoding
    :param cert_domains_expected: (required) a list of domains in the cert we
      expect to see
    :param dbCertificateCAChain: (required) The upstream
       :class:`model.objects.CertificateCAChain` that signed the certificate
    :param dbPrivateKey: (required) The :class:`model.objects.PrivateKey` that
      signed the certificate
    :param certificate_type_id: (required) The :class:`model.utils.CertifcateType`
      corresponding to this Certificate
    :param dbAcmeOrder: (optional) The :class:`model.objects.AcmeOrder` the
      certificate was generated through. If provivded, do not submit
      `dbCertificateRequest` or `dbPrivateKey`
    :param dbCertificateCAChains_alt: (optional) Iterable. Alternate
      :class:`model.objects.CertificateCAChain`s that signed this certificate
    :param dbCertificateRequest: (optional) The
      :class:`model.objects.CertificateRequest` the certificate was generated
      through. If provivded, do not submit `dbAcmeOrder`.
    :param dbUniqueFQDNSet: (optional) required if there is no `dbAcmeOrder` or
      `dbCertificateRequest` The :class:`model.objects.UniqueFQDNSet`
      representing domains on the certificate.
    :param is_active: (optional) default `None`; do not activate a certificate
      when uploading unless specified.

    returns:
    tuple (dbCertificateSigned, is_created)
    """
    if not any((dbAcmeOrder, dbCertificateRequest, dbUniqueFQDNSet)):
        raise ValueError(
            "getcreate__CertificateSigned must be provided with `dbCertificateRequest`, `dbAcmeOrder` or `dbUniqueFQDNSet`"
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

    if not any((dbAcmeOrder, dbCertificateRequest, dbUniqueFQDNSet)):
        if not dbUniqueFQDNSet:
            raise ValueError(
                "must submit `dbUniqueFQDNSet` if there is no `dbAcmeOrder` or `dbUniqueFQDNSet`"
            )

    if not all(
        (
            cert_pem,
            dbCertificateCAChain,
            dbPrivateKey,
        )
    ):
        raise ValueError(
            "getcreate__CertificateSigned must be provided with all of (cert_pem, dbCertificateCAChain, dbPrivateKey)"
        )

    if certificate_type_id not in model_utils.CertificateType._mapping:
        raise ValueError("invalid `certificate_type_id`")

    is_created = False
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = cert_utils.utils.md5_text(cert_pem)

    # make sure the Certificate Elements match
    _cert_spki = None
    _tmpfile = None
    try:
        if cert_utils.NEEDS_TEMPFILES:
            _tmpfile = cert_utils.new_pem_tempfile(cert_pem)
        # grab the spki
        _cert_spki = cert_utils.parse_cert__spki_sha256(
            cert_pem=cert_pem, cert_pem_filepath=_tmpfile.name if _tmpfile else None
        )
    finally:
        if _tmpfile:
            _tmpfile.close()

    _pkey_spki = None
    _tmpfile = None
    try:
        if cert_utils.NEEDS_TEMPFILES:
            _tmpfile = cert_utils.new_pem_tempfile(dbPrivateKey.key_pem)
        # grab the spki
        _pkey_spki = cert_utils.parse_key__spki_sha256(
            key_pem=dbPrivateKey.key_pem,
            key_pem_filepath=_tmpfile.name if _tmpfile else None,
        )
    finally:
        if _tmpfile:
            _tmpfile.close()

    if not all((_cert_spki, _pkey_spki)):
        raise ValueError("Could not compute the Certificate or Key's SPKI")
    if _cert_spki != _pkey_spki:
        raise ValueError("The PrivateKey did not sign the CertificateSigned")

    if dbCertificateRequest:
        if _cert_spki != dbCertificateRequest.spki_sha256:
            raise ValueError("The PrivateKey did not sign the CertificateRequest")

    dbCertificateSigned = (
        ctx.dbSession.query(model_objects.CertificateSigned)
        .filter(
            model_objects.CertificateSigned.cert_pem_md5 == cert_pem_md5,
            model_objects.CertificateSigned.cert_pem == cert_pem,
        )
        .first()
    )
    if dbCertificateSigned:
        is_created = False
        if dbUniqueFQDNSet:
            if dbCertificateSigned.unique_fqdn_set_id != dbUniqueFQDNSet.id:
                raise ValueError("Integrity Error. UniqueFQDNSet differs.")
        if dbPrivateKey and (dbCertificateSigned.private_key_id != dbPrivateKey.id):
            if dbCertificateSigned.private_key_id:
                raise ValueError("Integrity Error. Competing PrivateKey (!?)")
            elif dbCertificateSigned.private_key_id is None:
                dbCertificateSigned.private_key_id = dbPrivateKey.id
                dbPrivateKey.count_certificate_signeds += 1
                if not dbPrivateKey.timestamp_last_certificate_issue or (
                    dbPrivateKey.timestamp_last_certificate_issue < ctx.timestamp
                ):
                    dbPrivateKey.timestamp_last_certificate_issue = ctx.timestamp
                ctx.dbSession.flush(objects=[dbCertificateSigned, dbPrivateKey])

        # ensure we have all the Alternate Chains connected to this ServerCerticiate
        _upchains_existing = dbCertificateSigned.certificate_ca_chain_ids
        _upchains_needed = []
        # check the primary
        if dbCertificateCAChain.id not in _upchains_existing:
            _upchains_needed.append(dbCertificateCAChain.id)
        if dbCertificateCAChains_alt:
            # check the alts
            for _dbCertificateCAChain_alt in dbCertificateCAChains_alt:
                if _dbCertificateCAChain_alt.id not in _upchains_existing:
                    _upchains_needed.append(_dbCertificateCAChain_alt.id)
        for _up_needed in _upchains_needed:
            dbCertificateSignedChain = model_objects.CertificateSignedChain()
            dbCertificateSignedChain.certificate_signed_id = dbCertificateSigned.id
            dbCertificateSignedChain.certificate_ca_chain_id = _up_needed
            if _up_needed == dbCertificateCAChain.id:
                dbCertificateSignedChain.is_upstream_default = True
            else:
                dbCertificateSignedChain.is_upstream_default = None
            ctx.dbSession.add(dbCertificateSignedChain)
            ctx.dbSession.flush(objects=[dbCertificateSignedChain])

    elif not dbCertificateSigned:
        dbCertificateSigned = create__CertificateSigned(
            ctx,
            cert_pem=cert_pem,
            cert_domains_expected=cert_domains_expected,
            dbCertificateCAChain=dbCertificateCAChain,
            certificate_type_id=certificate_type_id,
            # optionals
            is_active=is_active,
            dbAcmeOrder=dbAcmeOrder,
            dbCertificateCAChains_alt=dbCertificateCAChains_alt,
            dbCertificateRequest=dbCertificateRequest,
            dbPrivateKey=dbPrivateKey,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            discovery_type=discovery_type,
        )
        is_created = True

    return (dbCertificateSigned, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__Domain__by_domainName(
    ctx: "ApiContext",
    domain_name: str,
    discovery_type: Optional[str] = None,
) -> Tuple["Domain", bool]:
    """
    getcreate wrapping a domain

    return dbDomain, is_created

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_name:
    :param discovery_type:
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
        dbDomain.operations_event_id__created = dbOperationsEvent.id
        dbDomain.discovery_type = discovery_type
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
    ctx: "ApiContext",
    key_pem: str,
    private_key_source_id: int,
    private_key_type_id: int,
    acme_account_id__owner: Optional[int] = None,
    private_key_id__replaces: Optional[int] = None,
    discovery_type: Optional[str] = None,
) -> Tuple["PrivateKey", bool]:
    """
    getcreate wrapping private keys

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param str key_pem:
    :param int private_key_source_id: (required) A string matching a source in A :class:`lib.utils.PrivateKeySource`
    :param int private_key_type_id: (required) Valid options are in :class:`model.utils.PrivateKeyType`
    :param int acme_account_id__owner: (optional) the id of a :class:`model.objects.AcmeAccount` which owns this :class:`model.objects.PrivateKey`
    :param int private_key_id__replaces: (optional) if this key replaces a compromised key, note it.
    :param str discovery_type:
    """
    is_created = False
    key_pem = cert_utils.cleanup_pem_text(key_pem)
    key_pem_md5 = cert_utils.utils.md5_text(key_pem)
    dbPrivateKey = (
        ctx.dbSession.query(model_objects.PrivateKey)
        .filter(
            model_objects.PrivateKey.key_pem_md5 == key_pem_md5,
            model_objects.PrivateKey.key_pem == key_pem,
        )
        .first()
    )
    if not dbPrivateKey:
        key_technology_id: Optional[int] = None
        _tmpfile = None
        try:
            if cert_utils.NEEDS_TEMPFILES:
                _tmpfile = cert_utils.new_pem_tempfile(key_pem)

            # validate + grab the technology
            cu_key_technology = cert_utils.validate_key(
                key_pem=key_pem,
                key_pem_filepath=_tmpfile.name if _tmpfile else None,
            )
            if TYPE_CHECKING:
                assert cu_key_technology is not None
            key_technology_id = model_utils.KeyTechnology.from_cert_utils_tuple(
                cu_key_technology
            )
            assert key_technology_id

            pkey__spki_sha256 = cert_utils.parse_key__spki_sha256(
                key_pem=key_pem, key_pem_filepath=_tmpfile.name if _tmpfile else None
            )

        except Exception as exc:  # noqa: F841
            raise
        finally:
            if _tmpfile:
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
        dbPrivateKey.key_technology_id = key_technology_id
        dbPrivateKey.key_pem = key_pem
        dbPrivateKey.key_pem_md5 = key_pem_md5
        dbPrivateKey.spki_sha256 = pkey__spki_sha256
        dbPrivateKey.operations_event_id__created = dbOperationsEvent.id
        dbPrivateKey.acme_account_id__owner = acme_account_id__owner
        dbPrivateKey.private_key_source_id = private_key_source_id
        dbPrivateKey.private_key_type_id = private_key_type_id
        dbPrivateKey.private_key_id__replaces = private_key_id__replaces
        dbPrivateKey.discovery_type = discovery_type
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


def getcreate__PrivateKey_for_AcmeAccount(
    ctx: "ApiContext",
    dbAcmeAccount: "AcmeAccount",
    key_technology_id: Optional[int] = None,
    private_key_cycle_id: Optional[int] = None,
    private_key_id__replaces: Optional[int] = None,
) -> "PrivateKey":
    """
    getcreate wrapping a dbPrivateKey, which is used by orders

    returns: The :class:`model.objects.PrivateKey`
    raises: ValueError

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbAcmeAccount: (required) The :class:`model.objects.AcmeAccount` that owns the certificate
    :param key_technology_id: (optional) Valid options are in :class:`model.utils.KeyTechnology`
    :param private_key_cycle_id: (optional) Valid options are in :class:`model.utils.PrivateKeyCycle`
    :param private_key_id__replaces: (optional) Passthrough to `create__PrivateKey`

    """
    private_key_cycle: str
    if private_key_cycle_id is None:
        private_key_cycle_id = dbAcmeAccount.order_default_private_key_cycle_id
        private_key_cycle = dbAcmeAccount.order_default_private_key_cycle
    else:
        private_key_cycle = model_utils.PrivateKeyCycle._mapping[private_key_cycle_id]

    if key_technology_id is None:
        key_technology_id = dbAcmeAccount.order_default_private_key_technology_id

    # private_key_technology = dbAcmeAccount.private_key_technology
    acme_account_id__owner = dbAcmeAccount.id

    # scoping
    dbPrivateKey_new: Optional["PrivateKey"]

    if private_key_cycle == "single_use":
        # NOTE: AcmeAccountNeedsPrivateKey ; single_use
        dbPrivateKey_new = create__PrivateKey(
            ctx,
            private_key_source_id=model_utils.PrivateKeySource.GENERATED,
            private_key_type_id=model_utils.PrivateKeyType.SINGLE_USE,
            key_technology_id=key_technology_id,
            acme_account_id__owner=acme_account_id__owner,
            private_key_id__replaces=private_key_id__replaces,
        )
        return dbPrivateKey_new

    elif private_key_cycle == "single_use__reuse_1_year":
        # NOTE: AcmeAccountNeedsPrivateKey ; single_use
        # ???: do we lookup?
        # ???: how is create scoped - within an order?
        dbPrivateKey_new = create__PrivateKey(
            ctx,
            private_key_source_id=model_utils.PrivateKeySource.GENERATED,
            private_key_type_id=model_utils.PrivateKeyType.SINGLE_USE__REUSE_1_YEAR,
            key_technology_id=key_technology_id,
            acme_account_id__owner=acme_account_id__owner,
            private_key_id__replaces=private_key_id__replaces,
        )
        return dbPrivateKey_new

    elif private_key_cycle == "account_daily":
        # NOTE: AcmeAccountNeedsPrivateKey ; account_daily
        dbPrivateKey_new = get__PrivateKey_CurrentDay_AcmeAccount(
            ctx,
            acme_account_id__owner,
        )
        if not dbPrivateKey_new:
            dbPrivateKey_new = create__PrivateKey(
                ctx,
                private_key_source_id=model_utils.PrivateKeySource.GENERATED,
                private_key_type_id=model_utils.PrivateKeyType.ACCOUNT_DAILY,
                key_technology_id=key_technology_id,
                acme_account_id__owner=acme_account_id__owner,
            )
        return dbPrivateKey_new

    elif private_key_cycle == "global_daily":
        # NOTE: AcmeAccountNeedsPrivateKey ; global_daily
        dbPrivateKey_new = get__PrivateKey_CurrentDay_Global(ctx)
        if not dbPrivateKey_new:
            dbPrivateKey_new = create__PrivateKey(
                ctx,
                private_key_source_id=model_utils.PrivateKeySource.GENERATED,
                private_key_type_id=model_utils.PrivateKeyType.GLOBAL_DAILY,
                key_technology_id=model_utils.KeyTechnology._DEFAULT_GlobalKey_id,
            )
        return dbPrivateKey_new

    elif private_key_cycle == "account_weekly":
        # NOTE: AcmeAccountNeedsPrivateKey ; account_weekly
        dbPrivateKey_new = get__PrivateKey_CurrentWeek_AcmeAccount(
            ctx,
            acme_account_id__owner,
        )
        if not dbPrivateKey_new:
            dbPrivateKey_new = create__PrivateKey(
                ctx,
                private_key_source_id=model_utils.PrivateKeySource.GENERATED,
                private_key_type_id=model_utils.PrivateKeyType.ACCOUNT_WEEKLY,
                key_technology_id=dbAcmeAccount.private_key_technology_id,
                acme_account_id__owner=acme_account_id__owner,
            )
        return dbPrivateKey_new

    elif private_key_cycle == "global_weekly":
        # NOTE: AcmeAccountNeedsPrivateKey ; global_weekly
        dbPrivateKey_new = get__PrivateKey_CurrentWeek_Global(ctx)
        if not dbPrivateKey_new:
            dbPrivateKey_new = create__PrivateKey(
                ctx,
                private_key_source_id=model_utils.PrivateKeySource.GENERATED,
                private_key_type_id=model_utils.PrivateKeyType.GLOBAL_WEEKLY,
                key_technology_id=model_utils.KeyTechnology._DEFAULT_GlobalKey_id,
            )
        return dbPrivateKey_new

    elif private_key_cycle == "account_default":
        # NOTE: AcmeAccountNeedsPrivateKey ; account_default | INVALID
        # this should never happen
        # while it is a valid `model_utils.PrivateKeyCycle` option,
        # anything calling this function should not pass it in
        raise ValueError("Invalid option: `account_default`")

    else:
        # NOTE: AcmeAccountNeedsPrivateKey | INVALID
        raise ValueError("Invalid option for `private_key_cycle`")


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__RemoteIpAddress(
    ctx: "ApiContext",
    remote_ip_address: str,
) -> Tuple["RemoteIpAddress", bool]:
    """
    getcreate wrapping a RemoteIpAddress

    returns (dbRemoteIpAddress, is_created)

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_name:
    """
    is_created = False

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


def getcreate__UniqueFQDNSet__by_domains(
    ctx: "ApiContext",
    domain_names: List[str],
    discovery_type: Optional[str] = None,
    allow_blocklisted_domains: Optional[bool] = False,
) -> Tuple["UniqueFQDNSet", bool]:
    """
    getcreate wrapping unique fqdn

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domain_names: a list of domains names (strings)
    :param discovery_type:
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
        _domain_name: getcreate__Domain__by_domainName(
            ctx, _domain_name, discovery_type="via UniqueFQDNSet"
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
    ) = getcreate__UniqueFQDNSet__by_domainObjects(
        ctx,
        list(domain_objects.values()),
        discovery_type=discovery_type,
    )

    return (dbUniqueFQDNSet, is_created_fqdn)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__UniqueFQDNSet__by_domainObjects(
    ctx: "ApiContext",
    domainObjects: List["Domain"],
    discovery_type: Optional[str] = None,
) -> Tuple["UniqueFQDNSet", bool]:
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
        dbUniqueFQDNSet.discovery_type = discovery_type
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


def getcreate__UniquelyChallengedFQDNSet__by_domainObjects_domainsChallenged(
    ctx: "ApiContext",
    domainObjects: Dict[str, "Domain"],
    domainsChallenged: "DomainsChallenged",
    dbUniqueFQDNSet: "UniqueFQDNSet",
    discovery_type: Optional[str] = None,
) -> Tuple["UniquelyChallengedFQDNSet", bool]:
    """
    getcreate wrapping unique fqdn

    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param domainObjects:
    """
    is_created = False

    domain_challenges_serialized = domainsChallenged.serialize_ids(
        mapping=domainObjects
    )

    dbUniquelyChallengedFQDNSet = (
        ctx.dbSession.query(model_objects.UniquelyChallengedFQDNSet)
        .filter(
            model_objects.UniquelyChallengedFQDNSet.domain_challenges_serialized
            == domain_challenges_serialized
        )
        .first()
    )

    if not dbUniquelyChallengedFQDNSet:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(
            ctx,
            model_utils.OperationsEventType.from_string(
                "UniquelyChallengedFQDNSet__insert"
            ),
        )

        dbUniquelyChallengedFQDNSet = model_objects.UniquelyChallengedFQDNSet()
        dbUniquelyChallengedFQDNSet.unique_fqdn_set_id = dbUniqueFQDNSet.id
        dbUniquelyChallengedFQDNSet.domain_challenges_serialized = (
            domain_challenges_serialized
        )
        dbUniquelyChallengedFQDNSet.timestamp_created = ctx.timestamp
        dbUniquelyChallengedFQDNSet.operations_event_id__created = dbOperationsEvent.id
        dbUniquelyChallengedFQDNSet.discovery_type = discovery_type
        ctx.dbSession.add(dbUniquelyChallengedFQDNSet)
        ctx.dbSession.flush(objects=[dbUniquelyChallengedFQDNSet])

        for _ct, _domains in domainsChallenged.items():
            if not _domains:
                continue
            acme_challenge_type_id = model_utils.AcmeChallengeType.from_string(_ct)
            for _domain_name in _domains:
                dbDomain = domainObjects[_domain_name]

                dbAssoc = model_objects.UniquelyChallengedFQDNSet2Domain()
                dbAssoc.uniquely_challenged_fqdn_set_id = dbUniquelyChallengedFQDNSet.id
                dbAssoc.domain_id = dbDomain.id
                dbAssoc.acme_challenge_type_id = acme_challenge_type_id
                ctx.dbSession.add(dbAssoc)
                ctx.dbSession.flush(objects=[dbAssoc])

        is_created = True

        event_payload_dict["uniquely_challenged_fqdn_set.id"] = (
            dbUniquelyChallengedFQDNSet.id
        )
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "UniquelyChallengedFQDNSet__insert"
            ),
            dbUniquelyChallengedFQDNSet=dbUniquelyChallengedFQDNSet,
        )

    return (dbUniquelyChallengedFQDNSet, is_created)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "getcreate__AcmeAccount",
    "getcreate__CertificateCA__by_pem_text",
    "getcreate__CertificateRequest__by_pem_text",
    "getcreate__Domain__by_domainName",
    "getcreate__PrivateKey__by_pem_text",
    "getcreate__CertificateSigned",
    "getcreate__UniqueFQDNSet__by_domainObjects",
    "getcreate__UniquelyChallengedFQDNSet__by_domainObjects_domainsChallenged",
)
