# stdlib
# import base64
# import binascii
import datetime
import hashlib
import json
import logging
import os
import pdb
import re
import time
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union
from urllib.request import Request
from urllib.request import urlopen

# import pdb
# import pprint
# import subprocess

# pypi
import cert_utils
from cert_utils.model import AccountKeyData
import josepy
import requests
from requests.utils import parse_header_links
from typing_extensions import Literal
from typing_extensions import NotRequired
from typing_extensions import TypedDict
from urllib3.util.ssl_ import create_urllib3_context

# localapp
from . import acmedns as lib_acmedns
from . import cas
from . import errors
from . import utils
from . import utils_dns
from .db import create as db_create
from .db import get as db_get
from .db import update as db_update
from .utils import ari_timestamp_to_python
from .utils import new_BrowserSession
from .utils_datetime import datetime_ari_timely
from .. import USER_AGENT
from ..model import utils as model_utils

if TYPE_CHECKING:
    from ..model.objects import AcmeAccount
    from ..model.objects import AcmeAccountKey
    from ..model.objects import AcmeAuthorization
    from ..model.objects import AcmeChallenge
    from ..model.objects import AcmeOrder
    from ..model.objects import AcmeServer
    from ..model.objects import CertificateSigned
    from ..model.objects import UniqueFQDNSet
    from ..model.utils import DomainsChallenged
    from .db.logger import AcmeLogger
    from .context import ApiContext
    from email.message import Message
    from http.client import HTTPMessage
    from requests import Response
    from requests.structures import CaseInsensitiveDict

    HEADERS_COMPAT = Union["HTTPMessage", "CaseInsensitiveDict", "Message"]

    # (resp_data, status_code, headers)
    # resp_data might be decoded from str into json
    RESPONSE_TUPLE = Tuple[int, Union[Dict, str], "HTTPMessage"]

# ==============================================================================

log = logging.getLogger("peter_sslers.lib")
log_api = logging.getLogger("peter_sslers.lib.acme_api")

# ------------------------------------------------------------------------------


MAX_DEPTH = 10
DEBUG_HEADERS = False
SECONDS_POLLING_TIMEOUT = 45

# TODO - should this be a config var?
DEBUG_CHALLENGES_MANUAL = bool(int(os.getenv("DEBUG_CHALLENGES_MANUAL", "0")))
if DEBUG_CHALLENGES_MANUAL:
    print("ALERT!!!!")
    print("ENV is set with `DEBUG_CHALLENGES_MANUAL=1`")
    print("This will pause the application if a failure occurs during precheck")


class AriCheckResult(TypedDict):
    """
    AriCheck[payload] will be null if there is an error
    AriCheck[headers] will always exist
    """

    payload: Optional[Dict]
    headers: "CaseInsensitiveDict"
    status_code: int

    def as_json(self):  # type: ignore[misc]
        return self["payload"]


class AcmeOrderPayload(TypedDict):
    identifiers: List[Dict[str, str]]
    profile: NotRequired[str]
    replaces: NotRequired[str]


def new_response_404() -> Dict:
    return {"status": "*404*"}


def new_response_invalid() -> Dict:
    return {"status": "invalid"}


def url_request(
    ctx: "ApiContext",
    url: str,
    post_data: Optional[Dict] = None,
    err_msg: str = "Error",
    depth: int = 0,
    dbAcmeServer: Optional["AcmeServer"] = None,
) -> "RESPONSE_TUPLE":
    """
    Originally from acme-tiny
    # helper function - make request and automatically parse json response

    :param str url: (required) The url
    :param dict post_data: (optional) Data to POST to the url
    :param str err_msg: (optional) A custom error message
    :param int depth: (optional) An integer nothing the depth of this function being called
    :param `model_objects.AcmeServer` dbAcmeServer: an AcmeServer, or compatible object,
        with a function `local_ca_bundle(ctx)` that will return a CA Bundle filepath
        if a custom CA bundle is needed

    returns (status_code, resp_data, headers)
    """
    log_api.info("acme_v2.url_request(")
    log_api.debug(" REQUEST-")
    log_api.debug("  url       > %s", url)
    log_api.debug("  post_data > %s", post_data)
    log_api.debug("  depth     > %s", depth)
    if depth > MAX_DEPTH:
        raise ValueError("depth > MAX_DEPTH[%s]" % MAX_DEPTH)
    context = None
    alt_bundle = dbAcmeServer.local_ca_bundle(ctx) if dbAcmeServer else None
    try:
        post_headers = {
            "Content-Type": "application/jose+json",
            "User-Agent": USER_AGENT,
        }
        if alt_bundle:
            # see https://github.com/urllib3/urllib3/issues/3571
            context = create_urllib3_context()
            context.load_verify_locations(cafile=alt_bundle)
            log_api.info("Making a request with alt_bundle: %s", alt_bundle)
        resp = urlopen(
            Request(url, data=post_data, headers=post_headers),
            context=context,
            timeout=10,
        )
        log_api.debug(" RESPONSE-")
        resp_data, status_code, headers = (
            resp.read().decode("utf8"),
            resp.getcode(),
            resp.headers,
        )
        log_api.debug("  status_code < %s", status_code)
        log_api.debug("  resp_data   < %s", resp_data)
        log_api.debug("  headers     < %s", headers)
    except IOError as exc:
        resp_data = exc.read().decode("utf8") if hasattr(exc, "read") else str(exc)
        status_code, headers = getattr(exc, "code", None), {}
        # potentially there is a code=400  body=json{"type": "urn:ietf:params:acme:error:badNonce"}
        # that is caught below
    except Exception as exc:
        # TODO: log this error to the database
        raise errors.AcmeCommunicationError(str(exc))
    try:
        resp_data = json.loads(resp_data)  # try to parse json results
    except ValueError:
        pass  # ignore json parsing errors
    if status_code == 404:
        raise errors.AcmeServer404(404, resp_data)
    elif status_code == 400:
        # this happens on pebble if we set it to http, not https
        if resp_data == "Client sent an HTTP request to an HTTPS server.\n":
            raise IndexError(resp_data)
        if (
            isinstance(resp_data, dict)
            and resp_data["type"] == "urn:ietf:params:acme:error:badNonce"
        ):
            raise IndexError(resp_data)  # allow `MAX_DEPTH` retrys for bad nonces
    if status_code not in [200, 201, 204]:
        if isinstance(resp_data, dict):
            # (status_code, url, resp_data, headers) = exc.args
            raise errors.AcmeServerError(status_code, url, resp_data, headers)
        # reformat the error for display
        # this should probably be undone
        msg = "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(
            err_msg, url, post_data, status_code, resp_data
        )
        # (status_code, url, resp_data, headers) = exc.args
        raise errors.AcmeServerError(status_code, url, msg, headers)
    return status_code, resp_data, headers


# ------------------------------------------------------------------------------


def get_authorization_challenges(
    authorization_response: Dict,
    required_challenges: Optional[List[str]] = None,
) -> Dict[str, Optional[Dict]]:
    """
    :param dict authorization_response: (required) A Python dict representing a server's JSON payload of an Authorization Object.
    :param list required_challenges: (optional) Pass in a list of required challenges

    returns:
        `dict` in which keys are the challenge type and values are the challenge payload.
    """

    challenges: Dict[str, Optional[Dict]] = {
        "http-01": None,
        "dns-01": None,
        "tls-alpn-01": None,
    }
    for _challenge in authorization_response["challenges"]:
        if _challenge["type"] in challenges:
            challenges[_challenge["type"]] = _challenge
    if required_challenges:
        for _type in required_challenges:
            if (_type not in challenges) or (not challenges[_type]):
                raise errors.AcmeMissingChallenges(
                    "could not find a required challenge"
                )
    if not any(challenges.values()):
        raise errors.AcmeMissingChallenges("could not find a challenge")
    return challenges


def filter_specific_challenge(
    acme_challenges_payload: Dict,
    acme_challenge_type: Optional[str] = None,
) -> Dict[str, Optional[Dict]]:
    """
    :param dict acme_challenges_payload: (required) A payload of acme-challenges
    :param str acme_challenge_type: (required) The selected type of acme-challenge
    """
    if (
        acme_challenge_type not in acme_challenges_payload
    ) or not acme_challenges_payload[acme_challenge_type]:
        raise ValueError("selected challenege not provided by ACME server")
    return acme_challenges_payload[acme_challenge_type]


def create_challenge_keyauthorization(
    token: str,
    accountKeyData: AccountKeyData,
) -> str:
    """
    :param str token: (required) A string `token` entry from a server Challenge object
    :param str accountKeyData: (required) an instance conforming to `cert_utils.model.AccountKeyData`
        in that it at-least has a `.thumbprint` attribute of an Authenticated Account
    """
    token = re.sub(r"[^A-Za-z0-9_\-]", "_", token)
    keyauthorization = "{0}.{1}".format(token, accountKeyData.thumbprint)
    return keyauthorization


def create_dns01_keyauthorization(
    keyauthorization: str,
) -> str:
    """

    Certbot:: acme/acme/challenges.py

    class DNS01(KeyAuthorizationChallenge):
        def validation(self, account_key, **unused_kwargs):
            return jose.b64encode(hashlib.sha256(self.key_authorization(
                account_key).encode("utf-8")).digest()).decode()

    """
    dns_keyauthorization = josepy.b64encode(
        hashlib.sha256(keyauthorization.encode("utf-8")).digest()
    ).decode("utf8")
    return dns_keyauthorization


# ------------------------------------------------------------------------------


def acme_directory_get(ctx: "ApiContext", acmeAccount: "AcmeAccount") -> Dict:
    """
    Get the ACME directory of urls

    :param acmeAccount: (required) a :class:`model.objects.AcmeAccount` instance
    """
    log_api.info("acme_v2.acme_directory_get(")
    directory_url = acmeAccount.acme_server.directory_url
    if not directory_url:
        raise ValueError("no directory for the CERTIFICATE_AUTHORITY!")
    _status_code, directory_payload, _headers = url_request(
        ctx,
        directory_url,
        err_msg="Error getting directory",
        dbAcmeServer=acmeAccount.acme_server,
    )
    if not directory_payload:
        raise ValueError("no directory data for the CERTIFICATE_AUTHORITY")
    if not isinstance(directory_payload, dict):
        raise ValueError("could not decode `directory_payload` to json")
    log_api.info(") acme_directory_get success")
    return directory_payload


# ------------------------------------------------------------------------------


class AcmeOrderRFC(object):
    """
    An object wrapping up an ACME server order

    Attributes:

    :param rfc_object: (required) A Python dict representing the RFC AcmeOrder object
    :param response_headers: (required) The headers of the ACME Directory's response
    :param dbUniqueFQDNSet: (required) A :class:`model.objects.UniqueFQDNSet` object
    """

    rfc_object: Dict
    response_headers: "HTTPMessage"  # Dict-like
    dbUniqueFQDNSet: "UniqueFQDNSet"

    def __init__(
        self,
        rfc_object: Dict,
        response_headers: "HTTPMessage",
        dbUniqueFQDNSet: "UniqueFQDNSet",
    ):
        self.rfc_object = rfc_object
        self.response_headers = response_headers
        self.dbUniqueFQDNSet = dbUniqueFQDNSet


def get_header_links(
    response_headers: "HEADERS_COMPAT",
    relation_type: str,
) -> List[str]:
    """
    based on certbot's `_get_links`
    https://github.com/certbot/certbot/pull/8080/files#diff-2ddf346e79198cd9bd28a8e8ee691b7b

    :param headers: response headers
    :param relation_type: the relation type sought

    The response object may have multiple links:

        Link: <https://acme-staging-v02.api.letsencrypt.org/directory>;rel="index"
        Link: <https://acme-staging-v02.api.letsencrypt.org/acme/cert/12345/1>;rel="alternate"

    In Python 3.x , the <httplib.HTTPMessage> class has a `.get_all()` method:

        (Pdb) response_headers.get_all("Link")
        ['<https://acme-staging-v02.api.letsencrypt.org/directory>;rel="index"',
         '<https://acme-staging-v02.api.letsencrypt.org/acme/cert/12345/1>;rel="alternate"'
         ]

    But in Python 2.x, we only have `get`:

        (Pdb) response_headers.get("Link")
        '<https://acme-staging-v02.api.letsencrypt.org/directory>;rel="index",
         <https://acme-staging-v02.api.letsencrypt.org/acme/cert/fa536ddfe679c4bcbdf48271f36975729229/1>;rel="alternate"'


    Coverage for this is provided by:

        tests_unit.UnitTest_ACME_v2.test__parse_headers
    """
    if "Link" not in response_headers:
        return []
    if hasattr(response_headers, "get_all"):
        links_a_ = response_headers.get_all("Link")
        if TYPE_CHECKING:
            assert links_a_ is not None
        links_a__ = [parse_header_links(h) for h in links_a_]
        links = [_l[0] for _l in links_a__ if _l]
    else:
        # '<https://acme-staging-v02.api.letsencrypt.org/directory>;rel="index", <https://acme-staging-v02.api.letsencrypt.org/acme/cert/123/1>;rel="alternate"'
        links_b_ = response_headers.get("Link")
        if TYPE_CHECKING:
            assert links_b_ is not None
        links = parse_header_links(links_b_)
    return [
        _l["url"]
        for _l in links
        if "rel" in _l and "url" in _l and _l["rel"] == relation_type
    ]


def b64_payload(payload=Any) -> str:
    if payload is None:
        return ""
    # cert_utils.jose_b64 -> string
    return cert_utils.jose_b64(json.dumps(payload, sort_keys=True).encode("utf8"))


def sign_payload(
    endpoint_type: str,
    url: str,
    payload: Any,
    accountKeyData: AccountKeyData,
    nonce: str,
    kid: Optional[str] = None,
):
    """
    This format is used by core operations

    kid should be the AcmeAccount URL, if it exists

    JWK is required for:
        newAccount
        revokeCert

    For all other requests, the request is signed using an existing
    account, and there MUST be a "kid" field.

    """
    protected: Dict = {
        "alg": accountKeyData.alg,
        "nonce": nonce,
        "url": url,
    }
    if endpoint_type in ("newAccount", "revokeCert"):
        protected.update({"jwk": accountKeyData.jwk})
    else:
        if not kid:
            raise ValueError(
                "`kid` is required for all payloads except: newAccount, revokeCert"
            )
        protected.update({"kid": kid})

    protected64 = b64_payload(protected)
    payload64 = b64_payload(payload)
    protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
    signature = cert_utils.account_key__sign(
        protected_input,
        key_pem=accountKeyData.key_pem,
    )
    """
    # DEBUGGING
    if False:
        _verified = cert_utils.account_key__verify(
            signature,
            protected_input,
            key_pem=accountKeyData.key_pem,
        )
    """

    _signed_payload = json.dumps(
        {
            "protected": protected64,
            "payload": payload64,
            "signature": cert_utils.jose_b64(signature),
        }
    )
    return _signed_payload


def sign_payload_inner(
    url: str,
    payload: Any,
    accountKeyData: AccountKeyData,
) -> Dict:
    """
    This format is used by the `keyChange` rollover endpoint's inner payload.

    :param payload: the payload to sign
    :param url: the url in the protected section
    :param accountKeyData: instance of `cert_utils.model.AccountKeyData` used to sign
        this should be the NEW key

    Notes:

    1. This format does not use a Nonce
    2. This does not invoke `json.dumps()`

    Reference:

        https://tools.ietf.org/html/rfc8555#section-7.3.5
        https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.3.6

    Example:
              "payload": base64url({
                "protected": base64url({
                  "alg": "ES256",
                  "jwk": /* new key */,
                  "url": "https://example.com/acme/key-change"
                }),
                "payload": base64url({
                  "account": "https://example.com/acme/acct/1",
                  "oldKey": /* old key */
                }),
                "signature": "Xe8B94RD30Azj2ea...8BmZIRtcSKPSd8gU"
              }),
    """
    protected = {
        "url": url,
        "alg": accountKeyData.alg,
        "jwk": accountKeyData.jwk,
    }
    protected64 = b64_payload(protected)
    payload64 = b64_payload(payload)
    protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
    signature = cert_utils.account_key__sign(
        protected_input,
        key_pem=accountKeyData.key_pem,
    )
    if True:
        _verified = cert_utils.account_key__verify(  # noqa: F841
            signature,
            protected_input,
            key_pem=accountKeyData.key_pem,
        )
    _signed_payload = {
        "protected": protected64,
        "payload": payload64,
        "signature": cert_utils.jose_b64(signature),
    }
    return _signed_payload


# ------------------------------------------------------------------------------


class AuthenticatedUser(object):
    # our API guarantees these items
    ctx: "ApiContext"
    acmeLogger: "AcmeLogger"
    acmeAccount: "AcmeAccount"
    acme_directory: Dict  # the payload from the remote server
    log__OperationsEvent: Optional[Callable]

    accountKeyData: (
        AccountKeyData  # an instance conforming to `cert_utils.model.AccountKeyData`
    )

    _api_account_object: Optional[Dict] = None  # api server native/json object
    _api_account_headers: Optional[Union[Dict, "HTTPMessage"]] = (
        None  # api server native/json object
    )
    # default to None;
    # set True if server known to support it
    # set False if server known to NOT support it
    # if None, we may want to check
    supports_ari: Optional[bool] = None
    _next_nonce: Optional[str] = None

    def __init__(
        self,
        ctx: "ApiContext",
        acmeLogger: "AcmeLogger",
        acmeAccount: "AcmeAccount",
        acme_directory: Optional[Dict] = None,
        log__OperationsEvent: Optional[Callable] = None,
        func_acmeAccount_directory_updates: Optional[Callable] = None,
        acknowledge_transaction_commits: Optional[Literal[True]] = None,
    ):
        """
        :param acmeLogger: (required) A :class:`.logger.AcmeLogger` instance
        :param acmeAccount: (required) A :class:`model.objects.AcmeAccount` object
        :param acme_directory: (optional) The ACME Directory payload. If not supplied, this will
            be generated.
        :param log__OperationsEvent: (required) callable function to log the operations event
        """
        if not acknowledge_transaction_commits:
            raise errors.AcknowledgeTransactionCommitRequired()
        self.ctx = ctx
        if not all((acmeLogger, acmeAccount)):
            raise ValueError("all elements are required: (acmeLogger, acmeAccount)")

        if acme_directory is None:
            # semaphore
            fetch_directory = True
            # don't trust the ctx.timestamp as we could be in a long running process
            timestamp_now = datetime.datetime.now(datetime.timezone.utc)
            dbAcmeServerConfiguration = (
                db_get.get__AcmeServerConfiguration__by_AcmeServerId__active(
                    ctx, acmeAccount.acme_server_id
                )
            )
            if dbAcmeServerConfiguration:
                timestamp_max = timestamp_now - datetime.timedelta(seconds=300)
                if dbAcmeServerConfiguration.timestamp_lastchecked > timestamp_max:
                    fetch_directory = False
                    acme_directory = json.loads(
                        dbAcmeServerConfiguration.directory_payload
                    )
            if fetch_directory:
                acme_directory = acme_directory_get(self.ctx, acmeAccount)
                db_update.update_AcmeServer_directory(
                    ctx,
                    acmeAccount.acme_server,
                    acme_directory_payload=acme_directory,
                    timestamp=timestamp_now,
                )
                # TODO: the above and below should be consolidated
                if func_acmeAccount_directory_updates:
                    func_acmeAccount_directory_updates(
                        ctx,
                        acmeAccount,
                        acme_directory,
                        acknowledge_transaction_commits=acknowledge_transaction_commits,
                    )
            if TYPE_CHECKING:
                assert acme_directory is not None

        # covers submitted & cached/fetched
        self.acme_directory = acme_directory

        # parse account key to get public key
        self.accountKeyData = AccountKeyData(
            key_pem=acmeAccount.acme_account_key.key_pem,
        )

        # configure the object!
        self.acmeLogger = acmeLogger
        self.acmeAccount = acmeAccount
        self.log__OperationsEvent = log__OperationsEvent
        if acmeAccount.acme_server and acmeAccount.acme_server.is_supports_ari:
            self.supports_ari = True

    def _send_signed_request(
        self,
        endpoint_type: str,
        url: str,
        payload: Any = None,
        depth: int = 0,
    ) -> "RESPONSE_TUPLE":
        """
        Originally from acme-tiny
        :param url: (required) The url
        :param payload: (optional) A Python dict of data to POST to the url
        :param depth: (optional) An integer nothing the depth of this function being called

        This proxies `url_request` with a signed payload
        returns (status_code, resp_data, headers)
        """
        log.debug("_send_signed_request")
        log.debug("_send_signed_request | depth=%s" % depth)
        if depth > MAX_DEPTH:
            raise ValueError("depth > MAX_DEPTH[%s]" % MAX_DEPTH)
        nonce: Optional[str] = None
        if self._next_nonce:
            nonce = self._next_nonce
        else:
            log.debug("_send_signed_request > newNonce")
            # TODO: store/retrieve a nonce from the db
            # this pulls it off the headers
            self._next_nonce = nonce = url_request(
                self.ctx,
                self.acme_directory["newNonce"],
                dbAcmeServer=self.acmeAccount.acme_server,
            )[2]["Replay-Nonce"]

        # the `kid` is the AccountURL on the acme server
        kid = self.acmeAccount.account_url or None
        # if kid is None:
        #    if (self._api_account_headers is not None) and ("Location" in self._api_account_headers):
        #        kid = self._api_account_headers["Location"]
        try:
            _signed_payload = sign_payload(
                endpoint_type=endpoint_type,
                url=url,
                payload=payload,
                accountKeyData=self.accountKeyData,
                nonce=nonce,
                kid=kid,
            )
        except IOError as exc:  # noqa: F841
            log.debug("_send_signed_request > sign_payload | IOError")
            log.debug(exc)
            self._next_nonce = None
            raise
        try:
            result = url_request(
                self.ctx,
                url,
                post_data=_signed_payload.encode("utf8"),
                err_msg="_send_signed_request",
                depth=depth,
                dbAcmeServer=self.acmeAccount.acme_server,
            )
            try:
                if DEBUG_HEADERS:
                    print("*******************************************************")
                    print("_send_signed_request | DEBUG_HEADERS")
                    # print(result[2]._headers)  # undocumented storage attribute
                    print(result[2].items())
                    print("*******************************************************")
                _next_nonce = result[2]["Replay-Nonce"]
                if (not _next_nonce) or (nonce == _next_nonce):
                    self._next_nonce = None
                else:
                    self._next_nonce = _next_nonce
            except IndexError as exc:
                log.debug(
                    "_send_signed_request > sign_payload | _next_nonce IndexError"
                )
                log.debug(exc)
                raise
            except Exception as exc:  # noqa: F841
                log.debug("_send_signed_request > sign_payload | _next_nonce Exception")
                log.debug(exc)
                self._next_nonce = None
            return result
        except IndexError:  # retry bad nonces (they raise IndexError)
            log.debug("_send_signed_request > IndexError retry")
            self._next_nonce = None
            return self._send_signed_request(
                endpoint_type,
                url,
                payload=payload,
                depth=(depth + 1),
            )

    def _poll_until_not(
        self,
        _endpoint_type: str,
        _url: str,
        _pending_statuses: List[str],
        _log_message: str,
    ) -> Dict:
        """
        Originally from acme-tiny
        :param _url: (required) The url
        :param _pending_statuses: (required) The statuses we will continue polling until we lose
        :param depth: (optional) An integer nothing the depth of this function being called

        The response data is a dict
        """
        log.info("acme_v2.AuthenticatedUser._poll_until_not {0}".format(_log_message))
        _result = None
        _t0 = time.time()
        while (_result is None) or (
            isinstance(_result, dict) and _result["status"] in _pending_statuses
        ):
            log.debug(") polling...")
            time.sleep(1 if _result is None else 2)
            _status_code, _result, _headers = self._send_signed_request(
                _endpoint_type,
                _url,
                payload=None,
            )
            if not isinstance(_result, dict):
                raise ValueError("expected `dict` response")
            _tdelta = time.time() - _t0
            if _tdelta > SECONDS_POLLING_TIMEOUT:
                log.critical("polling too long")
                raise errors.AcmePollingTooLong(_tdelta, _result)  # args[0] = tDelta
        if TYPE_CHECKING:
            assert isinstance(_result, dict)
        return _result

    def update_contact(
        self,
        ctx: "ApiContext",
        contact: Optional[str] = None,
    ) -> None:
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param contact: (optional) The updated contact info
        :param is_registration: (optional) Boolean
        """
        log.info("acme_v2.AuthenticatedUser.update_contact( {0}".format(contact))
        payload_contact = {"contact": contact}
        assert self._api_account_headers
        (
            _status_code,
            acme_account_object,
            _acme_account_headers,
        ) = self._send_signed_request(
            "AccountUrl",
            self._api_account_headers["Location"],
            payload=payload_contact,
        )
        if not isinstance(acme_account_object, dict):
            raise ValueError("expected `dict` response")
        self._api_account_object = acme_account_object
        log.debug(") update_contact | acme_account_object: %s" % acme_account_object)
        log.debug(
            ") update_contact | _acme_account_headers: %s" % _acme_account_headers
        )
        log.info(
            ") update_contact | updated {0}".format(
                " ; ".join(acme_account_object["contact"])
            )
        )

    def authenticate(
        self,
        ctx: "ApiContext",
        contact: Optional[str] = None,
        onlyReturnExisting: Optional[bool] = None,
        transaction_commit: Optional[bool] = None,
    ) -> bool:
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param contact: (optional) The contact info
        :param onlyReturnExisting: bool. Default None. see ACME-spec (docs below)
            `onlyReturnExisting=True` requires an EXISTING user
            `onlyReturnExisting=False` will register a NEW user if applicable

        returns:
            False - no matching account
        or
            True - matching account

        https://tools.ietf.org/html/rfc8555#section-7.3

            A client creates a new account with the server by sending a POST
            request to the server's newAccount URL.  The body of the request is a
            stub account object containing some subset of the following fields:

                contact (optional, array of string):  Same meaning as the
                   corresponding server field defined in Section 7.1.2.

                termsOfServiceAgreed (optional, boolean):  Same meaning as the
                   corresponding server field defined in Section 7.1.2.

                onlyReturnExisting (optional, boolean):  If this field is present
                   with the value "true", then the server MUST NOT create a new
                   account if one does not already exist.  This allows a client to
                   look up an account URL based on an account key (see
                   Section 7.3.1).

                externalAccountBinding (optional, object):  Same meaning as the
                   corresponding server field defined in Section 7.1.2

            ...

            The server creates an account and stores the public key used to
            verify the JWS (i.e., the "jwk" element of the JWS header) to
            authenticate future requests from the account.  The server returns
            this account object in a 201 (Created) response, with the account URL
            in a Location header field.  The account URL is used as the "kid"
            value in the JWS authenticating subsequent requests by this account
            (see Section 6.2).  The account URL is also used for requests for
            management actions on this account, as described below.

            ...

            Example - Request

                POST /acme/new-account HTTP/1.1
                Host: example.com
                Content-Type: application/jose+json

                {
                  "protected": base64url({
                    "alg": "ES256",
                    "jwk": {...},
                    "nonce": "6S8IqOGY7eL2lsGoTZYifg",
                    "url": "https://example.com/acme/new-account"
                  }),
                  "payload": base64url({
                    "termsOfServiceAgreed": true,
                    "contact": [
                      "mailto:cert-admin@example.org",
                      "mailto:admin@example.org"
                    ]
                  }),
                  "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
                }

            Example - Response

               HTTP/1.1 201 Created
               Content-Type: application/json
               Replay-Nonce: D8s4D2mLs8Vn-goWuPQeKA
               Link: <https://example.com/acme/directory>;rel="index"
               Location: https://example.com/acme/acct/evOfKhNU60wg

               {
                 "status": "valid",

                 "contact": [
                   "mailto:cert-admin@example.org",
                   "mailto:admin@example.org"
                 ],

                 "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
               }
        """
        log_api.info("acme_v2.AuthenticatedUser.authenticate(")
        if self.acme_directory is None:
            raise ValueError("`acme_directory` is required")

        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "MUST persist external system data."
            )

        if "newAccount" not in self.acme_directory:
            raise ValueError("directory does not support `newAccount`")

        # log the event to the db
        assert ctx.application_settings
        if ctx.application_settings["log.acme"]:
            self.acmeLogger.log_newAccount("v2", transaction_commit=transaction_commit)

        # hit the acme api for the registration
        try:
            """possible api values for newAccount payload are:
            {"contact": None,
             "termsOfServiceAgreed": None,
             "onlyReturnExisting": None,
             "externalAccountBinding": None,
             }
            """
            payload_registration: Dict[str, Union[bool, str, List[str]]] = {
                "termsOfServiceAgreed": True,
            }
            if contact is not None:
                # contact should be a LIST of URI
                if "@" in contact and (not contact.startswith("mailto:")):
                    contact = "mailto:%s" % contact
                payload_registration["contact"] = [
                    contact,
                ]  # spec wants a list
            if onlyReturnExisting is not None:
                payload_registration["onlyReturnExisting"] = onlyReturnExisting

            try:
                (
                    status_code,
                    acme_account_object,
                    acme_account_headers,
                ) = self._send_signed_request(
                    "newAccount",
                    self.acme_directory["newAccount"],
                    payload=payload_registration,
                )
                if not isinstance(acme_account_object, dict):
                    raise ValueError("expected `dict` response")
            except errors.AcmeServerError as exc:
                # only catch this if `onlyReturnExisting` and there is an DNE error
                if onlyReturnExisting:
                    # (status_code, url, resp_data, headers) = exc.args
                    # OR (exc = exc.args[0])
                    if exc.args[0] == 400:
                        if (
                            exc.args[2]["type"]
                            == "urn:ietf:params:acme:error:accountDoesNotExist"
                        ):
                            log_api.debug(
                                ") authenticate | check failed. key is unknown to server"
                            )
                            event_payload_dict = utils.new_event_payload_dict()
                            event_payload_dict["acme_account.id"] = self.acmeAccount.id
                            event_payload_dict["acme_account.check"] = False
                            if self.log__OperationsEvent:
                                dbOperationsEvent = self.log__OperationsEvent(
                                    ctx,
                                    model_utils.OperationsEventType.from_string(
                                        "AcmeAccount__check"
                                    ),
                                    event_payload_dict,
                                )
                raise exc

            self._api_account_object = acme_account_object
            self._api_account_headers = acme_account_headers
            log_api.debug(
                ") authenticate | acme_account_object: %s" % acme_account_object
            )
            log_api.debug(
                ") authenticate | acme_account_headers: %s" % acme_account_headers
            )
            log_api.info(
                ") authenticate = %s"
                % (
                    "acme_v2 Registered!"
                    if status_code == 201
                    else "Already registered!"
                )
            )

            # this would raise if we couldn't authenticate
            self.acmeAccount.timestamp_last_authenticated = ctx.timestamp
            ctx.dbSession.flush(objects=[self.acmeAccount])

            # log this
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_account.id"] = self.acmeAccount.id
            if self.log__OperationsEvent:
                dbOperationsEvent = self.log__OperationsEvent(  # noqa: F841
                    ctx,
                    model_utils.OperationsEventType.from_string(
                        "AcmeAccount__authenticate"
                    ),
                    event_payload_dict,
                )
            return True
        except Exception as exc:  # noqa: F841
            raise

    def deactivate(
        self,
        ctx: "ApiContext",
        transaction_commit: Optional[bool] = None,
    ) -> Optional[bool]:
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance

        Deactivates the authenticated user against the Acme directory

        https://tools.ietf.org/html/rfc8555#section-7.3.6
        https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.3.7

            A client can deactivate an account by posting a signed update to the
            account URL with a status field of "deactivated".

                POST /acme/acct/evOfKhNU60wg HTTP/1.1
                Host: example.com
                Content-Type: application/jose+json

                {
                  "protected": base64url({
                    "alg": "ES256",
                    "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                    "nonce": "ntuJWWSic4WVNSqeUmshgg",
                    "url": "https://example.com/acme/acct/evOfKhNU60wg"
                  }),
                  "payload": base64url({
                    "status": "deactivated"
                  }),
                  "signature": "earzVLd3m5M4xJzR...bVTqn7R08AKOVf3Y"
                }

        https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.3.7
        """
        log_api.info("acme_v2.AuthenticatedUser.deactivate(")
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `AcmeLogger`"
            )

        if self.acme_directory is None:
            raise ValueError("`acme_directory` is required")

        assert self._api_account_headers
        _account_url = self._api_account_headers["Location"]
        if not _account_url:
            raise ValueError("Account URL unknown")

        is_did_deactivate = None
        try:
            _payload_deactivate = {"status": "deactivated"}
            (
                status_code,
                acme_account_object,
                acme_account_headers,
            ) = self._send_signed_request(
                "AccountUrl",
                _account_url,
                payload=_payload_deactivate,
            )
            if not isinstance(acme_account_object, dict):
                raise ValueError("expected `dict` response")

            # this is a flag
            is_did_deactivate = True

            log_api.debug(
                ") deactivate | acme_account_object: %s" % acme_account_object
            )
            log_api.debug(
                ") deactivate | acme_account_headers: %s" % acme_account_headers
            )
            log_api.info(
                ") deactivate = %s"
                % ("acme_v2 DEACTIVATED!" if status_code == 200 else "ERROR")
            )

            # this would raise if we couldn't authenticate
            db_update.update_AcmeAccount__set_deactivated(ctx, self.acmeAccount)
            ctx.dbSession.flush(objects=[self.acmeAccount])

            # log this
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_account.id"] = self.acmeAccount.id
            if self.log__OperationsEvent:
                dbOperationsEvent = self.log__OperationsEvent(  # noqa: F841
                    ctx,
                    model_utils.OperationsEventType.from_string(
                        "AcmeAccount__deactivate"
                    ),
                    event_payload_dict,
                )
        finally:
            return is_did_deactivate

    def key_change(
        self,
        ctx: "ApiContext",
        dbAcmeAccountKey_new: "AcmeAccountKey",
        transaction_commit: Optional[bool] = None,
    ) -> bool:
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAccountKey_new: (required) a :class:`model.objects.AcmeAccountKey` instance

        Performs a key change rollover

        https://tools.ietf.org/html/rfc8555#section-7.3.5
        https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.3.6


            POST /acme/key-change HTTP/1.1
            Host: example.com
            Content-Type: application/jose+json

            {
              "protected": base64url({
                "alg": "ES256",
                "kid": "https://example.com/acme/acct/1",
                "nonce": "K60BWPrMQG9SDxBDS_xtSw",
                "url": "https://example.com/acme/key-change"
              }),
              "payload": base64url({
                "protected": base64url({
                  "alg": "ES256",
                  "jwk": /* new key */,
                  "url": "https://example.com/acme/key-change"
                }),
                "payload": base64url({
                  "account": "https://example.com/acme/acct/1",
                  "oldKey": /* old key */
                }),
                "signature": "Xe8B94RD30Azj2ea...8BmZIRtcSKPSd8gU"
              }),
              "signature": "5TWiqIYQfIDfALQv...x9C2mg8JGPxl5bI4"
            }

        """
        log.info("acme_v2.AuthenticatedUser.key_change(")
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `AcmeLogger`"
            )

        if self.acme_directory is None:
            raise ValueError("`acme_directory` is required")

        if "keyChange" not in self.acme_directory:
            raise ValueError("directory does not support `keyChange`")

        assert self._api_account_headers
        _account_url = self._api_account_headers["Location"]
        if not _account_url:
            raise ValueError("Account URL unknown")

        is_did_keychange = False
        try:
            # quickref and toggle these, so we generate the correct payloads
            accountKeyData_old = self.accountKeyData
            accountKeyData_new = AccountKeyData(
                key_pem=dbAcmeAccountKey_new.key_pem,
            )

            _key_change_url = self.acme_directory["keyChange"]

            _payload_inner = {
                "account": _account_url,
                "oldKey": accountKeyData_old.jwk,
            }
            payload_inner = sign_payload_inner(
                url=_key_change_url,
                payload=_payload_inner,
                accountKeyData=accountKeyData_new,
            )

            (
                status_code,
                acme_response,
                acme_headers,
            ) = self._send_signed_request(
                "keyChange",
                _key_change_url,
                payload=payload_inner,
            )
            if not isinstance(acme_response, dict):
                raise ValueError("expected `dict` response")

            is_did_keychange = True

            log.debug(") key_change | acme_response: %s" % acme_response)
            log.debug(") key_change | acme_headers: %s" % acme_headers)

            # assuming things worked...
            self.accountKeyData = accountKeyData_new
            # turn off the old and flush, so the index is maintained
            dbAcmeAccountKey_old = self.acmeAccount.acme_account_key
            dbAcmeAccountKey_old.is_active = None
            dbAcmeAccountKey_old.timestamp_deactivated = ctx.timestamp
            dbAcmeAccountKey_old.key_deactivation_type_id = (
                model_utils.KeyDeactivationType.ACCOUNT_KEY_ROLLOVER
            )
            ctx.dbSession.flush(objects=[dbAcmeAccountKey_old])
            # turn on the new and flush
            self.acmeAccount.acme_account_key = dbAcmeAccountKey_new
            dbAcmeAccountKey_new.is_active = True
            ctx.dbSession.flush(
                objects=[
                    dbAcmeAccountKey_new,
                    self.acmeAccount,
                ]
            )

            # log this
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_account.id"] = self.acmeAccount.id
            event_payload_dict["acme_account_key-old.id"] = dbAcmeAccountKey_old.id
            event_payload_dict["acme_account_key-new.id"] = dbAcmeAccountKey_new.id
            if self.log__OperationsEvent:
                dbOperationsEvent = self.log__OperationsEvent(  # noqa: F841
                    ctx,
                    model_utils.OperationsEventType.from_string(
                        "AcmeAccount__key_change"
                    ),
                    event_payload_dict,
                )

        except Exception:
            raise

        finally:
            return is_did_keychange

    def acme_order_load(
        self,
        ctx: "ApiContext",
        dbAcmeOrder: "AcmeOrder",
        transaction_commit: Optional[bool] = None,
    ) -> Tuple:
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeOrder: (required) a :class:`model.objects.AcmeOrder` instance
        """
        log.info(
            "acme_v2.AuthenticatedUser.acme_order_load(AcmeOrder[%s]" % dbAcmeOrder.id
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `AcmeLogger`"
            )

        if not dbAcmeOrder.order_url:
            raise ValueError("the order does not have a `order_url`")

        try:
            (
                _status_code,
                acme_order_object,
                acme_order_headers,
            ) = self._send_signed_request("OrderUrl", dbAcmeOrder.order_url, None)
            if not isinstance(acme_order_object, dict):
                raise ValueError("expected `dict` response")
            log.debug(") acme_order_load | acme_order_object: %s" % acme_order_object)
            log.debug(") acme_order_load | acme_order_headers: %s" % acme_order_headers)
        except errors.AcmeServer404 as exc:  # noqa: F841
            log.info(") acme_order_load | ERROR AcmeServer404!")
            raise
        finally:
            # log the event to the db
            dbEventLogged = None
            assert ctx.application_settings
            if ctx.application_settings["log.acme"]:
                dbEventLogged = self.acmeLogger.log_order_load(
                    "v2", dbAcmeOrder, transaction_commit=transaction_commit
                )

        # this is just a convenience wrapper for our order object
        acmeOrderRfcObject = AcmeOrderRFC(
            rfc_object=acme_order_object,
            response_headers=acme_order_headers,
            dbUniqueFQDNSet=dbAcmeOrder.unique_fqdn_set,
        )

        return (acmeOrderRfcObject, dbEventLogged)

    def acme_order_new(
        self,
        ctx: "ApiContext",
        domain_names: List[str],
        dbUniqueFQDNSet: "UniqueFQDNSet",
        transaction_commit: bool,
        profile: Optional[str] = None,
        replaces: Optional[str] = None,
    ) -> Tuple[AcmeOrderRFC, Any]:
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param domain_names: (required) The domains for our order
        :param dbUniqueFQDNSet: (required) The :class:`model.objects.UniqueFQDNSet` associated with the order
        :param profile: (optional) an optional server profile
        :param replaces: (optional) an optional ARI identifier
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        returns
            acmeOrderRfcObject, dbEventLogged
        """
        log.info("acme_v2.AuthenticatedUser.acme_order_new(")
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `AcmeLogger`"
            )

        # Check to see if we are ratelimited
        if db_get.get__RateLimited__by__acmeAccountId(ctx, self.acmeAccount.id):
            raise errors.AcmeServerErrorExistingRatelimit("ACME Account")
        if db_get.get__RateLimited__by__acmeServerId(
            ctx, self.acmeAccount.acme_server_id, exclude_accounts=False
        ):
            raise errors.AcmeServerErrorExistingRatelimit("ACME Server")
        if db_get.get__RateLimited__by__acmeServerId_uniqueFqdnSetId(
            ctx, self.acmeAccount.acme_server_id, dbUniqueFQDNSet.id
        ):
            raise errors.AcmeServerErrorExistingRatelimit("ACME Server + Domain(s)")

        # the payload can have a dict or strings
        payload_order: AcmeOrderPayload = {
            "identifiers": [{"type": "dns", "value": d} for d in domain_names]
        }
        if profile is not None:
            payload_order["profile"] = profile
        if self.supports_ari and (replaces is not None):
            payload_order["replaces"] = replaces
        try:
            (
                _status_code,
                acme_order_object,
                acme_order_headers,
            ) = self._send_signed_request(
                "newOrder",
                self.acme_directory["newOrder"],
                payload=payload_order,
            )
            if not isinstance(acme_order_object, dict):
                raise ValueError("expected `dict` response")
            log.debug(") acme_order_new | acme_order_object: %s" % acme_order_object)
            log.debug(") acme_order_new | acme_order_headers: %s" % acme_order_headers)
        except errors.AcmeServerError as exc:
            log.debug(") acme_order_new | AcmeServerError: %s" % exc)

            # (status_code, url, resp_data, headers) = exc.args
            # OR (exc = exc.args[0])
            if exc.args[0] == 429:
                log.debug("Ratelimited Error")
                log.debug(exc.args)
                dbRateLimited = db_create.create__RateLimited(  # noqa: F841
                    ctx,
                    dbAcmeAccount=self.acmeAccount,
                    dbAcmeOrder=None,
                    dbAcmeServer=self.acmeAccount.acme_server,
                    dbUniqueFQDNSet=dbUniqueFQDNSet,
                    server_response_body=exc.args[2],
                    server_response_headers=exc.args[3],
                )
                ctx.pyramid_transaction_commit()
                raise

            # (status_code, url, resp_data, resp_headers) = exc
            _raise = True
            if isinstance(exc.args[2], dict):
                """
                Neither the ACME RFC, nor any extensions, standardize an invalid `replaces` field.
                Different ACME Servers will handle an invalid "replaces" field differently.

                    ACME Server
                        exc.args[2]["type"]
                        exc.args[2]["detail"]
                    ------------------------------
                    LetsEncrypt - Boulder
                        "urn:ietf:params:acme:error:malformed"
                        "parsing ARI CertID failed"
                    LetsEncrypt - Pebble
                        "urn:ietf:params:acme:error:serverInternal"
                        "could not find an order for the given certificate: could not find order resulting in the given certificate serial number"

                While these could be tested to ensure this error might be happening,
                the status quo across clients right now is to just try again:
                """
                if payload_order.get("replaces"):
                    # logging only
                    _type_details = {
                        "LetsEncrypt - Boulder": {
                            "type": "urn:ietf:params:acme:error:malformed",
                            "detail": "parsing ARI CertID failed",
                        },
                        "LetsEncrypt - Pebble": {
                            "type": "urn:ietf:params:acme:error:serverInternal",
                            "detail": "could not find an order for the given certificate: "
                            "could not find order resulting in the given certificate serial number",
                        },
                    }
                    for _server, _expects in _type_details.items():
                        if (exc.args[2]["type"] == _expects["type"]) and exc.args[2][
                            "detail"
                        ].startswith(_expects["detail"]):
                            # just log this, we will retry regardless
                            log.info("ARI `replaces` Probable Mismatch")
                            log.info("Server: %s", _server)
                            log.info("replaces: `%s`", replaces)
                            break
                    log.debug(") acme_order_new | retrying without `replaces`:")
                    del payload_order["replaces"]
                    (
                        _status_code,
                        acme_order_object,
                        acme_order_headers,
                    ) = self._send_signed_request(
                        "newOrder",
                        self.acme_directory["newOrder"],
                        payload=payload_order,
                    )
                    if not isinstance(acme_order_object, dict):
                        raise ValueError("expected `dict` response")
                    log.debug(
                        ") acme_order_new | acme_order_object: %s" % acme_order_object
                    )
                    log.debug(
                        ") acme_order_new | acme_order_headers: %s" % acme_order_headers
                    )
                    _raise = False
            if _raise:
                raise exc

        # log the event to the db
        dbEventLogged = None
        assert ctx.application_settings
        if ctx.application_settings.get("log.acme"):
            dbEventLogged = self.acmeLogger.log_newOrder(
                "v2", dbUniqueFQDNSet, transaction_commit=transaction_commit
            )

        if TYPE_CHECKING:
            assert isinstance(acme_order_object, dict)

        # this is just a convenience wrapper for our order object
        acmeOrderRfcObject = AcmeOrderRFC(
            rfc_object=acme_order_object,
            response_headers=acme_order_headers,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
        )

        return (acmeOrderRfcObject, dbEventLogged)

    def prepare_acme_challenge(
        self,
        ctx: "ApiContext",
        dbAcmeAuthorization: "AcmeAuthorization",
        dbAcmeChallenge: "AcmeChallenge",
        transaction_commit: Optional[bool] = None,
    ) -> bool:
        """
        This is a core routine to "prepare" an ACME Challenge for processing.

        This hook may consist of setting up the server(s) to respond to a
        challenge, testing the server(s) for the challenge, or both.

        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAuthorization: (required) The :class:`model.objects.dbAcmeAuthorization`
        :param dbAcmeChallenge: (required) The :class:`model.objects.dbAcmeChallenge`
        """
        log.info(
            "acme_v2.AuthenticatedUser.prepare_acme_challenge("
            "AcmeAuthorization[%s], AcmeChallenge[%s]"
            % (
                dbAcmeAuthorization.id if dbAcmeAuthorization else "",
                dbAcmeChallenge.id if dbAcmeChallenge else "",
            )
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "MUST persist external system data."
            )

        if dbAcmeChallenge.acme_challenge_type == "http-01":
            self._prepare_acme_challenge__http01(
                ctx,
                dbAcmeAuthorization=dbAcmeAuthorization,
                dbAcmeChallenge=dbAcmeChallenge,
                transaction_commit=transaction_commit,
            )
        elif dbAcmeChallenge.acme_challenge_type == "dns-01":
            self._prepare_acme_challenge__dns01(
                ctx,
                dbAcmeAuthorization=dbAcmeAuthorization,
                dbAcmeChallenge=dbAcmeChallenge,
                transaction_commit=transaction_commit,
            )
        # elif dbAcmeChallenge.acme_challenge_type == "tls-alpn-01":
        #    # TODO: tls-alpn-01
        #    raise NotImplementedError()
        else:
            raise NotImplementedError()

        return True

    def _prepare_acme_challenge__http01(
        self,
        ctx: "ApiContext",
        dbAcmeAuthorization: "AcmeAuthorization",
        dbAcmeChallenge: "AcmeChallenge",
        transaction_commit: Optional[bool] = None,
    ) -> None:
        """
        In the current design of PeterSSLers, no additional setup is
        required for a HTTP ACME Challenge, as the system can respond to the
        challenge natively.

        In earlier versions and from forked/inspired projects, this hook would
        be used to configure the server or file directories.

        This hook is currently used for testing.

        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAuthorization: (required) The :class:`model.objects.dbAcmeAuthorization`
        :param dbAcmeChallenge: (required) The :class:`model.objects.dbAcmeChallenge`
        """
        log.info(
            "acme_v2.AuthenticatedUser._prepare_acme_challenge__http01("
            "AcmeAuthorization[%s], AcmeChallenge[%s]"
            % (
                dbAcmeAuthorization.id if dbAcmeAuthorization else "",
                dbAcmeChallenge.id if dbAcmeChallenge else "",
            )
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "MUST persist external system data."
            )
        # acme_challenge_response
        assert dbAcmeChallenge.token
        keyauthorization = create_challenge_keyauthorization(
            dbAcmeChallenge.token,
            self.accountKeyData,
        )
        if dbAcmeChallenge.keyauthorization != keyauthorization:
            raise ValueError("This should never happen!")

        # update the db; this should be integrated with the above
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(
            dbAcmeAuthorization.domain.domain_name,
            dbAcmeChallenge.token,
        )

        # note: preflight / precheck : http01
        # check that the file is in place
        try:
            assert ctx.request
            assert ctx.application_settings
            if ctx.application_settings["precheck_acme_challenges"] and (
                "http-01" in ctx.application_settings["precheck_acme_challenges"]
            ):
                log.debug(
                    "precheck_acme_challenges[http-01] | ensuring the challenge is readable"
                )
                try:
                    resp = requests.get(wellknown_url)
                    resp_data = resp.content.decode("utf-8").strip()
                    assert resp_data == keyauthorization
                except (IOError, AssertionError):
                    if ctx.application_settings["log.acme"]:
                        self.acmeLogger.log_challenge_error(
                            "v2",
                            dbAcmeChallenge,
                            "precheck-1",
                            transaction_commit=True,
                        )
                    if DEBUG_CHALLENGES_MANUAL:
                        print("DEBUG_CHALLENGES_MANUAL=True")
                        print("precheck failure, HTTP-01", wellknown_url)
                        pdb.set_trace()
                    raise errors.DomainVerificationError(
                        "Precheck Failure: Hosting keyauth challenge, but couldn't download {0}".format(
                            wellknown_url
                        )
                    )
            else:
                log.debug("no precheck configured for http-01")
        except (AssertionError, ValueError) as exc:
            log.critical(
                "precheck_acme_challenges[http-01] | FAILED (%s) %s"
                % (wellknown_url, exc)
            )
            raise errors.DomainVerificationError(
                "couldn't download `{0}`: {1}".format(wellknown_url, exc)
            )
        except Exception as exc:
            log.critical(
                "precheck_acme_challenges[http-01] | FAILED GENERIC (%s) %s"
                % (wellknown_url, exc)
            )
            raise errors.DomainVerificationError(
                "couldn't download `{0}`: {1}".format(wellknown_url, exc)
            )

    def _prepare_acme_challenge__dns01(
        self,
        ctx: "ApiContext",
        dbAcmeAuthorization: "AcmeAuthorization",
        dbAcmeChallenge: "AcmeChallenge",
        transaction_commit: Optional[bool] = None,
    ) -> None:
        """
        Prepares a DNS-01 ACME Challenge by updating the acme-dns server for
        the domain belonging to the challenge

        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAuthorization: (required) The :class:`model.objects.dbAcmeAuthorization`
        :param dbAcmeChallenge: (required) The :class:`model.objects.dbAcmeChallenge`
        """
        log.info(
            "acme_v2.AuthenticatedUser._prepare_acme_challenge__dns01("
            "AcmeAuthorization[%s], AcmeChallenge[%s]"
            % (
                dbAcmeAuthorization.id if dbAcmeAuthorization else "",
                dbAcmeChallenge.id if dbAcmeChallenge else "",
            )
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "MUST persist external system data."
            )

        # TODO: test the integration
        if lib_acmedns.pyacmedns is None:
            raise ValueError("`pyacmedns` is not installed")

        dbAcmeDnsServerAccount = (
            dbAcmeAuthorization.domain.acme_dns_server_account__active
        )
        if not dbAcmeDnsServerAccount:
            raise ValueError(
                "no active AcmeDnsServerAccount for domain: %s"
                % dbAcmeAuthorization.domain.domain_name
            )

        # acme_challenge_response
        assert dbAcmeChallenge.token
        keyauthorization = create_challenge_keyauthorization(
            dbAcmeChallenge.token,
            self.accountKeyData,
        )
        if dbAcmeChallenge.keyauthorization != keyauthorization:
            raise ValueError("This should never happen!")

        dns_keyauthorization = create_dns01_keyauthorization(keyauthorization)
        # "_acme-challenge.%s."
        dns_record_prime = dbAcmeAuthorization.domain.acme_challenge_domain_name
        expected_record_name = dbAcmeDnsServerAccount.pyacmedns_dict["fulldomain"]

        try:
            # initialize a client
            acmeDnsClient = lib_acmedns.new_client(
                dbAcmeDnsServerAccount.acme_dns_server.api_url
            )

            # update the acmedns server
            acmeDnsClient.update_txt_record(
                dbAcmeDnsServerAccount.pyacmedns_dict, dns_keyauthorization
            )

        except Exception as exc:
            # ???: should be this `errors.AcmeDnsServerError`
            raise errors.DomainVerificationError(str(exc))

        # note: preflight / precheck : dns-01
        # check that the file is in place
        try:
            assert ctx.request
            assert ctx.application_settings
            if ctx.application_settings["precheck_acme_challenges"] and (
                "dns-01" in ctx.application_settings["precheck_acme_challenges"]
            ):
                log.debug(
                    "precheck_acme_challenges[dns-01] | ensuring the challenge is readable"
                )
                try:
                    # check the first domain value
                    # an easy mistake is a TXT not CNAME, so check that first
                    record_txt = utils_dns.get_records(
                        dns_record_prime, record_type="TXT"
                    )
                    if record_txt:
                        raise errors.DomainVerificationError(
                            "Found TXT record, not CNAME on `{0}`".format(
                                dns_record_prime
                            )
                        )
                    # check the CNAME
                    record_cname = utils_dns.get_records(
                        dns_record_prime, record_type="CNAME"
                    )
                    if not record_cname:
                        raise errors.DomainVerificationError(
                            "Did not find any CNAME on `{0}`".format(dns_record_prime)
                        )
                    found = False
                    for _cname in record_cname:
                        _candidate = _cname[:-1]
                        if _candidate == expected_record_name:
                            found = True
                            break
                    if not found:
                        raise errors.DomainVerificationError(
                            "Did not find valid CNAME on `{0}`".format(dns_record_prime)
                        )
                    # if we have a CNAME, check that acme-dns is updated correctly
                    cnamed_txts = utils_dns.get_records(
                        expected_record_name, record_type="TXT"
                    )
                    if not cnamed_txts:
                        raise errors.DomainVerificationError(
                            "Did not find any TXT on `{0}`".format(expected_record_name)
                        )
                    found = False
                    for _txt in cnamed_txts:
                        if _txt == dns_keyauthorization:
                            found = True
                            break
                    if not found:
                        raise errors.DomainVerificationError(
                            "Did not find valid TXT on `{0}`".format(
                                expected_record_name
                            )
                        )

                except errors.DomainVerificationError as exc:
                    if ctx.application_settings["log.acme"]:
                        self.acmeLogger.log_challenge_error(
                            "v2",
                            dbAcmeChallenge,
                            "precheck-1",
                            transaction_commit=True,
                        )
                    if DEBUG_CHALLENGES_MANUAL:
                        print("DEBUG_CHALLENGES_MANUAL=True")
                        print(
                            "precheck failure, DNS-01",
                            dns_record_prime,
                            expected_record_name,
                        )
                        print(exc.args)
                        pdb.set_trace()
                    raise exc
            else:
                log.debug("no precheck configured for dns-01")
        except (AssertionError, ValueError) as exc:
            log.critical(
                "precheck_acme_challenges[dns-01] | FAILED (%s) %s"
                % (dns_record_prime, exc)
            )
            raise errors.DomainVerificationError(
                "couldn't resolve {0}: {1}".format(dns_record_prime, exc)
            )
        except Exception as exc:
            log.critical(
                "precheck_acme_challenges[dns-01] | FAILED GENERIC (%s) %s"
                % (dns_record_prime, exc)
            )
            raise errors.DomainVerificationError(
                "couldn't resolve {0}: {1}".format(dns_record_prime, exc)
            )

    def acme_order_process_authorizations(
        self,
        ctx: "ApiContext",
        acmeOrderRfcObject: "AcmeOrderRFC",
        dbAcmeOrder: "AcmeOrder",
        handle_authorization_payload: Callable,
        update_AcmeAuthorization_status: Callable,
        update_AcmeChallenge_status: Callable,
        updated_AcmeOrder_ProcessingStatus: Callable,
        transaction_commit: Optional[bool] = None,
    ) -> bool:
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param acmeOrderRfcObject: (required) A :class:`AcmeOrderRFC` object representing the server's response
        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the order

        :param handle_authorization_payload: (required) Callable function. expects (authorization_url, authorization_response, dbAcmeAuthorization=?, transaction_commit=?)
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        :param update_AcmeAuthorization_status: callable. expects (ctx, dbAcmeAuthorization, status_text, transaction_commit)
        :param update_AcmeChallenge_status: callable. expects (ctx, dbAcmeChallenge, status_text, transaction_commit)
        :param updated_AcmeOrder_ProcessingStatus: callable. expects (ctx, dbAcmeChallenge, acme_order_processing_status_id, transaction_commit)

        """
        log.info(
            "acme_v2.AuthenticatedUser.acme_order_process_authorizations(AcmeOrder[%s]"
            % dbAcmeOrder.id
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "MUST persist external system data."
            )

        _order_status = acmeOrderRfcObject.rfc_object["status"]
        if _order_status != "pending":
            if _order_status == "invalid":
                raise ValueError("this order is dead")
            else:
                raise ValueError(
                    "unsure how to handle this `status``: `%s`" % _order_status
                )

        if (
            dbAcmeOrder.acme_order_processing_status_id
            != model_utils.AcmeOrder_ProcessingStatus.created_acme
        ):
            raise ValueError(
                "unsure how to the `acme_order_processing_status_id` was wedged: `%s`"
                % dbAcmeOrder.acme_order_processing_status_id
            )
        updated_AcmeOrder_ProcessingStatus(
            ctx,
            dbAcmeOrder,
            acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.processing_started,
            transaction_commit=transaction_commit,
        )

        # verify each domain
        domains_challenged = dbAcmeOrder.domains_challenged
        for authorization_url in acmeOrderRfcObject.rfc_object["authorizations"]:
            auth_result = self.acme_authorization_process_url(  # noqa: F841
                ctx,
                authorization_url,
                handle_authorization_payload=handle_authorization_payload,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
                updated_AcmeOrder_ProcessingStatus=updated_AcmeOrder_ProcessingStatus,
                dbAcmeAuthorization=None,  # ???: should we have this?
                acme_challenge_type_id__preferred=None,
                domains_challenged=domains_challenged,
                transaction_commit=transaction_commit,
            )

        if (
            dbAcmeOrder.acme_order_processing_status_id
            == model_utils.AcmeOrder_ProcessingStatus.created_acme
        ):
            dbAcmeOrder.acme_order_processing_status_id == model_utils.AcmeOrder_ProcessingStatus.processing_started

        # no more domains!
        return True

    def acme_order_finalize(
        self,
        ctx: "ApiContext",
        dbAcmeOrder: "AcmeOrder",
        update_order_status: Callable,
        csr_pem: str,
        transaction_commit: Optional[bool] = None,
    ) -> Tuple[Dict, List[str]]:
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the order
        :param update_order_status: (required) Callable function. expects (ctx, dbAcmeOrder, acme_rfc_object, transaction_commit)
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        :param csr_pem: (required) The CertitificateSigningRequest as PEM

        :returns: a tuple in the form of
            `FinalizeResponse, FullchainPems`
            `Dict, List[str]`

        # get the new certificate
        """
        log.info(
            "acme_v2.AuthenticatedUser.acme_order_finalize(AcmeOrder[%s]"
            % dbAcmeOrder.id
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `update_order_status` callable"
            )

        if update_order_status is None:
            raise ValueError(
                "we must invoke this with a callable `update_order_status`"
            )

        assert dbAcmeOrder.finalize_url
        assert dbAcmeOrder.order_url

        # convert the certificate to a DER
        csr_der = cert_utils.convert_pem_to_der(csr_pem)

        # log this to the db
        assert ctx.application_settings
        if ctx.application_settings["log.acme"]:
            acmeLoggedEvent = self.acmeLogger.log_order_finalize(  # noqa: F841
                "v2", transaction_commit=True
            )

        payload_finalize = {"csr": cert_utils.jose_b64(csr_der)}
        try:
            (
                _status_code,
                finalize_response,
                _finalize_headers,
            ) = self._send_signed_request(
                "OrderUrl",
                dbAcmeOrder.finalize_url,
                payload=payload_finalize,
            )
            if not isinstance(finalize_response, dict):
                raise ValueError("expected `dict` response")
            log.debug(
                ") acme_order_finalize | finalize_response: %s" % finalize_response
            )
            log.debug(
                ") acme_order_finalize | _finalize_headers: %s" % _finalize_headers
            )
        except errors.AcmeServer404 as exc:  # noqa: F841
            finalize_response = new_response_404()
            raise

        # poll the order to monitor when it's done
        url_order_status = dbAcmeOrder.order_url

        log.info(") acme_order_finalize | checking order {0}".format("order"))
        try:
            acme_order_finalized = self._poll_until_not(
                "OrderUrl",
                url_order_status,
                ["pending", "processing"],
                "via acme_v2.AuthenticatedUser.acme_order_finalize()",
            )
        except errors.AcmePollingTooLong as exc:
            log.debug(exc)
            _tdelta, _result = exc.args
            dbPollingError = db_create.create__AcmePollingError(  # noqa: F841
                ctx,
                acme_polling_error_endpoint_id=model_utils.AcmePollingErrorEndpoint.ACME_ORDER_FINALIZE,
                acme_order_id=dbAcmeOrder.id,
                response=_result,
            )
            ctx.pyramid_transaction_commit()
            raise

        if acme_order_finalized["status"] != "valid":
            raise errors.AcmeCommunicationError(
                "Order failed: {0}".format(acme_order_finalized)
            )

        # acme_order_finalized["status"] == "valid"
        update_order_status(
            ctx,
            dbAcmeOrder,
            acme_order_finalized,
            acme_order_processing_status_id=model_utils.AcmeOrder_ProcessingStatus.order_finalized,
            transaction_commit=transaction_commit,
        )

        # TODO: should we ensure every Authorization is already tracked?

        url_certificate = acme_order_finalized.get("certificate")
        if not url_certificate:
            raise ValueError(
                "The AcmeOrder server response should have a `certificate`."
            )
        fullchain_pems = self.download_certificate(
            url_certificate,
            is_save_alternate_chains=dbAcmeOrder.is_save_alternate_chains,
        )
        return (acme_order_finalized, fullchain_pems)

    def download_certificate(
        self,
        url_certificate: str,
        is_save_alternate_chains: Optional[bool] = None,
    ) -> List[str]:
        log.info("acme_v2.AuthenticatedUser.download_certificate(")
        if not url_certificate:
            raise ValueError("Must supply a url for the certificate")

        # download the certificate
        # ACME-V2 furnishes a FULLCHAIN (certificate_pem + chain_pem)
        (_status_code, _fullchain_pem, _certificate_headers) = (
            self._send_signed_request("CertificateUrl", url_certificate, None)
        )
        if not isinstance(_fullchain_pem, str):
            raise ValueError("expected `str` response")
        log.debug(") download_certificate | fullchain_pem: %s" % _fullchain_pem)
        log.debug(
            ") download_certificate | _certificate_headers: %s" % _certificate_headers
        )
        fullchain_pems = [
            _fullchain_pem,
        ]
        if is_save_alternate_chains:
            alt_chains_urls = get_header_links(_certificate_headers, "alternate")
            alt_chains = []
            for url in alt_chains_urls:
                # wrap these in a try/except so a single failure doesn't kill the download
                try:
                    _pem = self._send_signed_request("CertificateUrl", url)[1]
                    if not isinstance(_pem, str):
                        raise ValueError("expected `str` response")
                    if TYPE_CHECKING:
                        assert isinstance(_pem, str)
                    alt_chains.append(_pem)
                except Exception:
                    log.error("Error downloading ALT chain.")
                    log.error("    url_certificate: %s" % url_certificate)
                    log.error("    alt_chains_url: %s" % url)
                    pass
            fullchain_pems.extend(alt_chains)
        log.info(") download_certificate | downloaded signed certificate!")
        return fullchain_pems

    def acme_authorization_process_url(
        self,
        ctx: "ApiContext",
        authorization_url: str,
        handle_authorization_payload: Callable,
        update_AcmeAuthorization_status: Callable,
        update_AcmeChallenge_status: Callable,
        updated_AcmeOrder_ProcessingStatus: Callable,
        dbAcmeAuthorization: Optional["AcmeAuthorization"] = None,
        acme_challenge_type_id__preferred: Optional[int] = None,
        domains_challenged: Optional["DomainsChallenged"] = None,
        transaction_commit: Optional[bool] = None,
    ) -> Optional[bool]:
        """
        Process a single Authorization URL

        * fetch the URL, construct a `model.objects.AcmeAuthorization` if needed;
          update otherwise
        * complete ACME Challenge if possible

        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param authorization_url: (required) The url of the authorization
        :param acme_challenge_type_id__preferred: An `int` representing a :class:`model.utils.AcmeChallengeType` challenge; `domains_challenged`
        :param domains_challenged: An instance of
            :class:`model.utils.DomainsChallenged` that can indicate which
            challenge is preferred; or `acme_challenge_type_id__preferred`
        :param handle_authorization_payload: (required) Callable function.
            expects ``(authorization_url, authorization_response,
            dbAcmeAuthorization=?, transaction_commit=?)``
        :param update_AcmeAuthorization_status: callable. expects ``(ctx,
            dbAcmeAuthorization, status_text, transaction_commit)``
        :param update_AcmeChallenge_status: callable. expects ``(ctx,
            dbAcmeChallenge, status_text, transaction_commit)``
        :param updated_AcmeOrder_ProcessingStatus: callable. expects ``(ctx,
            dbAcmeChallenge, acme_order_processing_status_id, transaction_commit)``
        :param dbAcmeAuthorization: A :class:`model.objects.AcmeAuthorization`
            instance
        :param transaction_commit: (required) Boolean. Must indicate that we
            will invoke this outside of transactions

        Returns:

            True: Authorization need, challenge performed and Valid
            False: No Authorization Action needed
            None: Authorization Action needed, but no Action taken

        If the challenge fails, we raise a `errors.DomainVerificationError`.
        """
        log.info("acme_v2.AuthenticatedUser.acme_authorization_process_url(")
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "MUST persist external system data."
            )

        if all((acme_challenge_type_id__preferred, domains_challenged)) or not any(
            (acme_challenge_type_id__preferred, domains_challenged)
        ):
            raise ValueError(
                "only submit one of acme_challenge_type_id__preferred, domains_challenged"
            )
        if acme_challenge_type_id__preferred:
            if (
                acme_challenge_type_id__preferred
                not in model_utils.AcmeChallengeType._mapping
            ):
                raise ValueError("invalid `acme_challenge_type_id__preferred`")

        # scoping, our task list
        _task__complete_challenge = None

        # in v1, we know the domain before the authorization request
        # in v2, we must query an order's authorization url to get the domain
        (
            _status_code,
            authorization_response,
            _authorization_headers,
        ) = self._send_signed_request(
            "AuthzUrl",
            authorization_url,
            payload=None,
        )
        if not isinstance(authorization_response, dict):
            raise ValueError("expected `dict` response")
        log.debug(
            ") acme_authorization_process_url | authorization_response: %s"
            % authorization_response
        )
        log.debug(
            ") acme_authorization_process_url | _authorization_headers: %s"
            % _authorization_headers
        )
        log.info(
            ") .acme_authorization_process_url | handle_authorization_payload(AcmeAuthorization[%s]"
            % (dbAcmeAuthorization.id if dbAcmeAuthorization else "")
        )

        _dbAcmeAuthorization = handle_authorization_payload(
            authorization_url,
            authorization_response,
            dbAcmeAuthorization=dbAcmeAuthorization,
            transaction_commit=True,
        )
        log.info(") handle_authorization_payload")

        # log the event
        assert ctx.application_settings
        if ctx.application_settings["log.acme"]:
            dbAcmeEventLog_authorization_fetch = (  # noqa: F841
                self.acmeLogger.log_authorization_request(
                    "v2",
                    dbAcmeAuthorization=_dbAcmeAuthorization,
                    transaction_commit=True,
                )
            )

        _response_domain = authorization_response["identifier"]["value"]
        if _dbAcmeAuthorization.domain.domain_name != _response_domain:
            raise ValueError("mismatch on a domain name")

        if not acme_challenge_type_id__preferred:
            assert domains_challenged
            acme_challenge_type_id__preferred = (
                domains_challenged.domain_to_challenge_type_id(_response_domain)
            )

        # once we inspect the url, we have the domain
        # the domain is in our `authorization_response`
        # but also on our `dbAcmeAuthorization` object
        log.info(
            ") acme_authorization_process_url | Handling Authorization for {0}...".format(
                _dbAcmeAuthorization.domain.domain_name
            )
        )

        _authorization_status = authorization_response["status"]
        if _authorization_status == "pending":
            # we need to run the authorization
            pass
        elif _authorization_status == "valid":
            # noting to do, one or more challenges is valid
            return False
        elif _authorization_status == "invalid":
            # this failed once, we need to auth again !
            raise errors.AcmeOrderFatal("AcmeAuthorization already `invalid`")
        elif _authorization_status == "deactivated":
            # this has been removed from the order?
            raise errors.AcmeOrderFatal("AcmeAuthorization already `deactivated`")
        elif _authorization_status == "expired":
            # this passed once, BUT we need to auth again
            raise errors.AcmeOrderFatal("AcmeAuthorization already `expired`")
        elif _authorization_status == "revoked":
            # this failed once, we need to auth again?
            raise errors.AcmeOrderFatal("AcmeAuthorization already `revoked`")
        else:
            raise ValueError(
                "unexpected authorization status: `%s`" % _authorization_status
            )

        # we could parse the challenge
        # however, the call to `process_discovered_auth`
        # should have updated the challenge object already
        acme_challenges = get_authorization_challenges(
            authorization_response,
            required_challenges=[
                "http-01",
            ],
        )
        _acme_challenge_type = model_utils.AcmeChallengeType._mapping[
            acme_challenge_type_id__preferred
        ]
        _acme_challenge_selected = filter_specific_challenge(
            acme_challenges, _acme_challenge_type
        )

        dbAcmeChallenge = None
        if _acme_challenge_type == "http-01":
            dbAcmeChallenge = _dbAcmeAuthorization.acme_challenge_http_01
        elif _acme_challenge_type == "dns-01":
            dbAcmeChallenge = _dbAcmeAuthorization.acme_challenge_dns_01
        elif _acme_challenge_type == "tls-alpn-01":
            dbAcmeChallenge = _dbAcmeAuthorization.acme_challenge_tls_alpn_01
        if not dbAcmeChallenge:
            raise ValueError("error loading AcmeChallenge. this is unexpected.")

        if _acme_challenge_selected["url"] != dbAcmeChallenge.challenge_url:
            raise ValueError(
                "`acme_challenges` has a different challenge_url. this is unexpected."
            )

        _challenge_status_text = dbAcmeChallenge.acme_status_challenge
        if _challenge_status_text == "*discovered*":
            # internal marker, pre "pending"
            _task__complete_challenge = True
        elif _challenge_status_text == "pending":
            _task__complete_challenge = True
        elif _challenge_status_text == "processing":
            # we may need to trigger again?
            _task__complete_challenge = True
        elif _challenge_status_text == "valid":
            # already completed
            _task__complete_challenge = False
        elif _challenge_status_text == "invalid":
            # we may need to trigger again?
            _task__complete_challenge = True
        else:
            raise ValueError(
                "unexpected challenge status: `%s`" % _challenge_status_text
            )

        if _task__complete_challenge:
            self.prepare_acme_challenge(
                ctx,
                dbAcmeAuthorization=_dbAcmeAuthorization,
                dbAcmeChallenge=dbAcmeChallenge,
                transaction_commit=transaction_commit,
            )
            self.acme_challenge_trigger(
                ctx,
                dbAcmeChallenge=dbAcmeChallenge,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
                transaction_commit=transaction_commit,
            )
            return True
        return None

    def acme_authorization_load(
        self,
        ctx: "ApiContext",
        dbAcmeAuthorization: "AcmeAuthorization",
        transaction_commit: Optional[bool] = None,
    ) -> Tuple:
        """
        This loads the authorization object and pulls the payload
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAuthorization: (required) a
            :class:`model.objects.AcmeAuthorization` instance
        """
        log.info(
            "acme_v2.AuthenticatedUser.acme_authorization_load(AcmeAuthorization[%s]"
            % dbAcmeAuthorization.id
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `AcmeLogger`"
            )

        if not dbAcmeAuthorization.authorization_url:
            raise ValueError(
                "the `AcmeAuthorization` does not have an `authorization_url`"
            )

        try:
            (
                _status_code,
                authorization_response,
                _authorization_headers,
            ) = self._send_signed_request(
                "AuthzUrl", dbAcmeAuthorization.authorization_url, None
            )
            if not isinstance(authorization_response, dict):
                raise ValueError("expected `dict` response")
            log.debug(
                ") acme_authorization_load | authorization_response: %s"
                % authorization_response
            )
            log.debug(
                ") acme_authorization_load | _authorization_headers: %s"
                % _authorization_headers
            )
        except errors.AcmeServer404 as exc:  # noqa: F841
            authorization_response = new_response_404()

        # log the event
        dbAcmeEventLog_authorization_fetch = None
        assert ctx.application_settings
        if ctx.application_settings["log.acme"]:
            dbAcmeEventLog_authorization_fetch = (
                self.acmeLogger.log_authorization_request(
                    "v2",
                    dbAcmeAuthorization=dbAcmeAuthorization,
                    transaction_commit=True,
                )
            )  # log this to the db

        return (authorization_response, dbAcmeEventLog_authorization_fetch)

    def acme_authorization_deactivate(
        self,
        ctx: "ApiContext",
        dbAcmeAuthorization: "AcmeAuthorization",
        transaction_commit: Optional[bool] = None,
    ) -> Tuple:
        """
        This loads the authorization object and pulls the payload
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAuthorization: (required)
            a :class:`model.objects.AcmeAuthorization` instance

        https://tools.ietf.org/html/rfc8555#section-7.5.2

            7.5.2.  Deactivating an Authorization

               If a client wishes to relinquish its authorization to issue
               certificates for an identifier, then it may request that the server
               deactivate each authorization associated with it by sending POST
               requests with the static object {"status": "deactivated"} to each
               authorization URL.

        """
        log.info(
            "acme_v2.AuthenticatedUser.acme_authorization_deactivate(AcmeAuthorization[%s]"
            % dbAcmeAuthorization.id
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `AcmeLogger`"
            )

        if not dbAcmeAuthorization.authorization_url:
            raise ValueError(
                "the `AcmeAuthorization` does not have an `authorization_url`"
            )

        try:
            (
                _status_code,
                authorization_response,
                _authorization_headers,
            ) = self._send_signed_request(
                "AuthzUrl",
                dbAcmeAuthorization.authorization_url,
                {"status": "deactivated"},
            )
            if not isinstance(authorization_response, dict):
                raise ValueError("expected `dict` response")
            log.debug(
                ") acme_authorization_deactivate | authorization_response: %s"
                % authorization_response
            )
            log.debug(
                ") acme_authorization_deactivate | _authorization_headers: %s"
                % _authorization_headers
            )
        except errors.AcmeServer404 as exc:  # noqa: F841
            authorization_response = new_response_404()

        # log the event
        dbAcmeEventLog_authorization_fetch = None
        assert ctx.application_settings
        if ctx.application_settings["log.acme"]:
            dbAcmeEventLog_authorization_fetch = (
                self.acmeLogger.log_authorization_deactivate(
                    "v2",
                    dbAcmeAuthorization=dbAcmeAuthorization,
                    transaction_commit=True,
                )
            )  # log this to the db

        return (authorization_response, dbAcmeEventLog_authorization_fetch)

    def acme_challenge_load(
        self,
        ctx: "ApiContext",
        dbAcmeChallenge: "AcmeChallenge",
        transaction_commit: Optional[bool] = None,
    ) -> Tuple:
        """
        This loads the authorization object and pulls the payload
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeChallenge: (required) a :class:`model.objects.AcmeChallenge` instance
        """
        log.info(
            "acme_v2.AuthenticatedUser.acme_challenge_load(AcmeChallenge[%s]"
            % dbAcmeChallenge.id
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `AcmeLogger`"
            )

        if not dbAcmeChallenge.challenge_url:
            raise ValueError("the challenge does not have a `challenge_url`")

        try:
            (
                _status_code,
                challenge_response,
                _challenge_headers,
            ) = self._send_signed_request(
                "ChallengeUrl", dbAcmeChallenge.challenge_url, None
            )
            if not isinstance(challenge_response, dict):
                raise ValueError("expected `dict` response")
            log.debug(
                ") acme_challenge_load | challenge_response: %s" % challenge_response
            )
            log.debug(
                ") acme_challenge_load | _challenge_headers: %s" % _challenge_headers
            )
        except errors.AcmeServer404 as exc:  # noqa: F841
            challenge_response = new_response_404()

        # log the event
        dbAcmeEventLog_challenge_fetch = None
        assert ctx.application_settings
        if ctx.application_settings["log.acme"]:
            dbAcmeEventLog_challenge_fetch = self.acmeLogger.log_challenge_PostAsGet(
                "v2",
                dbAcmeChallenge=dbAcmeChallenge,
                transaction_commit=True,
            )  # log this to the db

        return (challenge_response, dbAcmeEventLog_challenge_fetch)

    def acme_challenge_trigger(
        self,
        ctx: "ApiContext",
        dbAcmeChallenge: "AcmeChallenge",
        update_AcmeAuthorization_status: Callable,
        update_AcmeChallenge_status: Callable,
        transaction_commit: Optional[bool] = None,
    ) -> Dict:
        """
        This triggers the challenge object

        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeChallenge: (required) a
            :class:`model.objects.AcmeChallenge` instance
        :param dbAcmeAuthorization: (required) a
            :class:`model.objects.AcmeAuthorization` instance
        :param update_AcmeAuthorization_status: callable. expects ``(ctx,
            dbAcmeAuthorization, status_text, transaction_commit)``
        :param update_AcmeChallenge_status: callable. expects ``(ctx,
            dbAcmeChallenge, status_text, transaction_commit)``

        returns `challenge_response` the ACME paylaod for the specific challenge
        """
        log.info(
            "acme_v2.AuthenticatedUser.acme_challenge_trigger(AcmeChallenge[%s]"
            % dbAcmeChallenge.id
        )
        if not transaction_commit:
            raise errors.AcknowledgeTransactionCommitRequired(
                "required for the `AcmeLogger`"
            )

        assert dbAcmeChallenge.acme_challenge_type
        assert dbAcmeChallenge.challenge_url

        dbAcmeAuthorization = dbAcmeChallenge.acme_authorization
        acme_challenge_type = dbAcmeChallenge.acme_challenge_type

        # handle this in a loop, so we can retry

        # trigger the challenge!
        # if we had a 'valid' challenge, the payload would be `None`
        # to invoke a GET-as-POST functionality and load the challenge resource
        # POSTing an empty `dict` will trigger the challenge

        # note that we are about to trigger the challenge:
        assert ctx.application_settings
        if ctx.application_settings["log.acme"]:
            self.acmeLogger.log_challenge_trigger(
                "v2",
                dbAcmeChallenge,
                transaction_commit=True,
            )
        try:
            (
                _status_code,
                challenge_response,
                _challenge_headers,
            ) = self._send_signed_request(
                "ChallengeUrl",
                dbAcmeChallenge.challenge_url,
                payload={},  # `{}` will trigger; `None` will poll
            )
            if not isinstance(challenge_response, dict):
                raise ValueError("expected `dict` response")
            log.debug(
                ") acme_challenge_trigger | challenge_response: %s" % challenge_response
            )
            log.debug(
                ") acme_challenge_trigger | _challenge_headers: %s" % _challenge_headers
            )
        except errors.AcmeServer404 as exc:  # noqa: F841
            # this is a subclass of `errors.AcmeServerError`, but does not have all the args
            raise

        except errors.AcmeServerError as exc:
            # (status_code, url, resp_data, headers) = exc.args
            (_status_code, _url, _resp, _headers) = exc.args
            """
            if isinstance(_resp, dict):
                if _resp["type"].startswith("urn:ietf:params:acme:error:"):
                    # {u'status': 400, u'type': u'urn:ietf:params:acme:error:malformed', u'detail': u'Authorization expired 2020-02-28T20:25:02Z'}
                    # {'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'Cannot update challenge with status valid, only status pending', 'status': 400},
                    # can this be caught?
            """
            raise
        if challenge_response["status"] == "processing":
            # we're going to have to poll for changes, so give this a few seconds
            time.sleep(3)
        elif challenge_response["status"] not in ("pending", "valid"):
            # this should ALMOST ALWAYS be "pending" as we just requested it
            # this could possibly be "valid" due to cached authorizations
            # on a test environment, the `Pebble` server might instantly transition from "pending" to "valid"

            raise ValueError(
                "AcmeChallenge is not 'pending' or 'valid' on the ACME server; received `%s`"
                % challenge_response["status"]
            )

            # perhaps we should do a:
            # raise errors.AcmeAuthorizationFailure(
            #     "{0} challenge did not pass: {1}".format(
            #         dbAcmeChallenge.acme_authorization.domain.domain_name,
            #         authorization_response,
            #     )
            # )

        # TODO: COULD an accepted challenge be here?
        log.info(
            ") acme_challenge_trigger | checking domain {0}".format(
                dbAcmeAuthorization.domain.domain_name
            )
        )

        """
        There are two options for polling now:

        Option A-
            Poll the `dbAcmeChallenge.challenge_url`
            This will result in payload like this:

                {u'error': {u'detail': u'Get http://a.example.com:5002/.well-known/acme-challenge/zDavaMNbJugELFM5VIXqAaYQBcloPVtoWdqQXHgPn0U: error occurred while resolving URL "http://a.example.com:5002/.well-known/acme-challenge/zDavaMNbJugELFM5VIXqAaYQBcloPVtoWdqQXHgPn0U": "lookup a.example.com: no such host"',
                            u'status': 400,
                            u'type': u'urn:ietf:params:acme:error:connection'},
                 u'status': u'invalid',
                 u'token': u'zDavaMNbJugELFM5VIXqAaYQBcloPVtoWdqQXHgPn0U',
                 u'type': u'http-01',
                 u'url': u'https://127.0.0.1:14000/chalZ/skh_Vm2Jm1lpNi0WlQFMwCvddb0jN5vYOBwocgqwtDY',
                 u'validated': u'2020-02-28T20:14:56Z'}

        Option B-
            Poll the `dbAcmeChallenge.acme_authorization.authorization_url`
            This will result in payload like this:

                {u'challenges': [{u'error': {u'detail': u'Get http://a.example.com:5002/.well-known/acme-challenge/zDavaMNbJugELFM5VIXqAaYQBcloPVtoWdqQXHgPn0U: error occurred while resolving URL "http://a.example.com:5002/.well-known/acme-challenge/zDavaMNbJugELFM5VIXqAaYQBcloPVtoWdqQXHgPn0U": "lookup a.example.com: no such host"',
                                             u'status': 400,
                                             u'type': u'urn:ietf:params:acme:error:connection'},
                                  u'status': u'invalid',
                                  u'token': u'zDavaMNbJugELFM5VIXqAaYQBcloPVtoWdqQXHgPn0U',
                                  u'type': u'http-01',
                                  u'url': u'https://127.0.0.1:14000/chalZ/skh_Vm2Jm1lpNi0WlQFMwCvddb0jN5vYOBwocgqwtDY',
                                  u'validated': u'2020-02-28T20:14:56Z'}],
                 u'expires': u'2020-02-28T20:25:02Z',
                 u'identifier': {u'type': u'dns', u'value': u'a.example.com'},
                 u'status': u'invalid'}

        If we poll the Authorization instead of the Challenge, we won't have to
        issue a second query for the Authorization data.
        """

        try:
            authorization_response = self._poll_until_not(
                "AuthzUrl",
                dbAcmeChallenge.acme_authorization.authorization_url,
                ["pending", "processing"],
                "via acme_v2.AuthenticatedUser.acme_challenge_trigger();"
                "checking challenge status for {0}".format(
                    dbAcmeChallenge.acme_authorization.domain.domain_name
                ),
            )
        except errors.AcmePollingTooLong as exc:
            _tdelta, _result = exc.args
            for _chall in _result["challenges"]:
                if "error" in _chall:
                    timestamp_validated: Optional[datetime.datetime] = None
                    _validated = _chall.get("validated")
                    if _validated:
                        timestamp_validated = ari_timestamp_to_python(_validated)
                    subproblems_len = 0
                    if "subproblems" in _chall["error"]:
                        subproblems_len = len(_chall["error"]["subproblems"])
                    dbPollingError = db_create.create__AcmePollingError(  # noqa: F841
                        ctx,
                        acme_polling_error_endpoint_id=model_utils.AcmePollingErrorEndpoint.ACME_CHALLENGE_TRIGGER,
                        acme_order_id=dbAcmeAuthorization.acme_order_id__created,
                        acme_authorization_id=dbAcmeAuthorization.id,
                        acme_challenge_id=dbAcmeChallenge.id,
                        timestamp_validated=timestamp_validated,
                        subproblems_len=subproblems_len,
                        response=_result,
                    )
                    ctx.pyramid_transaction_commit()
            raise

        if authorization_response["status"] == "valid":
            log.info(
                ") acme_challenge_trigger | verified {0}".format(
                    dbAcmeChallenge.acme_authorization.domain.domain_name
                )
            )

            # log this
            assert ctx.application_settings
            if ctx.application_settings["log.acme"]:
                self.acmeLogger.log_challenge_pass(
                    "v2",
                    dbAcmeChallenge,
                    transaction_commit=True,
                )

            # update the authorization
            update_AcmeAuthorization_status(
                ctx,
                dbAcmeChallenge.acme_authorization,
                authorization_response["status"],
                transaction_commit=True,
            )

            # update the challenge
            acme_challenges = get_authorization_challenges(
                authorization_response,
                required_challenges=[
                    acme_challenge_type,
                ],
            )
            _acme_challenge_selected = filter_specific_challenge(
                acme_challenges, acme_challenge_type
            )
            if _acme_challenge_selected["url"] != dbAcmeChallenge.challenge_url:
                raise ValueError(
                    "IntegryError on challenge payload; this should never happen."
                )
            update_AcmeChallenge_status(
                ctx,
                dbAcmeChallenge,
                _acme_challenge_selected["status"],
                transaction_commit=True,
            )
            return _acme_challenge_selected

        # # the following elif condition is implied
        # elif authorization_response["status"] != "valid":
        assert ctx.application_settings
        if ctx.application_settings["log.acme"]:
            self.acmeLogger.log_challenge_error(
                "v2",
                dbAcmeChallenge,
                "fail-2",
                transaction_commit=True,
            )

        # update the challenge
        # 1. find the challenge
        acme_challenges = get_authorization_challenges(
            authorization_response,
            required_challenges=[
                acme_challenge_type,
            ],
        )
        _acme_challenge_selected = filter_specific_challenge(
            acme_challenges, acme_challenge_type
        )
        if _acme_challenge_selected["url"] != dbAcmeChallenge.challenge_url:
            raise ValueError(
                "IntegryError on challenge payload; this should never happen."
            )
        # 2. update the challenge
        update_AcmeChallenge_status(
            ctx,
            dbAcmeChallenge,
            _acme_challenge_selected["status"],
            transaction_commit=True,
        )

        # update the authorization, since we can
        update_AcmeAuthorization_status(
            ctx,
            dbAcmeChallenge.acme_authorization,
            authorization_response["status"],
            transaction_commit=True,
        )

        # a future version may want to log this failure somewhere
        # why? the timestamp on our AuthorizationObject
        # may get replaced during a server-sync

        raise errors.AcmeAuthorizationFailure(
            "{0} challenge did not pass: {1}".format(
                dbAcmeChallenge.acme_authorization.domain.domain_name,
                authorization_response,
            )
        )


def check_endpoint(
    ctx: "ApiContext",
    acme_directory: str,
    dbAcmeServer: Optional["AcmeServer"] = None,
) -> "Response":

    sess = new_BrowserSession()

    def _actual() -> "Response":
        """
        wrapped inner, as we may swap out a value here
        TODO: this would be better with a contextmanager
        """
        try:
            resp = sess.get(acme_directory, verify=cas.path(ctx, "CA_ACME"))
            return resp
        except Exception as exc:
            raise errors.AcmeServerErrorPublic(exc)

    alt_bundle = dbAcmeServer.local_ca_bundle(ctx) if dbAcmeServer else None
    if alt_bundle:
        _initial = cas.CA_ACME
        try:
            cas.CA_ACME = alt_bundle
            return _actual()
        finally:
            cas.CA_ACME = _initial

    return _actual()


def sanitize_directory_object(directory: Dict) -> Dict:
    """
    ACME directories might contain random key entries to keep clients from
    developing software that is hardcoded to that dict structure.
    This unfortunately makes it harder to detect changes, such as new fields.
    We can, at least, monitor existing fields:
    """
    _tracked_fields = [
        "keyChange",
        "meta",
        "newAccount",
        "newNonce",
        "newOrder",
        "renewalInfo",
        "revokeCert",
    ]
    d2 = {k: v for k, v in directory.items() if k in _tracked_fields}
    return d2


def serialize_directory_object(directory: Dict) -> str:
    directory_sanitized = sanitize_directory_object(directory)
    directory_string = json.dumps(directory_sanitized, sort_keys=True)
    return directory_string


def parse_acme_directory(
    directory: Dict[str, Union[str, Dict]]
) -> Tuple[Optional[Dict], Optional[str]]:
    """extracts relevant parts"""
    meta: Optional[Dict] = None
    profiles_str: Optional[str] = None
    _meta = directory.get("meta")
    if isinstance(_meta, dict):
        meta = _meta
        _profiles = _meta.get("profiles")
        if _profiles:
            profiles_str = ",".join(sorted(_profiles.keys()))
    return meta, profiles_str


def check_endpoint_for_meta(
    ctx: "ApiContext",
    acme_directory: str,
    dbAcmeServer: Optional["AcmeServer"] = None,
) -> Dict:
    resp = check_endpoint(ctx, acme_directory, dbAcmeServer=dbAcmeServer)
    resp_json = resp.json()
    return resp_json.get("meta")


def check_endpoint_for_renewalInfo(
    ctx: "ApiContext",
    acme_directory: str,
    dbAcmeServer: Optional["AcmeServer"] = None,
) -> bool:
    resp = check_endpoint(ctx, acme_directory, dbAcmeServer=dbAcmeServer)
    resp_json = resp.json()
    _renewal_base = resp_json.get("renewalInfo")
    if not _renewal_base:
        return False
    return True


def _ari_query(
    ctx: "ApiContext",
    acme_directory: str,
    ari_id: str,
    check_ari_support: Optional[bool] = True,
    dbAcmeServer: Optional["AcmeServer"] = None,
) -> AriCheckResult:
    def _actual() -> AriCheckResult:
        """
        wrapped inner, as we may swap out a value here
        TODO: this would be better with a contextmanager
        """
        try:
            sess = new_BrowserSession()
            r = sess.get(acme_directory, verify=cas.path(ctx, "CA_ACME"))
            _renewal_base = r.json().get("renewalInfo")
            if not _renewal_base:
                raise errors.AcmeAriCheckDeclined(
                    "ARI Check Declined; no `renewalInfo` endpoint"
                )
            _renewal_url = "%s/%s" % (_renewal_base, ari_id)
            log.info("renewalInfo endpoint: %s", _renewal_url)

            r = sess.get(_renewal_url, verify=cas.path(ctx, "CA_ACME"))
            _data: Optional[Dict] = r.json()
            _headers: "CaseInsensitiveDict" = r.headers
            ariCheckResult = AriCheckResult(
                payload=_data, headers=_headers, status_code=r.status_code
            )
            return ariCheckResult
        except Exception as exc:
            raise errors.AcmeServerErrorPublic(exc)

    alt_bundle = dbAcmeServer.local_ca_bundle(ctx) if dbAcmeServer else None
    if alt_bundle:
        _initial = cas.CA_ACME
        try:
            cas.CA_ACME = alt_bundle
            return _actual()
        finally:
            cas.CA_ACME = _initial

    return _actual()


def ari_check(
    ctx: "ApiContext",
    dbCertificateSigned: "CertificateSigned",
    force_check: bool = False,
) -> Optional[AriCheckResult]:
    """
    Returns:
        None if no endpoint
        AriCheck if there is an endpoing
            AriCheck[payload] will be null if there is an error
            AriCheck[headers] will always exist
    """
    log.info("ari_check(%s", dbCertificateSigned)

    # do not run ARI checks for certs that expire, or will expire before the
    # next proces is run

    datetime_now = datetime.datetime.now(datetime.timezone.utc)
    if not dbCertificateSigned.is_ari_checking_timely(ctx, datetime_now=datetime_now):
        if not force_check:
            # the expiry is a padded limit of the max time to rely on ARI checks
            timely_expiry = datetime_ari_timely(
                ctx, datetime_now=datetime_now, context="ari_check"
            )
            raise errors.AcmeAriCheckDeclined(
                "ARI Check Declined; Not Timely: %s<%s"
                % (
                    dbCertificateSigned.timestamp_not_after,
                    timely_expiry.replace(microsecond=0).isoformat(),
                )
            )

    ari_identifier: Optional[str] = None
    check_ari_support: bool = True
    dbAcmeServer: Optional["AcmeServer"] = None

    if dbCertificateSigned.acme_account:
        if dbCertificateSigned.acme_account.acme_server:
            dbAcmeServer = dbCertificateSigned.acme_account.acme_server
            if dbCertificateSigned.acme_account.acme_server.is_supports_ari:
                acme_directory = dbCertificateSigned.acme_account.acme_server.url
                check_ari_support = False
    else:
        # let's try to pull the cert info..
        cert_data = cert_utils.parse_cert(cert_pem=dbCertificateSigned.cert_pem)
        acme_directory = utils.issuer_to_endpoint(cert_data=cert_data)

    if not acme_directory:
        log.info("No ARI Endpoint detectable for this Certificate.")
        return None

    # can we grab the ARI info off the cert?
    try:
        ari_identifier = dbCertificateSigned.ari_identifier
    except Exception as exc:
        raise exc
    if not ari_identifier:
        raise errors.AcmeAriCheckDeclined("ARI Check Declined; No ARI Identifier")

    log.debug("ari_check: ")
    ariCheckResult = _ari_query(
        ctx,
        acme_directory,
        ari_identifier,
        check_ari_support=check_ari_support,
        dbAcmeServer=dbAcmeServer,
    )
    return ariCheckResult


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
