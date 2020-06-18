from __future__ import print_function

import logging

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# stdlib
import base64
import binascii
import datetime
import hashlib
import json
import pdb
import pprint
import re
import six
import ssl
import subprocess
import time

try:
    from urllib.request import urlopen, Request  # Python 3
    from urllib.error import URLError
except ImportError:
    from urllib2 import urlopen, Request  # Python 2
    from urllib2 import URLError

# pupi
import psutil

# localapp
from . import cert_utils
from . import errors
from . import utils
from ..model import utils as model_utils


# ==============================================================================


TESTING_ENVIRONMENT = False


# ==============================================================================


def new_response_404():
    return {"status": "*404*"}


# helper function base64 encode for jose spec
def _b64(b):
    return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")


def url_request(url, post_data=None, err_msg="Error", depth=0):
    """
    Originally from acme-tiny
    # helper function - make request and automatically parse json response

    :param str url: (required) The url
    :param dict post_data: (optional) Data to POST to the url
    :param str err_msg: (optional) A custom error message
    :param int depth: (optional) An integer nothing the depth of this function being called

    returns (resp_data, status_code, headers)
    """
    log.info("acme_v2.url_request(%s, %s", url, post_data)
    context = None
    try:
        headers = {
            "Content-Type": "application/jose+json",
            "User-Agent": "peter_sslers",
        }
        if TESTING_ENVIRONMENT:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            context = ctx
        resp = urlopen(Request(url, data=post_data, headers=headers), context=ctx)
        resp_data, status_code, headers = (
            resp.read().decode("utf8"),
            resp.getcode(),
            resp.headers,
        )
        log.info(") url_request < status_code < %s", status_code)
        log.info(") url_request < resp_data   < %s", resp_data)
        log.info(") url_request < headers     < %s", headers)
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
        depth < 100
        and status_code == 400
        and resp_data["type"] == "urn:ietf:params:acme:error:badNonce"
    ):
        raise IndexError(resp_data)  # allow 100 retrys for bad nonces
    if status_code not in [200, 201, 204]:
        if isinstance(resp_data, dict):
            raise errors.AcmeServerError(status_code, resp_data)
        msg = "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(
            err_msg, url, post_data, status_code, resp_data
        )
        # raise ValueError(msg)
        raise errors.AcmeServerError(msg)
    return resp_data, status_code, headers


# ------------------------------------------------------------------------------


def get_authorization_challenges(
    authorization_response, required_challenges=None,
):
    """
    :param dict authorization_response: (required) A Python dict representing a server's JSON payload of an Authorization Object.
    :param list required_challenges: (optional) Pass in a list of required challenges
    
    returns:
        `dict` in which keys are the challenge type and values are the challenge payload.
    """

    challenges = {
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
    acme_challenges_payload,
    acme_challenge_type=None,
):
    """
    :param dict acme_challenges_payload: (required) A payload of acme-challenges
    :param str acme_challenge_type: (required) The selected type of acme-challenge
    """
    if (acme_challenge_type not in acme_challenges_payload) or not acme_challenges_payload[
        acme_challenge_type
    ]:
        raise ValueError("selected challenege not provided by ACME server")
    return acme_challenges_payload[acme_challenge_type]


def create_challenge_keyauthorization(token, accountkey_thumbprint):
    """
    :param str token: (required) A string `token` entry from a server Challenge object
    :param str accountkey_thumbprint: (required) The thumbprint of an Authenticated Account
    """
    token = re.sub(r"[^A-Za-z0-9_\-]", "_", token)
    keyauthorization = "{0}.{1}".format(token, accountkey_thumbprint)
    return keyauthorization


# ------------------------------------------------------------------------------


def acme_directory_get(acmeAccount=None):
    """
    Get the ACME directory of urls

    :param acmeAccount: (required) a :class:`model.objects.AcmeAccount` instance
    """
    log.info("acme_v2.acme_directory_get(")
    url_directory = acmeAccount.acme_account_provider.directory
    if not url_directory:
        raise ValueError("no directory for the CERTIFICATE_AUTHORITY!")
    directory_payload, _status_code, _headers = url_request(
        url_directory, err_msg="Error getting directory"
    )
    if not directory_payload:
        raise ValueError("no directory data for the CERTIFICATE_AUTHORITY")
    log.info(") acme_directory_get success")
    return directory_payload


# ------------------------------------------------------------------------------


def account_key__parse(account_key_path=None):
    """
    :param account_key_path: (required) the filepath to a PEM encoded RSA account key file.
    """
    log.info("acme_v2.account_key__parse(")
    # todo: leverage crypto
    with psutil.Popen(
        [cert_utils.openssl_path, "rsa", "-in", account_key_path, "-noout", "-text",],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        out, err = proc.communicate()
        if six.PY3:
            out = out.decode("utf8")
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out, re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    alg = "RS256"
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    _accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(_accountkey_json.encode("utf8")).digest())
    return jwk, thumbprint, alg


# ------------------------------------------------------------------------------


class AcmeOrderRFC(object):
    """
    An object wrapping up an ACME server order

    Attributes:

    :param rfc_object: (required) A Python dict representing the RFC AcmeOrder object
    :param response_headers: (required) The headers of the ACME Directory's response
    :param dbUniqueFQDNSet: (required) A :class:`model.objects.UniqueFQDNSet` object
    """

    rfc_object = None
    response_headers = None
    dbUniqueFQDNSet = None

    def __init__(self, rfc_object=None, response_headers=None, dbUniqueFQDNSet=None):
        self.rfc_object = rfc_object
        self.response_headers = response_headers
        self.dbUniqueFQDNSet = dbUniqueFQDNSet


# ------------------------------------------------------------------------------


class AuthenticatedUser(object):

    # our API guarantees these items
    acmeLogger = None
    account_key_path = None
    acmeAccount = None
    acme_directory = None
    accountkey_jwk = None
    accountkey_thumbprint = None
    alg = None
    log__OperationsEvent = None

    _api_account_object = None  # api server native/json object
    _api_account_headers = None  # api server native/json object

    def __init__(
        self,
        acmeLogger=None,
        acmeAccount=None,
        account_key_path=None,
        acme_directory=None,
        log__OperationsEvent=None,
    ):
        """
        :param acmeLogger: (required) A :class:`.logger.AcmeLogger` instance
        :param acmeAccount: (required) A :class:`model.objects.AcmeAccount` object
        :param account_key_path: (optional) The filepath of a PEM encoded RSA key
        :param acme_directory: (optional) The ACME Directory's url for a "directory"
        :param log__OperationsEvent: (required) callable function to log the operations event
        """
        if not all((acmeLogger, acmeAccount, account_key_path)):
            raise ValueError(
                "all elements are required: (acmeLogger, acmeAccount, account_key_path)"
            )

        # do we need to load this?
        if acme_directory is None:
            acme_directory = acme_directory_get(acmeAccount)

        # parse account key to get public key
        (accountkey_jwk, accountkey_thumbprint, alg) = account_key__parse(
            account_key_path=account_key_path
        )

        # configure the object!
        self.acmeLogger = acmeLogger
        self.account_key_path = account_key_path
        self.acmeAccount = acmeAccount
        self.acme_directory = acme_directory
        self.accountkey_jwk = accountkey_jwk
        self.accountkey_thumbprint = accountkey_thumbprint
        self.alg = alg
        self.log__OperationsEvent = log__OperationsEvent
        self._next_nonce = None

    def _send_signed_request(self, url, payload=None, depth=0):
        """
        Originally from acme-tiny
        :param url: (required) The url
        :param payload: (optional) A Python dict of data to POST to the url
        :param depth: (optional) An integer nothing the depth of this function being called

        This proxies `url_request` with a signed payload
        returns (resp_data, status_code, headers)
        """
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
        if self._next_nonce:
            nonce = self._next_nonce
        else:
            self._next_nonce = nonce = url_request(self.acme_directory["newNonce"])[2][
                "Replay-Nonce"
            ]
        protected = {"url": url, "alg": self.alg, "nonce": nonce}
        protected.update(
            {"jwk": self.accountkey_jwk}
            if self._api_account_headers is None
            else {"kid": self._api_account_headers["Location"]}
        )
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
        # TODO: leverage crypto
        with psutil.Popen(
            [
                cert_utils.openssl_path,
                "dgst",
                "-sha256",
                "-sign",
                self.account_key_path,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            out, err = proc.communicate(protected_input)
            if proc.returncode != 0:
                self._next_nonce = None
                raise IOError("_send_signed_request\n{1}".format(err))
        data = json.dumps(
            {"protected": protected64, "payload": payload64, "signature": _b64(out)}
        )
        try:
            result = url_request(
                url,
                post_data=data.encode("utf8"),
                err_msg="_send_signed_request",
                depth=depth,
            )
            try:
                _next_nonce = result[2]["Replay-Nonce"]
                if (not _next_nonce) or (nonce == _next_nonce):
                    self._next_nonce = None
                else:
                    self._next_nonce = _next_nonce
            except Exception as exc:
                self._next_nonce = None
                pass
            return result
        except IndexError:  # retry bad nonces (they raise IndexError)
            self._next_nonce = None
            return self._send_signed_request(url, payload=payload, depth=(depth + 1),)

    def _poll_until_not(self, _url, _pending_statuses, _log_message):
        """
        Originally from acme-tiny
        :param _url: (required) The url
        :param _pending_statuses: (required) The statuses we will continue polling until we lose
        :param depth: (optional) An integer nothing the depth of this function being called
        """
        log.info("acme_v2.AuthenticatedUser._poll_until_not {0}".format(_log_message))
        _result, _t0 = None, time.time()
        while _result is None or _result["status"] in _pending_statuses:
            assert time.time() - _t0 < 3600, "Polling timeout"  # 1 hour timeout
            time.sleep(0 if _result is None else 2)
            _result, _status_code, _headers = self._send_signed_request(
                _url, payload=None,
            )
        return _result

    def update_contact(self, ctx, contact=None):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param contact: (optional) The updated contact info
        :param is_registration: (optional) Boolean
        """
        log.info("acme_v2.AuthenticatedUser.update_contact( {0}".format(contact))
        payload_contact = {"contact": contact}
        (
            acme_account_object,
            _status_code,
            _acme_account_headers,
        ) = self._send_signed_request(
            self._api_account_headers["Location"], payload=payload_contact,
        )
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

    def authenticate(self, ctx, contact=None):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param contact: (optional) The contact info

        returns:
            acme_account_object - ACME Directory account object
            acme_account_headers - ACME Directory account response headers

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
        log.info("acme_v2.AuthenticatedUser.authenticate(")
        if self.acme_directory is None:
            raise ValueError("`acme_directory` is required")

        if "newAccount" not in self.acme_directory:
            raise ValueError("directory does not support `newAccount`")

        # log the event to the db
        self.acmeLogger.log_newAccount("v2", transaction_commit=True)

        # hit the acme api for the registration
        try:
            """ possible api values for newAccount payload are:
                {"contact": None,
                 "termsOfServiceAgreed": None,
                 "onlyReturnExisting": None,
                 "externalAccountBinding": None,
                 }
            """
            payload_registration = {
                "termsOfServiceAgreed": True,
            }
            if contact is not None:
                # contact should be a LIST of URI
                if "@" in contact and (not contact.startswith("mailto:")):
                    contact = "mailto:%s" % contact
                payload_registration["contact"] = [
                    contact,
                ]
            (
                acme_account_object,
                status_code,
                acme_account_headers,
            ) = self._send_signed_request(
                self.acme_directory["newAccount"], payload=payload_registration
            )
            self._api_account_object = acme_account_object
            self._api_account_headers = acme_account_headers
            log.debug(") authenticate | acme_account_object: %s" % acme_account_object)
            log.debug(
                ") authenticate | acme_account_headers: %s" % acme_account_headers
            )
            log.info(
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
            dbOperationsEvent = self.log__OperationsEvent(
                ctx,
                model_utils.OperationsEventType.from_string(
                    "AcmeAccount__authenticate"
                ),
                event_payload_dict,
            )
        except Exception as exc:
            raise

    def acme_order_load(self, ctx, dbAcmeOrder, transaction_commit=None):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeOrder: (required) a :class:`model.objects.AcmeOrder` instance
        """
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        if not dbAcmeOrder.order_url:
            raise ValueError("the order does not have a `order_url`")

        try:
            log.info("acme_v2.AuthenticatedUser.acme_order_load(")
            (
                acme_order_object,
                _status_code,
                acme_order_headers,
            ) = self._send_signed_request(dbAcmeOrder.order_url, None)
            log.debug(") acme_order_load | acme_order_object: %s" % acme_order_object)
            log.debug(") acme_order_load | acme_order_headers: %s" % acme_order_headers)
        except errors.AcmeServer404 as exc:
            log.info(") acme_order_load | ERROR AcmeServer404!")
            # TODO: not finished with this logic flow, need to trigger somehow
            acme_order_object = new_response_404()
            raise

        # log the event to the db
        dbEventLogged = self.acmeLogger.log_order_load(
            "v2", dbAcmeOrder, transaction_commit=True
        )

        # this is just a convenience wrapper for our order object
        acmeOrderRfcObject = AcmeOrderRFC(
            rfc_object=acme_order_object,
            response_headers=acme_order_headers,
            dbUniqueFQDNSet=dbAcmeOrder.unique_fqdn_set,
        )

        return (acmeOrderRfcObject, dbEventLogged)

    def acme_order_new(
        self, ctx, domain_names=None, dbUniqueFQDNSet=None, transaction_commit=None,
    ):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param domain_names: (required) The domains for our order
        :param dbUniqueFQDNSet: (required) The :class:`model.objects.UniqueFQDNSet` associated with the order
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        returns
            acmeOrderRfcObject, dbEventLogged
        """
        # create a new order
        log.info("acme_v2.AuthenticatedUser.acme_order_new(")
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        payload_order = {
            "identifiers": [{"type": "dns", "value": d} for d in domain_names]
        }
        (
            acme_order_object,
            _status_code,
            acme_order_headers,
        ) = self._send_signed_request(
            self.acme_directory["newOrder"], payload=payload_order,
        )
        log.debug(") acme_order_new | acme_order_object: %s" % acme_order_object)
        log.debug(") acme_order_new | acme_order_headers: %s" % acme_order_headers)

        # log the event to the db
        dbEventLogged = self.acmeLogger.log_newOrder(
            "v2", dbUniqueFQDNSet, transaction_commit=True
        )

        # this is just a convenience wrapper for our order object
        acmeOrderRfcObject = AcmeOrderRFC(
            rfc_object=acme_order_object,
            response_headers=acme_order_headers,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
        )

        return (acmeOrderRfcObject, dbEventLogged)

    def _prepare_acme_challenge__http01(
        self,
        ctx,
        dbAcmeAuthorization=None,
        dbAcmeChallenge=None,
    ):
        """
        prepares an AcmeChallenge by registering - and perhaps testing, the url
        """
        # acme_challenge_response
        keyauthorization = create_challenge_keyauthorization(
            dbAcmeChallenge.token, self.accountkey_thumbprint,
        )
        if dbAcmeChallenge.keyauthorization != keyauthorization:
            raise ValueError("This should never happen!")

        # update the db; this should be integrated with the above
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(
            dbAcmeAuthorization.domain.domain_name, dbAcmeChallenge.token,
        )

        # check that the file is in place
        try:
            if TESTING_ENVIRONMENT:
                log.debug("TESTING_ENVIRONMENT, not ensuring the challenge is readable")
            else:
                try:
                    resp = urlopen(wellknown_url)
                    resp_data = resp.read().decode("utf8").strip()
                    assert resp_data == keyauthorization
                except (IOError, AssertionError):
                    self.acmeLogger.log_challenge_error(
                        "v2", dbAcmeChallenge, "pretest-1", transaction_commit=True,
                    )
                    raise errors.DomainVerificationError(
                        "Wrote keyauth challenge, but couldn't download {0}".format(
                            wellknown_url
                        )
                    )
                except ssl.CertificateError as exc:
                    self.acmeLogger.log_challenge_error(
                        "v2", dbAcmeChallenge, "pretest-2", transaction_commit=True,
                    )
                    if str(exc).startswith("hostname") and (
                        "doesn't match" in str(exc)
                    ):
                        raise errors.DomainVerificationError(
                            "Wrote keyauth challenge, but ssl can't view {0}. `%s`".format(
                                wellknown_url, str(exc)
                            )
                        )
                    raise
        except (AssertionError, ValueError) as exc:
            raise errors.DomainVerificationError(
                "couldn't download {0}: {1}".format(wellknown_url, exc)
            )

    def acme_order_process_authorizations(
        self,
        ctx,
        acmeOrderRfcObject=None,
        dbAcmeOrder=None,
        handle_authorization_payload=None,
        update_AcmeAuthorization_status=None,
        update_AcmeChallenge_status=None,
        updated_AcmeOrder_ProcessingStatus=None,
        transaction_commit=None,
    ):
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
        log.info("acme_v2.AuthenticatedUser.acme_order_process_authorizations(")
        if not transaction_commit:
            # !!!: if this were not True, then we can't invoke items with `transaction_commit=True` below
            raise ValueError(
                "`acme_order_process_authorizations()` must persist to the database."
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
        for authorization_url in acmeOrderRfcObject.rfc_object["authorizations"]:
            auth_result = self.acme_authorization_process_url(
                ctx,
                authorization_url,
                acme_challenge_type_id__preferred=model_utils.AcmeChallengeType.from_string(
                    "http-01"
                ),
                handle_authorization_payload=handle_authorization_payload,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
                updated_AcmeOrder_ProcessingStatus=updated_AcmeOrder_ProcessingStatus,
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
        ctx,
        dbAcmeOrder=None,
        update_order_status=None,
        transaction_commit=None,
        # function specific
        csr_path=None,
    ):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the order
        :param update_order_status: (required) Callable function. expects (ctx, dbAcmeOrder, acme_rfc_object, transaction_commit)
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        :param csr_path: (required)
        """
        # get the new certificate
        log.info("acme_v2.AuthenticatedUser.acme_order_finalize(")

        if transaction_commit is not True:
            # required for the `update_order_status`
            raise ValueError("we must invoke this knowing it will commit")

        if update_order_status is None:
            raise ValueError(
                "we must invoke this with a callable `update_order_status`"
            )

        # convert the certificate to a DER
        # todo: leverage crypto
        with psutil.Popen(
            [cert_utils.openssl_path, "req", "-in", csr_path, "-outform", "DER"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            csr_der, err = proc.communicate()

        acmeLoggedEvent = self.acmeLogger.log_order_finalize(
            "v2", transaction_commit=True
        )  # log this to the db

        payload_finalize = {"csr": _b64(csr_der)}
        try:
            (
                finalize_response,
                _status_code,
                _finalize_headers,
            ) = self._send_signed_request(
                dbAcmeOrder.finalize_url, payload=payload_finalize,
            )
            log.debug(
                ") acme_order_finalize | finalize_response: %s" % finalize_response
            )
            log.debug(
                ") acme_order_finalize | _finalize_headers: %s" % _finalize_headers
            )
        except errors.AcmeServer404 as exc:
            finalize_response = new_response_404()
            raise

        # poll the order to monitor when it's done
        url_order_status = dbAcmeOrder.order_url

        log.info(") acme_order_finalize | checking order {0}".format("order"))
        acme_order_finalized = self._poll_until_not(
            url_order_status, ["pending", "processing"], "Error checking order status"
        )
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

        url_certificate = acme_order_finalized.get("certificate")
        if not url_certificate:
            raise ValueError(
                "The AcmeOrder server response should have a `certificate`."
            )
        fullchain_pem = self.download_certificate(url_certificate)
        return fullchain_pem

    def download_certificate(self, url_certificate):
        log.info("acme_v2.AuthenticatedUser.download_certificate(")
        if not url_certificate:
            raise ValueError("Must supply a url for the certificate")

        # download the certificate
        # ACME-V2 furnishes a FULLCHAIN (certificate_pem + chain_pem)
        (fullchain_pem, _status_code, _certificate_headers) = self._send_signed_request(
            url_certificate, None
        )
        log.debug(") download_certificate | fullchain_pem: %s" % fullchain_pem)
        log.debug(
            ") download_certificate | _certificate_headers: %s" % _certificate_headers
        )
        log.info(") download_certificate | downloaded signed certificate!")
        return fullchain_pem

    def acme_authorization_process_url(
        self,
        ctx,
        authorization_url,
        acme_challenge_type_id__preferred=None,
        handle_authorization_payload=None,
        update_AcmeAuthorization_status=None,
        update_AcmeChallenge_status=None,
        updated_AcmeOrder_ProcessingStatus=None,
        dbAcmeAuthorization=None,
        transaction_commit=None,
    ):
        """
        Process a single Authorization URL

        * fetch the URL, construct a `model.objects.AcmeAuthorization` if needed; update otherwise
        * complete ACME Challenge if possible

        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param authorization_url: (required) The url of the authorization
        :param acme_challenge_type_id__preferred: An `int` representing a :class:`model.utils.AcmeChallengeType` challenge

        :param handle_authorization_payload: (required) Callable function. expects (authorization_url, authorization_response, dbAcmeAuthorization=?, transaction_commit=?)

        :param update_AcmeAuthorization_status: callable. expects (ctx, dbAcmeAuthorization, status_text, transaction_commit)
        :param update_AcmeChallenge_status: callable. expects (ctx, dbAcmeChallenge, status_text, transaction_commit)
        :param updated_AcmeOrder_ProcessingStatus: callable. expects (ctx, dbAcmeChallenge, acme_order_processing_status_id, transaction_commit)
        :param dbAcmeAuthorization: A :class:`model.objects.AcmeAuthorization` instance
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        Returns:

            True: Authorization need, challenge performed and Valid
            False: No Authorization Action needed
            None: Authorization Action needed, but no Action taken

        If the challenge fails, we raise a `errors.DomainVerificationError`.
        """
        log.info("acme_v2.AuthenticatedUser.acme_authorization_process_url(")
        # scoping, our todo list
        # _todo_complete_challenges = None

        if (
            acme_challenge_type_id__preferred
            not in model_utils.AcmeChallengeType._mapping
        ):
            raise ValueError("invalid `acme_challenge_type_id__preferred`")

        _todo__complete_challenge = None

        # in v1, we know the domain before the authorization request
        # in v2, we hit an order's authorization url to get the domain
        (
            authorization_response,
            _status_code,
            _authorization_headers,
        ) = self._send_signed_request(authorization_url, payload=None,)
        log.debug(
            ") acme_authorization_process_url | authorization_response: %s"
            % authorization_response
        )
        log.debug(
            ") acme_authorization_process_url | _authorization_headers: %s"
            % _authorization_headers
        )
        log.info(") .acme_authorization_process_url | handle_authorization_payload(")

        dbAcmeAuthorization = handle_authorization_payload(
            authorization_url,
            authorization_response,
            dbAcmeAuthorization=dbAcmeAuthorization,
            transaction_commit=True,
        )
        log.info(") handle_authorization_payload")

        # log the event
        dbAcmeEventLog_authorization_fetch = self.acmeLogger.log_authorization_request(
            "v2", dbAcmeAuthorization=dbAcmeAuthorization, transaction_commit=True,
        )  # log this to the db

        _response_domain = authorization_response["identifier"]["value"]
        if dbAcmeAuthorization.domain.domain_name != _response_domain:
            raise ValueError("mismatch on a domain name")

        # once we inspect the url, we have the domain
        # the domain is in our `authorization_response`
        # but also on our `dbAcmeAuthorization` object
        log.info(
            ") acme_authorization_process_url | Handling Authorization for {0}...".format(
                dbAcmeAuthorization.domain.domain_name
            )
        )

        _authorization_status = authorization_response["status"]
        if _authorization_status == "pending":
            # we need to run the authorization
            pass
        elif _authorization_status == "valid":
            # noting to do, one or more challenges is valid
            # _todo_complete_challenges = False
            return False
        elif _authorization_status == "invalid":
            # this failed once, we need to auth again !
            # _todo_complete_challenges = False
            raise errors.AcmeOrderFatal("AcmeAuthorization already `invalid`")
        elif _authorization_status == "deactivated":
            # this has been removed from the order?
            # _todo_complete_challenges = False
            raise errors.AcmeOrderFatal("AcmeAuthorization already `deactivated`")
        elif _authorization_status == "expired":
            # this passed once, BUT we need to auth again
            # _todo_complete_challenges = True
            raise errors.AcmeOrderFatal("AcmeAuthorization already `expired`")
        elif _authorization_status == "revoked":
            # this failed once, we need to auth again?
            # _todo_complete_challenges = True
            raise errors.AcmeOrderFatal("AcmeAuthorization already `revoked`")
        else:
            raise ValueError(
                "unexpected authorization status: `%s`" % _authorization_status
            )

        # if not _todo_complete_challenges:
        #    # short-circuit out of completing the challenge
        #    return False

        # we could parse the challenge
        # however, the call to `process_discovered_auth` should have updated the challenge object already
        acme_challenges = get_authorization_challenges(
            authorization_response, required_challenges=["http-01",]
        )
        _acme_challenge_type = model_utils.AcmeChallengeType._mapping[
            acme_challenge_type_id__preferred
        ]
        _acme_challenge_selected = filter_specific_challenge(
            acme_challenges, _acme_challenge_type
        )

        dbAcmeChallenge = None
        if _acme_challenge_type == "http-01":
            dbAcmeChallenge = dbAcmeAuthorization.acme_challenge_http_01
        elif _acme_challenge_type == "dns-01":
            dbAcmeChallenge = dbAcmeAuthorization.acme_challenge_dns_01
        elif _acme_challenge_type == "tls-alpn-01":
            dbAcmeChallenge = dbAcmeAuthorization.acme_challenge_tls_alpn_01
        if not dbAcmeChallenge:
            raise ValueError("error loading AcmeChallenge. this is unexpected.")

        if _acme_challenge_selected["url"] != dbAcmeChallenge.challenge_url:
            raise ValueError(
                "`acme_challenges` has a different challenge_url. this is unexpected."
            )

        _challenge_status_text = dbAcmeChallenge.acme_status_challenge
        if _challenge_status_text == "*discovered*":
            # internal marker, pre "pending"
            _todo__complete_challenge = True
        elif _challenge_status_text == "pending":
            _todo__complete_challenge = True
        elif _challenge_status_text == "processing":
            # we may need to trigger again?
            _todo__complete_challenge = True
        elif _challenge_status_text == "valid":
            # already completed
            _todo__complete_challenge = False
        elif _challenge_status_text == "invalid":
            # we may need to trigger again?
            _todo__complete_challenge = True
        else:
            raise ValueError(
                "unexpected challenge status: `%s`" % _challenge_status_text
            )

        if _todo__complete_challenge:
            if _acme_challenge_type == "http-01":
                self._prepare_acme_challenge__http01(
                    ctx, dbAcmeAuthorization=dbAcmeAuthorization, dbAcmeChallenge=dbAcmeChallenge,
                )
            elif _acme_challenge_type == "dns-01":
                # TODO: dns-01 with acme
                raise NotImplementedError()
            elif _acme_challenge_type == "tls-alpn-01":
                # TODO: tls-alpn-01
                raise NotImplementedError()

            self.acme_challenge_trigger(
                ctx,
                dbAcmeChallenge=dbAcmeChallenge,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
                transaction_commit=True,
            )
            return True
        return None

    def acme_authorization_load(
        self, ctx, dbAcmeAuthorization, transaction_commit=None
    ):
        """
        This loads the authorization object and pulls the payload
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAuthorization: (required) a :class:`model.objects.AcmeAuthorization` instance
        """
        log.info("acme_v2.AuthenticatedUser.acme_authorization_load(")
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        if not dbAcmeAuthorization.authorization_url:
            raise ValueError(
                "the `AcmeAuthorization` does not have an `authorization_url`"
            )

        try:
            (
                authorization_response,
                _status_code,
                _authorization_headers,
            ) = self._send_signed_request(dbAcmeAuthorization.authorization_url, None)
            log.debug(
                ") acme_authorization_load | authorization_response: %s"
                % authorization_response
            )
            log.debug(
                ") acme_authorization_load | _authorization_headers: %s"
                % _authorization_headers
            )
        except errors.AcmeServer404 as exc:
            authorization_response = new_response_404()

        # log the event
        dbAcmeEventLog_authorization_fetch = self.acmeLogger.log_authorization_request(
            "v2", dbAcmeAuthorization=dbAcmeAuthorization, transaction_commit=True,
        )  # log this to the db

        return (authorization_response, dbAcmeEventLog_authorization_fetch)

    def acme_authorization_deactivate(
        self, ctx, dbAcmeAuthorization, transaction_commit=None
    ):
        """
        This loads the authorization object and pulls the payload
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAuthorization: (required) a :class:`model.objects.AcmeAuthorization` instance

        https://tools.ietf.org/html/rfc8555#section-7.5.2

            7.5.2.  Deactivating an Authorization

               If a client wishes to relinquish its authorization to issue
               certificates for an identifier, then it may request that the server
               deactivate each authorization associated with it by sending POST
               requests with the static object {"status": "deactivated"} to each
               authorization URL.

        """
        log.info("acme_v2.AuthenticatedUser.acme_authorization_deactivate(")
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        if not dbAcmeAuthorization.authorization_url:
            raise ValueError(
                "the `AcmeAuthorization` does not have an `authorization_url`"
            )

        try:
            (
                authorization_response,
                _status_code,
                _authorization_headers,
            ) = self._send_signed_request(
                dbAcmeAuthorization.authorization_url, {"status": "deactivated"}
            )
            log.debug(
                ") acme_authorization_deactivate | authorization_response: %s"
                % authorization_response
            )
            log.debug(
                ") acme_authorization_deactivate | _authorization_headers: %s"
                % _authorization_headers
            )
        except errors.AcmeServer404 as exc:
            authorization_response = new_response_404()

        # log the event
        dbAcmeEventLog_authorization_fetch = self.acmeLogger.log_authorization_deactivate(
            "v2", dbAcmeAuthorization=dbAcmeAuthorization, transaction_commit=True,
        )  # log this to the db

        return (authorization_response, dbAcmeEventLog_authorization_fetch)

    def acme_challenge_load(self, ctx, dbAcmeChallenge, transaction_commit=None):
        """
        This loads the authorization object and pulls the payload
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeChallenge: (required) a :class:`model.objects.AcmeChallenge` instance
        """
        log.info("acme_v2.AuthenticatedUser.acme_challenge_load(")
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        if not dbAcmeChallenge.challenge_url:
            raise ValueError("the challenge does not have a `challenge_url`")

        try:
            (
                challenge_response,
                _status_code,
                _challenge_headers,
            ) = self._send_signed_request(dbAcmeChallenge.challenge_url, None)
            log.debug(
                ") acme_challenge_load | challenge_response: %s" % challenge_response
            )
            log.debug(
                ") acme_challenge_load | _challenge_headers: %s" % _challenge_headers
            )
        except errors.AcmeServer404 as exc:
            challenge_response = new_response_404()

        # log the event
        dbAcmeEventLog_challenge_fetch = self.acmeLogger.log_challenge_PostAsGet(
            "v2", dbAcmeChallenge=dbAcmeChallenge, transaction_commit=True,
        )  # log this to the db

        return (challenge_response, dbAcmeEventLog_challenge_fetch)

    def acme_challenge_trigger(
        self,
        ctx,
        dbAcmeChallenge=None,
        update_AcmeAuthorization_status=None,
        update_AcmeChallenge_status=None,
        transaction_commit=None,
    ):
        """
        This triggers the challenge object

        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeChallenge: (required) a :class:`model.objects.AcmeChallenge` instance
        :param dbAcmeAuthorization: (required) a :class:`model.objects.AcmeAuthorization` instance
        :param update_AcmeAuthorization_status: callable. expects (ctx, dbAcmeAuthorization, status_text, transaction_commit)
        :param update_AcmeChallenge_status: callable. expects (ctx, dbAcmeChallenge, status_text, transaction_commit)
        
        returns `challenge_response` the ACME paylaod for the specific challenge
        """
        log.info("acme_v2.AuthenticatedUser.acme_challenge_trigger(")
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        dbAcmeAuthorization = dbAcmeChallenge.acme_authorization

        # note that we are about to trigger the challenge:
        self.acmeLogger.log_challenge_trigger(
            "v2", dbAcmeChallenge, transaction_commit=True,
        )
        # trigger the challenge!
        # if we had a 'valid' challenge, the payload would be `None`
        # to invoke a GET-as-POST functionality and load the challenge resource
        # POSTing an empty `dict` will trigger the challenge
        try:
            (
                challenge_response,
                _status_code,
                _challenge_headers,
            ) = self._send_signed_request(dbAcmeChallenge.challenge_url, payload={},)
            log.debug(
                ") acme_challenge_trigger | challenge_response: %s" % challenge_response
            )
            log.debug(
                ") acme_challenge_trigger | _challenge_headers: %s" % _challenge_headers
            )
        except errors.AcmeServerError as exc:
            (_status_code, _resp) = exc.args
            if isinstance(_resp, dict):
                if _resp["type"].startswith("urn:ietf:params:acme:error:"):
                    # {u'status': 400, u'type': u'urn:ietf:params:acme:error:malformed', u'detail': u'Authorization expired 2020-02-28T20:25:02Z'}
                    # can this be caught?
                    pass
            raise
        if challenge_response["status"] not in ("pending", "valid"):
            # this should ALMOST ALWAYS be "pending"
            # on a test environment, the `Pebble` server might instantly transition from "pending" to "valid"
            raise ValueError(
                "AcmeChallenge is not 'pending' or 'valid' on the ACME server"
            )

        # TODO - COULD an accepted challenge be here?
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
                 u'url': u'https://0.0.0.0:14000/chalZ/skh_Vm2Jm1lpNi0WlQFMwCvddb0jN5vYOBwocgqwtDY',
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
                                  u'url': u'https://0.0.0.0:14000/chalZ/skh_Vm2Jm1lpNi0WlQFMwCvddb0jN5vYOBwocgqwtDY',
                                  u'validated': u'2020-02-28T20:14:56Z'}],
                 u'expires': u'2020-02-28T20:25:02Z',
                 u'identifier': {u'type': u'dns', u'value': u'a.example.com'},
                 u'status': u'invalid'}

        Because PeterSSlers only handles http01 challenges, we will opt for the authorization url
        """
        authorization_response = self._poll_until_not(
            dbAcmeChallenge.acme_authorization.authorization_url,
            ["pending"],
            "checking challenge status for {0}".format(
                dbAcmeChallenge.acme_authorization.domain.domain_name
            ),
        )

        if authorization_response["status"] == "valid":
            log.info(
                ") acme_challenge_trigger | verified {0}".format(
                    dbAcmeChallenge.acme_authorization.domain.domain_name
                )
            )

            # log this
            self.acmeLogger.log_challenge_pass(
                "v2", dbAcmeChallenge, transaction_commit=True,
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
                authorization_response, required_challenges=["http-01",]
            )
            _acme_challenge_selected = filter_specific_challenge(
                acme_challenges, dbAcmeChallenge.acme_challenge_type
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

        elif authorization_response["status"] != "valid":

            self.acmeLogger.log_challenge_error(
                "v2", dbAcmeChallenge, "fail-2", transaction_commit=True,
            )

            # kill the authorization
            update_AcmeAuthorization_status(
                ctx,
                dbAcmeChallenge.acme_authorization,
                authorization_response["status"],
                transaction_commit=True,
            )

            # kill the challenge
            acme_challenges = get_authorization_challenges(
                authorization_response, required_challenges=["http-01",],
            )
            _acme_challenge_selected = filter_specific_challenge(
                acme_challenges, dbAcmeChallenge.acme_challenge_type
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

            raise errors.AcmeAuthorizationFailure(
                "{0} challenge did not pass: {1}".format(
                    dbAcmeChallenge.acme_authorization.domain.domain_name,
                    authorization_response,
                )
            )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ()
