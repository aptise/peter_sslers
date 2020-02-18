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


_DEFAULT_CA = "https://acme-staging-v02.api.letsencrypt.org/directory"
CERTIFICATE_AUTHORITY = _DEFAULT_CA
CERTIFICATE_AUTHORITY_AGREEMENT = None
TESTING_ENVIRONMENT = False


# ==============================================================================


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
    """
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
        resp_data, code, headers = (
            resp.read().decode("utf8"),
            resp.getcode(),
            resp.headers,
        )
    except IOError as exc:
        # if isinstance(exc, URLError):
        #    # TODO: log this error to the database
        #    raise errors.AcmeCommunicationError(str(exc))
        resp_data = exc.read().decode("utf8") if hasattr(exc, "read") else str(exc)
        code, headers = getattr(exc, "code", None), {}
    except Exception as exc:
        # TODO: log this error to the database
        raise errors.AcmeCommunicationError(str(exc))
    try:
        resp_data = json.loads(resp_data)  # try to parse json results
    except ValueError:
        pass  # ignore json parsing errors
    if code == 404:
        raise errors.AcmeServer404(resp_data)
    if code == 400:
        # this happens on pebble if we set it to https, not https
        if resp_data == "Client sent an HTTP request to an HTTPS server.\n":
            raise IndexError(resp_data)
    if (
        depth < 100
        and code == 400
        and resp_data["type"] == "urn:ietf:params:acme:error:badNonce"
    ):
        raise IndexError(resp_data)  # allow 100 retrys for bad nonces
    if code not in [200, 201, 204]:
        raise ValueError(
            "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(
                err_msg, url, post_data, code, resp_data
            )
        )
    return resp_data, code, headers


# ------------------------------------------------------------------------------


def get_authorization_challenge(authorization_response, http01=None):
    """
    :param dict authorization_response: (required) A Python dict representing a server's JSON payload of an Authorization Object.
    :param bool http01: (required) You must declare this is a http01 request
    """
    if not http01:
        raise ValueError("must invoke with `http01=True`")
    # find the http-01 challenge and write the challenge file
    try:
        challenge = [
            c for c in authorization_response["challenges"] if c["type"] == "http-01"
        ][0]
    except Exception as exc:
        raise ValueError("could not find a challenge")
    return challenge


def create_challenge_keyauthorization(token, accountkey_thumbprint):
    """
    :param str token: (required) A string `token` entry from a server Challenge object
    :param str accountkey_thumbprint: (required) The thumbprint of an Authenticated Account
    """
    token = re.sub(r"[^A-Za-z0-9_\-]", "_", token)
    keyauthorization = "{0}.{1}".format(token, accountkey_thumbprint)
    return keyauthorization


# ------------------------------------------------------------------------------


def acme_directory_get(acmeAccountKey=None):
    """
    Get the ACME directory of urls

    :param acmeAccountKey: (required) a :class:`model.objects.AcmeAccountKey` instance
    """
    log.info("acme_v2 Getting directory...")
    url_directory = acmeAccountKey.acme_account_provider_directory
    if not url_directory:
        raise ValueError("no directory for the CERTIFICATE_AUTHORITY!")
    directory_payload, _code, _headers = url_request(
        url_directory, err_msg="Error getting directory"
    )
    if not directory_payload:
        raise ValueError("no directory data for the CERTIFICATE_AUTHORITY")
    log.info("acme_v2 Directory found!")
    return directory_payload


# ------------------------------------------------------------------------------


def account_key__parse(account_key_path=None):
    """
    :param account_key_path: (required) the filepath to a PEM encoded RSA account key file.
    """
    log.info("acme_v2 Parsing account key...")
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
    :param response_headers: (required) The headers of the ACME Server's response
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
    acmeAccountKey = None
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
        acmeAccountKey=None,
        account_key_path=None,
        acme_directory=None,
        log__OperationsEvent=None,
    ):
        """
        :param acmeLogger: (required) A :class:`.logger.AcmeLogger` instance
        :param acmeAccountKey: (required) A :class:`model.objects.AcmeAccountKey` object
        :param account_key_path: (optional) The filepath of a PEM encoded RSA key
        :param acme_directory: (optional) The ACME Server's url for a "directory"
        :param log__OperationsEvent: (required) callable function to log the operations event
        """
        if not all((acmeLogger, acmeAccountKey, account_key_path)):
            raise ValueError(
                "all elements are required: (acmeLogger, acmeAccountKey, account_key_path)"
            )

        # do we need to load this?
        if acme_directory is None:
            acme_directory = acme_directory_get(acmeAccountKey)

        # parse account key to get public key
        (accountkey_jwk, accountkey_thumbprint, alg) = account_key__parse(
            account_key_path=account_key_path
        )

        # configure the object!
        self.acmeLogger = acmeLogger
        self.account_key_path = account_key_path
        self.acmeAccountKey = acmeAccountKey
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
        log.info("acme_v2 _poll_until_not {0}".format(_log_message))
        _result, _t0 = None, time.time()
        while _result is None or _result["status"] in _pending_statuses:
            assert time.time() - _t0 < 3600, "Polling timeout"  # 1 hour timeout
            time.sleep(0 if _result is None else 2)
            _result, _, _ = self._send_signed_request(_url, payload=None,)
        return _result

    def authenticate(self, ctx, contact=None):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param contact: (optional) The updated contact info

        returns:
            acme_account_object - ACME Server account object
            acme_account_headers - ACME Server account response headers

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
            (
                acme_account_object,
                code,
                acme_account_headers,
            ) = self._send_signed_request(
                self.acme_directory["newAccount"], payload=payload_registration
            )
            self._api_account_object = acme_account_object
            self._api_account_headers = acme_account_headers
        except Exception as exc:
            pdb.set_trace()
            raise

        log.info("acme_v2 Registered!" if code == 201 else "Already registered!")
        if contact is not None:
            raise ValueError("todo: log this")
            payload_contact = {"contact": contact}
            (acme_account_object, _, _) = self._send_signed_request(
                acme_account_headers["Location"], payload=payload_contact,
            )
            self._api_account_object = acme_account_object
            log.info(
                "acme_v2 Updated contact details:\n{0}".format(
                    "\n".join(acme_account_object["contact"])
                )
            )

        # this would raise if we couldn't authenticate
        self.acmeAccountKey.timestamp_last_authenticated = ctx.timestamp
        ctx.dbSession.flush(objects=[self.acmeAccountKey])

        # log this
        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict["acme_account_key.id"] = self.acmeAccountKey.id
        dbOperationsEvent = self.log__OperationsEvent(
            ctx,
            model_utils.OperationsEventType.from_string(
                "acme_account_key__authenticate"
            ),
            event_payload_dict,
        )

    def acme_order_load(self, ctx, dbAcmeOrder, transaction_commit=None):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param dbAcmeOrder: (required) a :class:`model.objects.AcmeOrder` instance
        """
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        if not dbAcmeOrder.resource_url:
            raise ValueError("the order does not have a `resource_url`")

        try:
            (acme_order_object, _code, acme_order_headers) = self._send_signed_request(
                dbAcmeOrder.resource_url, None
            )
            log.info("acme_v2 Order loaded!")
        except errors.AcmeServer404 as exc:
            # todo: not finished with this logic flow
            acme_order_object = {"status": "*404*"}
            raise

        # log the event to the db
        dbEventLogged = self.acmeLogger.log_order_load(
            "v2", dbAcmeOrder, transaction_commit=True
        )

        # this is just a convenience wrapper for our order object
        acmeOrderRfcObject = AcmeOrderRFC(
            rfc_object=acme_order_object,
            response_headers=acme_order_headers,
            AcmeOrderRFC=dbAcmeOrder.unique_fqdn_set,
        )

        return (acmeOrderRfcObject, dbEventLogged)

    def acme_order_new(
        self, ctx, domain_names=None, dbUniqueFQDNSet=None, transaction_commit=None,
    ):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param domain_names: (required) The domains for our order
        :param dbUniqueFQDNSet: (required) The :class:`model.objects.UniqueFQDNSet` associated with the order
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        returns
            acmeOrderRfcObject, dbEventLogged

        https://tools.ietf.org/html/rfc8555#section-7.4

            identifiers (required, array of object):  An array of identifier
            objects that the client wishes to submit an order for.

                type (required, string):  The type of identifier.

                value (required, string):  The identifier itself.

                notBefore (optional, string):  The requested value of the notBefore
                    field in the certificate, in the date format defined in [RFC3339].

                notAfter (optional, string):  The requested value of the notAfter
                    field in the certificate, in the date format defined in [RFC3339].

            Example - Request

                POST /acme/new-order HTTP/1.1
                Host: example.com
                Content-Type: application/jose+json

                {
                  "protected": base64url({
                    "alg": "ES256",
                    "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                    "nonce": "5XJ1L3lEkMG7tR6pA00clA",
                    "url": "https://example.com/acme/new-order"
                  }),
                  "payload": base64url({
                    "identifiers": [
                      { "type": "dns", "value": "www.example.org" },
                      { "type": "dns", "value": "example.org" }
                    ],
                    "notBefore": "2016-01-01T00:04:00+04:00",
                    "notAfter": "2016-01-08T00:04:00+04:00"
                  }),
                  "signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
                }

            Example - Response

                HTTP/1.1 201 Created
                Replay-Nonce: MYAuvOpaoIiywTezizk5vw
                Link: <https://example.com/acme/directory>;rel="index"
                Location: https://example.com/acme/order/TOlocE8rfgo

                {
                 "status": "pending",
                 "expires": "2016-01-05T14:09:07.99Z",

                 "notBefore": "2016-01-01T00:00:00Z",
                 "notAfter": "2016-01-08T00:00:00Z",

                 "identifiers": [
                   { "type": "dns", "value": "www.example.org" },
                   { "type": "dns", "value": "example.org" }
                 ],

                 "authorizations": [
                   "https://example.com/acme/authz/PAniVnsZcis",
                   "https://example.com/acme/authz/r4HqLzrSrpI"
                 ],

                 "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
                }
        """
        # create a new order
        log.info("acme_v2 Creating new order...")
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        payload_order = {
            "identifiers": [{"type": "dns", "value": d} for d in domain_names]
        }
        (acme_order_object, _code, acme_order_headers) = self._send_signed_request(
            self.acme_directory["newOrder"], payload=payload_order,
        )
        log.info("acme_v2 Order created!")

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

    def acme_order_process_authorizations(
        self,
        ctx,
        acmeOrderRfcObject=None,
        dbAcmeOrder=None,
        handle_authorization_payload=None,
        handle_challenge_setup=None,
        handle_challenge_cleanup=None,
        update_AcmeAuthorization_status=None,
        update_AcmeChallenge_status=None,
        transaction_commit=None,
    ):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param acmeOrderRfcObject: (required) A :class:`AcmeOrderRFC` object representing the server's response
        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the order

        :param handle_authorization_payload: (required) Callable function. expects (authorization_url, authorization_response, transaction_commit)
        :param handle_challenge_setup: (required) Callable function. expects (domain, token, keyauthorization, transaction_commit)
        :param handle_challenge_cleanup: (required) Callable function. expects (domain, token, keyauthorization, transaction_commit)
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        :param update_AcmeAuthorization_status: callable. expects (ctx, dbAcmeAuthorization, status_text, transaction_commit)
        :param update_AcmeChallenge_status: callable. expects (ctx, dbAcmeChallenge, status_text, transaction_commit)

        """
        log.info("acme_v2 acme_order_process_authorizations...")
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
                    "unsure how to handle this status: `%s`" % _order_status
                )

        # verify each domain
        for authorization_url in acmeOrderRfcObject.rfc_object["authorizations"]:
            auth_result = self.acme_authorization_process(
                ctx,
                authorization_url,
                handle_authorization_payload=handle_authorization_payload,
                handle_challenge_setup=handle_challenge_setup,
                handle_challenge_cleanup=handle_challenge_cleanup,
                update_AcmeAuthorization_status=update_AcmeAuthorization_status,
                update_AcmeChallenge_status=update_AcmeChallenge_status,
                transaction_commit=transaction_commit,
            )

        # no more domains!
        return True

    def acme_order_finalize(
        self,
        ctx,
        acmeOrderRfcObject=None,
        dbAcmeOrder=None,
        update_order_status=None,
        transaction_commit=None,
        # function specific
        csr_path=None,
    ):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param acmeOrderRfcObject: (required) A :class:`AcmeOrderRFC` object representing the server's response
        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` associated with the order
        :param update_order_status: (required) Callable function. expects (ctx, dbAcmeOrder, status, transaction_commit)
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        :param csr_path: (required) a
        """
        # get the new certificate
        log.info("acme_v2 acme_order_finalize")

        if transaction_commit is not True:
            # required for the `update_order_status`
            raise ValueError("we must invoke this knowing it will commit")

        if update_order_status is None:
            raise ValueError(
                "we must invoke this with a callable `update_order_status`"
            )

        # convert the certificate to a DER
        with psutil.Popen(
            [cert_utils.openssl_path, "req", "-in", csr_path, "-outform", "DER"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            csr_der, err = proc.communicate()
            if six.PY3:
                csr_der = csr_der.decode("utf8")

        acmeLoggedEvent = self.acmeLogger.log_order_finalize(
            "v2", transaction_commit=True
        )  # log this to the db

        payload_finalize = {"csr": _b64(csr_der)}
        try:
            (finalize_response, _, _) = self._send_signed_request(
                acmeOrderRfcObject.rfc_object["finalize"], payload=payload_finalize,
            )
        except Exception as exc:
            pdb.set_trace()
            raise

        # poll the order to monitor when it's done
        # url_order_status = acmeOrderRfcObject.response_headers["Location"]
        url_order_status = dbAcmeOrder.resource_url

        log.info("checking order {0}".format("order"))
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
            acme_order_finalized["status"],
            transaction_commit=transaction_commit,
        )

        url_certificate = acme_order_finalized.get("certificate")
        if not url_certificate:
            raise ValueError(
                "The AcmeOrder server response should have a `certificate`."
            )

        # download the certificate
        # ACME-V2 furnishes a FULLCHAIN (certificate_pem + chain_pem)
        (fullchain_pem, _, certificate_headers) = self._send_signed_request(
            url_certificate, None
        )

        log.info("acme_v2 recived signed Certificate!")

        return fullchain_pem

    def acme_authorization_process(
        self,
        ctx,
        authorization_url,
        handle_authorization_payload=None,
        handle_challenge_setup=None,
        handle_challenge_cleanup=None,
        update_AcmeAuthorization_status=None,
        update_AcmeChallenge_status=None,
        transaction_commit=None,
    ):
        """
        Process a single Authorization

        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param authorization_url: (required) The url of the authorization

        :param handle_authorization_payload: (required) Callable function. expects (authorization_url, authorization_response, transaction_commit)
        :param handle_challenge_setup: (required) Callable function. expects (domain, token, keyauthorization, transaction_commit)
        :param handle_challenge_cleanup: (required) Callable function. expects (domain, token, keyauthorization, transaction_commit)
        :param transaction_commit: (required) Boolean. Must indicate that we will invoke this outside of transactions

        :param update_AcmeAuthorization_status: callable. expects (ctx, dbAcmeAuthorization, status_text, transaction_commit)
        :param update_AcmeChallenge_status: callable. expects (ctx, dbAcmeChallenge, status_text, transaction_commit)

        Returns:

            True: Authorization Valid
            None: No Authorization Action

        If the challenge fails, we raise a `errors.DomainVerificationError`.

        ------------------------------------------------------------------------

        Authorizations

            https://tools.ietf.org/html/rfc8555#section-7.1.4

                status (required, string):  The status of this authorization.
                    Possible values are "pending", "valid", "invalid", "deactivated",
                    "expired", and "revoked".  See Section 7.1.6.

            https://tools.ietf.org/html/rfc8555#page-31

               Authorization objects are created in the "pending" state.  If one of
               the challenges listed in the authorization transitions to the "valid"
               state, then the authorization also changes to the "valid" state.  If
               the client attempts to fulfill a challenge and fails, or if there is
               an error while the authorization is still pending, then the
               authorization transitions to the "invalid" state.  Once the
               authorization is in the "valid" state, it can expire ("expired"), be
               deactivated by the client ("deactivated", see Section 7.5.2), or
               revoked by the server ("revoked").

            Therefore:

                "pending"
                    newly created
                "valid"
                    one or more challenges is valid
                "invalid"
                    a challenge failed
                "deactivated"
                    deactivated by the client
                "expired"
                    a valid challenge has expired
                "revoked"
                    revoked by the server

        Challenges

            https://tools.ietf.org/html/rfc8555#section-8

                status (required, string):  The status of this challenge.  Possible
                   values are "pending", "processing", "valid", and "invalid" (see
                   Section 7.1.6).

            https://tools.ietf.org/html/rfc8555#section-7.1.6

                Challenge objects are created in the "pending" state.  They
                transition to the "processing" state when the client responds to the
                challenge (see Section 7.5.1) and the server begins attempting to
                validate that the client has completed the challenge.  Note that
                within the "processing" state, the server may attempt to validate the
                challenge multiple times (see Section 8.2).  Likewise, client
                requests for retries do not cause a state change.  If validation is
                successful, the challenge moves to the "valid" state; if there is an
                error, the challenge moves to the "invalid" state.

            Therefore:

                "pending"
                    newly created
                "processing"
                    the client has responded to the challenge
                "valid"
                    the ACME server has validated the challenge
                "invalid"
                    the ACME server encountered an error when validating        """
        # scoping, our todo list
        _todo_complete_challenges = None
        _todo_complete_challenge_http01 = None

        # in v1, we know the domain before the authorization request
        # in v2, we hit an order's authorization url to get the domain
        (authorization_response, _, authorization_headers,) = self._send_signed_request(
            authorization_url, payload=None,
        )
        dbAcmeAuthorization = handle_authorization_payload(
            authorization_url, authorization_response, transaction_commit=True,
        )

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
            "acme_v2 Handling Authorization for {0}...".format(
                dbAcmeAuthorization.domain.domain_name
            )
        )

        _authorization_status = authorization_response["status"]
        if _authorization_status == "pending":
            # we need to run the authorization
            _todo_complete_challenges = True
        elif _authorization_status == "valid":
            # noting to do, one or more challenges is valid
            _todo_complete_challenges = False
        elif _authorization_status == "invalid":
            # this failed once, we need to auth again !
            _todo_complete_challenges = False
        elif _authorization_status == "deactivated":
            # this has been removed from the order?
            _todo_complete_challenges = False
        elif _authorization_status == "expired":
            # this passed once, BUT we need to auth again
            _todo_complete_challenges = True
        elif _authorization_status == "expired":
            # this failed once, we need to auth again?
            _todo_complete_challenges = True
        else:
            raise ValueError(
                "unexpected authorization status: `%s`" % _authorization_status
            )

        if not _todo_complete_challenges:
            # short-circuit out of completing the challenge
            return None

        # we could parse the challenge
        # however, the call to `process_discovered_auth` should have updated the challenge object already
        acme_challenge_response = get_authorization_challenge(
            authorization_response, http01=True
        )
        if not acme_challenge_response:
            raise ValueError(
                "`acme_challenge_response` not in `authorization_response`"
            )
        dbAcmeChallenge = dbAcmeAuthorization.acme_challenge_http01
        if acme_challenge_response["url"] != dbAcmeChallenge.challenge_url:
            raise ValueError(
                "`acme_challenge_response` has a different challenge_url. this is unexpected."
            )

        _challenge_status_text = (
            dbAcmeAuthorization.acme_challenge_http01.acme_status_challenge
        )
        if _challenge_status_text == "pending":
            _todo_complete_challenge_http01 = True
        elif _challenge_status_text == "processing":
            # we may need to trigger again?
            _todo_complete_challenge_http01 = True
        elif _challenge_status_text == "valid":
            # already completed
            _todo_complete_challenge_http01 = False
        elif _challenge_status_text == "invalid":
            # we may need to trigger again?
            _todo_complete_challenge_http01 = True
        else:
            raise ValueError(
                "unexpected challenge status: `%s`" % _challenge_status_text
            )

        if _todo_complete_challenge_http01:
            # acme_challenge_response
            keyauthorization = create_challenge_keyauthorization(
                dbAcmeChallenge.token, self.accountkey_thumbprint,
            )
            if dbAcmeChallenge.keyauthorization != keyauthorization:
                raise ValueError("This should never happen!")

            # update the db; this should be integrated with the above
            wellknown_path = handle_challenge_setup(
                dbAcmeAuthorization.domain.domain_name,
                dbAcmeChallenge.token,
                dbAcmeChallenge.keyauthorization,
                transaction_commit=True,
            )
            wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(
                dbAcmeAuthorization.domain.domain_name, dbAcmeChallenge.token,
            )

            # check that the file is in place
            try:
                if TESTING_ENVIRONMENT:
                    log.debug(
                        "TESTING_ENVIRONMENT, not ensuring the challenge is readable"
                    )
                else:
                    try:
                        resp = urlopen(wellknown_url)
                        resp_data = resp.read().decode("utf8").strip()
                        assert resp_data == keyauthorization
                    except (IOError, AssertionError):
                        handle_challenge_cleanup(
                            dbAcmeAuthorization.domain.domain_name,
                            dbAcmeChallenge.token,
                            keyauthorization,
                            transaction_commit=True,
                        )
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
            except (AssertionError, ValueError) as e:
                raise ValueError(
                    "Wrote file to {0}, but couldn't download {1}: {2}".format(
                        wellknown_path, wellknown_url, e
                    )
                )

            # note that we are about to trigger the challenge:
            self.acmeLogger.log_challenge_trigger(
                "v2", dbAcmeChallenge, transaction_commit=True,
            )
            # trigger the challenge!
            # if we had a 'valid' challenge, the payload would be `None`
            # to invoke a GET-as-POST functionality and load the challenge resource
            # POSTing an empty `dict` will trigger the challenge
            (challenge_response, _, _) = self._send_signed_request(
                dbAcmeChallenge.challenge_url, payload={},
            )
            if challenge_response["status"] != "pending":
                pdb.set_trace()
                raise ValueError("not pending!? how/!?")

            # todo - COULD an accepted challenge be here?
            log.info(
                "checking domain {0}".format(dbAcmeAuthorization.domain.domain_name)
            )
            authorization_response = self._poll_until_not(
                authorization_url,
                ["pending"],
                "checking challenge status for {0}".format(
                    dbAcmeAuthorization.domain.domain_name
                ),
            )
            if authorization_response["status"] == "valid":
                log.info(
                    "acme_v2 {0} verified!".format(
                        dbAcmeAuthorization.domain.domain_name
                    )
                )
                handle_challenge_cleanup(
                    dbAcmeAuthorization.domain.domain_name,
                    dbAcmeChallenge.token,
                    dbAcmeChallenge.keyauthorization,
                    transaction_commit=True,
                )

                # log this
                self.acmeLogger.log_challenge_pass(
                    "v2", dbAcmeChallenge, transaction_commit=True,
                )

                # update the authorization
                update_AcmeAuthorization_status(
                    ctx,
                    dbAcmeAuthorization,
                    authorization_response["status"],
                    transaction_commit=True,
                )

                # update the challenge
                acme_challenge_response_2 = get_authorization_challenge(
                    authorization_response, http01=True
                )
                if acme_challenge_response_2["url"] == dbAcmeChallenge.challenge_url:
                    update_AcmeChallenge_status(
                        ctx,
                        dbAcmeChallenge,
                        acme_challenge_response_2["status"],
                        transaction_commit=True,
                    )

                return True

            elif authorization_response["status"] != "valid":

                self.acmeLogger.log_challenge_error(
                    "v2", dbAcmeChallenge, "fail-2", transaction_commit=True,
                )

                # kill the authorization
                update_AcmeAuthorization_status(
                    ctx,
                    dbAcmeAuthorization,
                    authorization_response["status"],
                    transaction_commit=True,
                )

                # kill the challenge
                acme_challenge_response_2 = get_authorization_challenge(
                    authorization_response, http01=True
                )
                if acme_challenge_response_2["url"] == dbAcmeChallenge.challenge_url:
                    update_AcmeChallenge_status(
                        ctx,
                        dbAcmeChallenge,
                        acme_challenge_response_2["status"],
                        transaction_commit=True,
                    )

                raise errors.AcmeAuthorizationFailure(
                    "{0} challenge did not pass: {1}".format(
                        dbAcmeAuthorization.domain.domain_name, authorization_response,
                    )
                )

    def acme_authorization_load(
        self, ctx, dbAcmeAuthorization, transaction_commit=None
    ):
        """
        This loads the authorization object and pulls the payload
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param dbAcmeAuthorization: (required) a :class:`model.objects.AcmeAuthorization` instance
        """
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        if not dbAcmeAuthorization.authorization_url:
            raise ValueError("the order does not have a `resource_url`")

        try:
            (
                authorization_response,
                _,
                authorization_headers,
            ) = self._send_signed_request(dbAcmeAuthorization.authorization_url, None)
        except errors.AcmeServer404 as exc:
            authorization_response = {"status": "*404*"}

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
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param dbAcmeAuthorization: (required) a :class:`model.objects.AcmeAuthorization` instance

        https://tools.ietf.org/html/rfc8555#section-7.5.2

            7.5.2.  Deactivating an Authorization

               If a client wishes to relinquish its authorization to issue
               certificates for an identifier, then it may request that the server
               deactivate each authorization associated with it by sending POST
               requests with the static object {"status": "deactivated"} to each
               authorization URL.

        """
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        if not dbAcmeAuthorization.authorization_url:
            raise ValueError("the order does not have a `resource_url`")

        try:
            (
                authorization_response,
                _,
                authorization_headers,
            ) = self._send_signed_request(
                dbAcmeAuthorization.authorization_url, {"status": "deactivated"}
            )
        except errors.AcmeServer404 as exc:
            authorization_response = {"status": "*404*"}

        # log the event
        dbAcmeEventLog_authorization_fetch = self.acmeLogger.log_authorization_deactivate(
            "v2", dbAcmeAuthorization=dbAcmeAuthorization, transaction_commit=True,
        )  # log this to the db

        return (authorization_response, dbAcmeEventLog_authorization_fetch)

    def acme_challenge_load(self, ctx, dbAcmeChallenge, transaction_commit=None):
        """
        This loads the authorization object and pulls the payload
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param dbAcmeChallenge: (required) a :class:`model.objects.AcmeChallenge` instance
        """
        if transaction_commit is not True:
            # required for the `AcmeLogger`
            raise ValueError("we must invoke this knowing it will commit")

        if not dbAcmeChallenge.challenge_url:
            raise ValueError("the challenge does not have a `challenge_url`")

        try:
            (challenge_response, _, challenge_headers) = self._send_signed_request(
                dbAcmeChallenge.challenge_url, None
            )
        except errors.AcmeServer404 as exc:
            challenge_response = {"status": "*404*"}

        # log the event
        dbAcmeEventLog_challenge_fetch = self.acmeLogger.log_challenge_PostAsGet(
            "v2", dbAcmeChallenge=dbAcmeChallenge, transaction_commit=True,
        )  # log this to the db

        return (challenge_response, dbAcmeEventLog_challenge_fetch)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ()
