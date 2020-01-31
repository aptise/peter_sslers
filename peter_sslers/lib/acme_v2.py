from __future__ import print_function

import logging

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# stdlib
import base64
import binascii
import hashlib
import json
import re
import ssl
import subprocess
import time
import pdb

try:
    from urllib.request import urlopen, Request  # Python 3
except ImportError:
    from urllib2 import urlopen, Request  # Python 2


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


# helper function - make request and automatically parse json response
def url_request(url, post_data=None, err_msg="Error", depth=0):
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
    except IOError as e:
        resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
        code, headers = getattr(e, "code", None), {}
    try:
        resp_data = json.loads(resp_data)  # try to parse json results
    except ValueError:
        pass  # ignore json parsing errors
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


def acme_directory_get(acmeAccountKey=None):
    # get the ACME directory of urls
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
    log.info("acme_v2 Parsing account key...")
    proc = subprocess.Popen(
        [cert_utils.openssl_path, "rsa", "-in", account_key_path, "-noout", "-text"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate()
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(
        pub_pattern, out.decode("utf8"), re.MULTILINE | re.DOTALL
    ).groups()
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


class AcmeOrder(object):
    api_object = None
    response_headers = None
    dbCertificateRequest = None

    def __init__(
        self, api_object=None, response_headers=None, dbCertificateRequest=None
    ):
        self.api_object = api_object
        self.response_headers = response_headers
        self.dbCertificateRequest = dbCertificateRequest


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
    log__SslOperationsEvent = None

    _api_account_object = None  # api server native/json object
    _api_account_headers = None  # api server native/json object

    def __init__(
        self,
        acmeLogger=None,
        acmeAccountKey=None,
        account_key_path=None,
        acme_directory=None,
        log__SslOperationsEvent=None,
    ):
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
        self.log__SslOperationsEvent = log__SslOperationsEvent

    def _send_signed_request(self, url, payload=None, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
        new_nonce = url_request(self.acme_directory["newNonce"])[2]["Replay-Nonce"]
        protected = {"url": url, "alg": self.alg, "nonce": new_nonce}
        protected.update(
            {"jwk": self.accountkey_jwk}
            if self._api_account_headers is None
            else {"kid": self._api_account_headers["Location"]}
        )
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
        proc = subprocess.Popen(
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
        )
        out, err = proc.communicate(protected_input)
        if proc.returncode != 0:
            raise IOError("_send_signed_request\n{1}".format(err))
        data = json.dumps(
            {"protected": protected64, "payload": payload64, "signature": _b64(out)}
        )
        try:
            return url_request(
                url,
                post_data=data.encode("utf8"),
                err_msg="_send_signed_request",
                depth=depth,
            )
        except IndexError:  # retry bad nonces (they raise IndexError)
            return self._send_signed_request(url, payload=payload, depth=(depth + 1),)

    def _poll_until_not(self, _url, _pending_statuses, _log_message):
        log.info("acme_v2 _poll_until_not {0}".format(_log_message))
        _result, _t0 = None, time.time()
        while _result is None or _result["status"] in _pending_statuses:
            assert time.time() - _t0 < 3600, "Polling timeout"  # 1 hour timeout
            time.sleep(0 if _result is None else 2)
            _result, _, _ = self._send_signed_request(_url, payload=None,)
        return _result

    def authenticate(self, app_ctx, contact=None):
        """
        kwargs:
            app_ctx = app context.
            contact = updated contact info

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
        self.acmeLogger.log_registration("v2")

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
        self.acmeAccountKey.timestamp_last_authenticated = app_ctx.timestamp
        app_ctx.dbSession.flush(objects=[self.acmeAccountKey])

        # log this
        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict["ssl_acme_account_key.id"] = self.acmeAccountKey.id
        dbOperationsEvent = self.log__SslOperationsEvent(
            app_ctx,
            model_utils.SslOperationsEventType.from_string(
                "acme_account_key__authenticate"
            ),
            event_payload_dict,
        )

    def acme_new_order(
        self, csr_domains=None, dbCertificateRequest=None,
    ):
        """
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

        # log the event to the db
        self.acmeLogger.log_newOrder("v2", dbCertificateRequest)

        payload_order = {
            "identifiers": [{"type": "dns", "value": d} for d in csr_domains]
        }
        (acme_order_object, _code, acme_order_headers) = self._send_signed_request(
            self.acme_directory["newOrder"], payload=payload_order,
        )
        log.info("acme_v2 Order created!")
        acmeOrder = AcmeOrder(
            api_object=acme_order_object,
            response_headers=acme_order_headers,
            dbCertificateRequest=dbCertificateRequest,
        )
        return acmeOrder

    def acme_handle_order_authorizations(
        self,
        acmeOrder=None,  # acme server api response, `AcmeOrder` object
        handle_keyauth_challenge=None,  # callable; expects (domain, token, keyauthorization)
        handle_keyauth_cleanup=None,  # callable; expects (domain, token, keyauthorization)
    ):
        log.info("acme_v2 acme_handle_order_authorizations...")

        _order_status = acmeOrder.api_object["status"]
        if _order_status != "pending":
            raise ValueError("unsure how to handle this status: `%s`" % _order_status)

        # verify each domain
        for authorization_url in acmeOrder.api_object["authorizations"]:

            # in v1, we know the domain before the authorization request
            # in v2, we hit an order's authorization url to get the domain
            (authorization_response, _, _) = self._send_signed_request(
                authorization_url, payload=None,
            )
            domain = authorization_response["identifier"]["value"]
            log.info("acme_v2 Verifying {0}...".format(domain))

            """
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
            """
            _authorization_status = authorization_response["status"]
            _todo_complete_challenge = None
            if _authorization_status == "pending":
                # we need to run the authorization
                _todo_complete_challenge = True
            elif _authorization_status == "valid":
                # noting to do, one or more challenges is valid
                _todo_complete_challenge = False
            elif _authorization_status == "invalid":
                # this failed once, we need to auth again?
                _todo_complete_challenge = True
            elif _authorization_status == "deactivated":
                # this has been removed from the order?
                _todo_complete_challenge = False
            elif _authorization_status == "expired":
                # this passed once, BUT we need to auth again
                _todo_complete_challenge = True
            elif _authorization_status == "expired":
                # this failed once, we need to auth again?
                _todo_complete_challenge = True
            else:
                raise ValueError(
                    "unexpected authorization status: `%s`" % _authorization_status
                )

            if not _todo_complete_challenge:
                # short-circuit out of completing the challenge
                continue

            (
                sslAcmeEventLog_new_authorization,
                sslAcmeChallengeLog,
            ) = self.acmeLogger.log_new_authorization(
                "v2", acmeOrder.dbCertificateRequest, domain=domain
            )  # log this to the db

            # find the http-01 challenge and write the challenge file
            try:
                challenge = [
                    c
                    for c in authorization_response["challenges"]
                    if c["type"] == "http-01"
                ][0]
            except Exception as exc:
                raise ValueError("could not find a challenge")

            """
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
                    the ACME server encountered an error when validating
            """
            _challenge_status = challenge["status"]
            _todo_complete_challenge = None

            if _challenge_status == "pending":
                _todo_complete_challenge = True
            elif _challenge_status == "processing":
                # we may need to trigger again?
                _todo_complete_challenge = True
            elif _challenge_status == "valid":
                # already completed
                _todo_complete_challenge = False
            elif _challenge_status == "invalid":
                # we may need to trigger again?
                _todo_complete_challenge = True
            else:
                raise ValueError(
                    "unexpected challenge status: `%s`" % _challenge_status
                )

            if _todo_complete_challenge:
                token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
                keyauthorization = "{0}.{1}".format(token, self.accountkey_thumbprint)

                # update the challenge
                sslAcmeChallengeLog.set__challenge("http-01", keyauthorization)

                # update the db; this should be integrated with the above
                wellknown_path = handle_keyauth_challenge(
                    domain, token, keyauthorization
                )
                wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(
                    domain, token
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
                            handle_keyauth_cleanup(domain, token, keyauthorization)
                            self.acmeLogger.log_challenge_error(
                                sslAcmeChallengeLog, "pretest-1"
                            )
                            raise errors.DomainVerificationError(
                                "Wrote keyauth challenge, but couldn't download {0}".format(
                                    wellknown_url
                                )
                            )
                        except ssl.CertificateError as exc:
                            self.acmeLogger.log_challenge_error(
                                sslAcmeChallengeLog, "pretest-2"
                            )
                            if exc.message.startswith("hostname") and (
                                "doesn't match" in exc.message
                            ):
                                raise errors.DomainVerificationError(
                                    "Wrote keyauth challenge, but ssl can't view {0}. `%s`".format(
                                        wellknown_url, exc.message
                                    )
                                )
                            raise
                except (AssertionError, ValueError) as e:
                    raise ValueError(
                        "Wrote file to {0}, but couldn't download {1}: {2}".format(
                            wellknown_path, wellknown_url, e
                        )
                    )

                # note the challenge
                self.acmeLogger.log_challenge_trigger(sslAcmeChallengeLog)

                # if we had a 'valid' challenge, the payload would be `None`
                # to trigger a GET-as-POST functionality
                (challenge_response, _, _) = self._send_signed_request(
                    challenge["url"], payload={},
                )

                # todo - would an accepted challenge require this?
                log.info("checking domain {0}".format(domain))
                authorization_response = self._poll_until_not(
                    authorization_url,
                    ["pending"],
                    "checking challenge status for {0}".format(domain),
                )
                if authorization_response["status"] == "valid":
                    log.info("acme_v2 {0} verified!".format(domain))
                    handle_keyauth_cleanup(domain, token, keyauthorization)
                elif authorization_response["status"] != "valid":
                    self.acmeLogger.log_challenge_error(sslAcmeChallengeLog, "fail-2")
                    raise errors.DomainVerificationError(
                        "{0} challenge did not pass: {1}".format(
                            domain, authorization_response
                        )
                    )

                # log this
                self.acmeLogger.log_challenge_pass(sslAcmeChallengeLog)

        # no more domains!
        return True

    def acme_finalize_order(
        self,
        acmeOrder=None,  # acme server api response, `AcmeOrder` object
        # function specific
        csr_path=None,
    ):
        # get the new certificate
        log.info("acme_v2 acme_finalize_order")

        # convert the certificate to a DER
        proc = subprocess.Popen(
            [cert_utils.openssl_path, "req", "-in", csr_path, "-outform", "DER"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        csr_der, err = proc.communicate()

        acmeLoggedEvent = self.acmeLogger.log_order_finalize(
            "v2", acmeOrder.dbCertificateRequest
        )  # log this to the db

        payload_finalize = {"csr": _b64(csr_der)}
        try:
            (finalize_response, _, _) = self._send_signed_request(
                acmeOrder.api_object["finalize"], payload=payload_finalize,
            )
        except Exception as exc:
            pdb.set_trace()
            raise

        # poll the order to monitor when it's done
        url_order_status = acmeOrder.response_headers["Location"]

        log.info("checking order {0}".format("order"))
        acme_order_finalized = self._poll_until_not(
            url_order_status, ["pending", "processing"], "Error checking order status"
        )
        if acme_order_finalized["status"] != "valid":
            raise errors.AcmeCommunicationError(
                "Order failed: {0}".format(acme_order_finalized)
            )

        # download the certificate
        # ACME-V2 furnishes a FULLCHAIN (certificate_pem + chain_pem)
        (fullchain_pem, _, certificate_headers) = self._send_signed_request(
            acme_order_finalized["certificate"], None
        )

        log.info("acme_v2 Certificate signed!")

        """

        # return signed certificate!
        # openssl x509 -inform der -in issuer-cert -out issuer-cert.pem
        """

        return (
            fullchain_pem,
            acmeLoggedEvent,
        )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ()
