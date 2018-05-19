import logging
log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# stdlib
import base64
import binascii
import copy
import hashlib
import json
import re
import ssl
import subprocess
import tempfile
import textwrap
import time
try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2

# pypi
from dateutil import parser as dateutil_parser

# localapp
from . import cert_utils
from . import errors
from . import utils
from . import letsencrypt_info


# ==============================================================================


_DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
CERTIFICATE_AUTHORITY = _DEFAULT_CA
CERTIFICATE_AUTHORITY_AGREEMENT = 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'
TESTING_ENVIRONMENT = False


# ==============================================================================


def my_urlopen(url, *args):
    if TESTING_ENVIRONMENT:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urlopen(url, *args, context=ctx)
    else:
        resp = urlopen(url, *args)
    return resp


# helper function base64 encode for jose spec
def _b64(b):
    return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")


# helper function make signed requests
def _send_signed_request(url, payload, account_key_path, header):
    payload64 = _b64(json.dumps(payload).encode("utf8"))
    protected = copy.deepcopy(header)
    resp_directory = my_urlopen(CERTIFICATE_AUTHORITY + "/directory")
    protected["nonce"] = resp_directory.headers["Replay-Nonce"]
    protected64 = _b64(json.dumps(protected).encode("utf8"))
    proc = subprocess.Popen([cert_utils.openssl_path, "dgst", "-sha256", "-sign", account_key_path],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode("utf8"))
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    data = json.dumps({"header": header,
                       "protected": protected64,
                       "payload": payload64,
                       "signature": _b64(out),
                       })
    try:
        resp = my_urlopen(url, data.encode("utf8"))
        return resp.getcode(), resp.read(), resp.info()
    except IOError as e:
        return getattr(e, "code", None), getattr(e, "read", e.__str__)(), None


def account_key__header_thumbprint(
    account_key_path=None
):
    log.info("Parsing account key...")
    proc = subprocess.Popen([cert_utils.openssl_path, "rsa", "-in", account_key_path, "-noout", "-text"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode("utf8"), re.MULTILINE | re.DOTALL
    ).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {"alg": "RS256",
              "jwk": {"e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
                      "kty": "RSA",
                      "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
                      },
              }
    accountkey_json = json.dumps(header["jwk"], sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())

    return header, thumbprint


def acme_register_account(
    header=None,
    account_key_path=None,
    acmeLogger=None,  # an instance of AcmeLogger
):
    log.info("Registering account...")
    acmeLogger.log_registration()  # log this to the db
    code, result, headers = _send_signed_request(
        CERTIFICATE_AUTHORITY + "/acme/new-reg",
        {"resource": "new-reg",
         "agreement": CERTIFICATE_AUTHORITY_AGREEMENT,
         },
        account_key_path,
        header,
    )
    if code == 201:
        log.info("Registered!")
    elif code == 409:
        log.info("Already registered!")
    else:
        raise errors.AcmeCommunicationError("Error registering: {0} {1}".format(code, result))
    return True


def acme_verify_domains(
    csr_domains=None,
    account_key_path=None,
    handle_keyauth_challenge=None,
    handle_keyauth_cleanup=None,
    thumbprint=None,
    header=None,
    acmeLogger=None,  # an instance of AcmeLogger
):
    """
    """

    # verify each domain
    for domain in csr_domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        (sslAcmeEventLog_new_authz,
         sslAcmeChallengeLog
         ) = acmeLogger.log_new_authz(domain=domain)  # log this to the db
        code, result, headers = _send_signed_request(
            CERTIFICATE_AUTHORITY + "/acme/new-authz",
            {"resource": "new-authz",
             "identifier": {"type": "dns",
                            "value": domain
                            },
             },
            account_key_path,
            header,
        )
        if code != 201:
            raise errors.AcmeCommunicationError("Error requesting challenges: {0} {1}".format(code, result))

        # make the challenge file
        challenge = [c for c in json.loads(result.decode("utf8"))["challenges"] if c["type"] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
        keyauthorization = "{0}.{1}".format(token, thumbprint)

        # update the challenge
        sslAcmeChallengeLog.set__challenge("http-01", keyauthorization)

        # update the db; this should be integrated with the above
        wellknown_path = handle_keyauth_challenge(domain, token, keyauthorization)

        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        if TESTING_ENVIRONMENT:
            print("TESTING_ENVIRONMENT, not ensuring the challenge is readable")
        else:
            try:
                resp = urlopen(wellknown_url)
                resp_data = resp.read().decode("utf8").strip()
                assert resp_data == keyauthorization
            except (IOError, AssertionError):
                handle_keyauth_cleanup(domain, token, keyauthorization)
                acmeLogger.log_challenge_error(sslAcmeChallengeLog, 'pretest-1')
                raise errors.DomainVerificationError("Wrote keyauth challenge, but couldn't download {0}".format(wellknown_url))
            except ssl.CertificateError as e:
                acmeLogger.log_challenge_error(sslAcmeChallengeLog, 'pretest-2')
                if e.message.startswith('hostname') and ("doesn't match" in e.message):
                    raise errors.DomainVerificationError("Wrote keyauth challenge, but ssl can't view {0}. `%s`".format(wellknown_url, e.message))
                raise

        # note the challenge
        acmeLogger.log_challenge_trigger(sslAcmeChallengeLog)
        # if all challenges are active, trigger validation from LetsEncrypt
        code, result, headers = _send_signed_request(
            challenge["uri"],
            {"resource": "challenge",
             "keyAuthorization": keyauthorization,
             },
            account_key_path,
            header,
        )
        if code != 202:
            raise errors.AcmeCommunicationError("Error triggering challenge: {0} {1}".format(code, result))

        # wait for challenge to be verified
        # this just pings LetsEncrypt every 2 seconds
        while True:
            try:
                acmeLogger.log_challenge_polled(sslAcmeChallengeLog)
                resp = urlopen(challenge["uri"])
                challenge_status = json.loads(resp.read().decode("utf8"))
            except IOError as e:
                acmeLogger.log_challenge_error(sslAcmeChallengeLog, 'fail-1')
                raise errors.AcmeCommunicationError("Error checking challenge: {0} {1}".format(e.code, json.loads(e.read().decode("utf8"))))
            if challenge_status["status"] == "pending":
                time.sleep(2)
            elif challenge_status["status"] == "valid":
                log.info("{0} verified!".format(domain))
                handle_keyauth_cleanup(domain, token, keyauthorization)
                break
            else:
                acmeLogger.log_challenge_error(sslAcmeChallengeLog, 'fail-2')
                raise errors.DomainVerificationError("{0} challenge did not pass: {1}".format(domain, challenge_status))
        acmeLogger.log_challenge_pass(sslAcmeChallengeLog)
    return True


def acme_sign_certificate(
    account_key_path=None,
    csr_path=None,
    header=None,
):
    # get the new certificate
    log.info("Signing certificate...")
    proc = subprocess.Popen([cert_utils.openssl_path, "req", "-in", csr_path, "-outform", "DER"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()

    acmeLoggedEvent = acmeLogger.log_new_cert()  # log this to the db
    code, result, headers = _send_signed_request(
        CERTIFICATE_AUTHORITY + "/acme/new-cert",
        {"resource": "new-cert",
         "csr": _b64(csr_der),
         },
        account_key_path,
        header,
    )
    if code != 201:
        raise errors.AcmeCommunicationError("Error signing certificate: {0} {1}".format(code, result))

    # format as PEM
    log.info("Certificate signed!")
    cert_pem_text = """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode("utf8"), 64)))

    chained_pem_text = None
    chain_url = re.match("\\s*<([^>]+)>;rel=\"up\"", headers["Link"])
    if chain_url:
        chain_url = chain_url.group(1)
        resp = urlopen(chain_url)
        chain_data = resp.read()
        try:
            # store some data in a tempfile
            _tmpfile_chain = tempfile.NamedTemporaryFile()
            _tmpfile_chain.write(chain_data)
            _tmpfile_chain.seek(0)
            chain_format = cert_utils.probe_cert__format(_tmpfile_chain.name)
            if chain_format == 'pem':
                chained_pem_text = chain_data
            elif chain_format == 'der':
                chained_pem_text = cert_utils.convert_der_to_pem(der_data=chain_data)
        finally:
            _tmpfile_chain.close()
    if not chained_pem_text:
        raise ValueError("could not load text from `%s`" % chain_url)

    datetime_signed = dateutil_parser.parse(headers["Date"])
    datetime_expires = dateutil_parser.parse(headers["Expires"])

    # we need to make these naive
    datetime_signed = datetime_signed.replace(tzinfo=None)
    datetime_expires = datetime_expires.replace(tzinfo=None)

    # return signed certificate!

    # openssl x509 -inform der -in issuer-cert -out issuer-cert.pem

    return cert_pem_text, chained_pem_text, chain_url, datetime_signed, datetime_expires, acmeLoggedEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ('account_key__header_thumbprint',
           'acme_register_account',
           'acme_verify_domains',
           'acme_sign_certificate',
           )
