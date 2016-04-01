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
import pdb
import re
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

from . import errors
from . import utils
from . import letsencrypt_info


_DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"

CERTIFICATE_AUTHORITY = _DEFAULT_CA
openssl_path = "openssl"
openssl_path_conf = "/etc/ssl/openssl.cnf"

# ==============================================================================


# helper function base64 encode for jose spec
def _b64(b):
    return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")


# helper function make signed requests
def send_signed_request(url, payload, account_key_path, header):
    payload64 = _b64(json.dumps(payload).encode("utf8"))
    protected = copy.deepcopy(header)
    protected["nonce"] = urlopen(CERTIFICATE_AUTHORITY + "/directory").headers["Replay-Nonce"]
    protected64 = _b64(json.dumps(protected).encode("utf8"))
    proc = subprocess.Popen([openssl_path, "dgst", "-sha256", "-sign", account_key_path],
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
        resp = urlopen(url, data.encode("utf8"))
        return resp.getcode(), resp.read(), resp.info()
    except IOError as e:
        return getattr(e, "code", None), getattr(e, "read", e.__str__)(), None


def new_csr_for_domain_names(
    domain_names,
    private_key_path,
    tmpfiles_tracker,
):
    max_domains_certificate = letsencrypt_info.LIMITS['names/certificate']['limit']

    if len(domain_names) == 1:
        _csr_subject = "/CN=%s" % domain_names[0]
        proc = subprocess.Popen([openssl_path, "req", "-new", "-sha256", "-key", private_key_path, "-subj", _csr_subject],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        csr_text, err = proc.communicate()
        if err:
            raise errors.OpenSslError_CsrGeneration("could not create a CSR")

    elif len(domain_names) <= max_domains_certificate:

        # getting subprocess to work right is a pain, because we need to chain a bunch of commands
        # to get around this, we'll do two things:
        # 1. cat the [SAN] and openssl path file onto a tempfile
        # 2. use shell=True
        
        domain_names = sorted(domain_names)

        # generate the [SAN]
        _csr_san = "[SAN]\nsubjectAltName=" + ",".join(["DNS:%s" % d for d in domain_names])

        # store some data in a tempfile
        tmpfile_csr_san = tempfile.NamedTemporaryFile()
        tmpfile_csr_san.write(open(openssl_path_conf).read())
        tmpfile_csr_san.write("\n\n")
        tmpfile_csr_san.write(_csr_san)
        tmpfile_csr_san.seek(0)
        tmpfiles_tracker.append(tmpfile_csr_san)

        # note that we use /bin/cat (!)
        _command = """%s req -new -sha256 -key %s -subj "/" -reqexts SAN -config < /bin/cat %s""" % (openssl_path, private_key_path, tmpfile_csr_san.name)
        proc = subprocess.Popen(_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        csr_text, err = proc.communicate()
        if err:
            raise errors.OpenSslError_CsrGeneration("could not create a CSR")

        csr_text = cleanup_pem_text(csr_text)

    else:
        raise ValueError("LetsEncrypt can only allow `%s` domains per certificate" % max_domains_certificate)

    return csr_text


def account_key__header_thumbprint(
    account_key_path=None
):
    log.info("Parsing account key...")
    proc = subprocess.Popen([openssl_path, "rsa", "-in", account_key_path, "-noout", "-text"],
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


def parse_cert_domains(
    cert_path=None,
):
    subject_domain, san_domains = parse_cert_domains__segmented(cert_path=cert_path)
    if subject_domain is not None and subject_domain not in san_domains:
        san_domains.insert(0, subject_domain)
    return san_domains


def parse_cert_domains__segmented(
    cert_path=None,
):
    log.info("Parsing CERT...")
    proc = subprocess.Popen([openssl_path, "x509", "-in", cert_path, "-noout", "-text"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(cert_path, err))

    # init
    subject_domain = None
    san_domains = set([])  # convert to list on return

    _common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out.decode("utf8"))
    if _common_name is not None:
        subject_domain = _common_name.group(1).lower()
    _subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode("utf8"), re.MULTILINE | re.DOTALL)
    if _subject_alt_names is not None:
        for _san in _subject_alt_names.group(1).split(", "):
            if _san.startswith("DNS:"):
                san_domains.add(_san[4:].lower())
    return subject_domain, list(san_domains)


def parse_csr_domains(
    csr_path=None,
    submitted_domain_names=None,
):
    """checks found names against `submitted_domain_names`
    """
    log.info("Parsing CSR...")
    proc = subprocess.Popen([openssl_path, "req", "-in", csr_path, "-noout", "-text"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(csr_path, err))
    found_domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out.decode("utf8"))
    if common_name is not None:
        found_domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode("utf8"), re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                found_domains.add(san[4:])

    # ensure our CERT matches our submitted_domain_names
    if submitted_domain_names is not None:
        for domain in found_domains:
            if domain not in submitted_domain_names:
                raise ValueError("domain not in submitted_domain_names")
        for domain in submitted_domain_names:
            if domain not in found_domains:
                raise ValueError("domain not in found_domains")

    return found_domains


def acme_register_account(
    header=None,
    account_key_path=None
):
    log.info("Registering account...")
    code, result, headers = send_signed_request(
        CERTIFICATE_AUTHORITY + "/acme/new-reg",
        {"resource": "new-reg",
         "agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf",
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
):

    # verify each domain
    for domain in csr_domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result, headers = send_signed_request(
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
        wellknown_path = handle_keyauth_challenge(domain, token, keyauthorization)

        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode("utf8").strip()
            assert resp_data == keyauthorization
        except (IOError, AssertionError):
            handle_keyauth_cleanup(domain, token, keyauthorization)
            raise errors.DomainVerificationError("Wrote keyauth challenge, but couldn't download {0}".format(wellknown_url))

        # notify challenge are met
        code, result, headers = send_signed_request(
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
        while True:
            try:
                resp = urlopen(challenge["uri"])
                challenge_status = json.loads(resp.read().decode("utf8"))
            except IOError as e:
                raise errors.AcmeCommunicationError("Error checking challenge: {0} {1}".format(e.code, json.loads(e.read().decode("utf8"))))
            if challenge_status["status"] == "pending":
                time.sleep(2)
            elif challenge_status["status"] == "valid":
                log.info("{0} verified!".format(domain))
                handle_keyauth_cleanup(domain, token, keyauthorization)
                break
            else:
                raise errors.DomainVerificationError("{0} challenge did not pass: {1}".format(domain, challenge_status))
    return True


def acme_sign_certificate(
    account_key_path=None,
    csr_path=None,
    header=None,
):
    # get the new certificate
    log.info("Signing certificate...")
    proc = subprocess.Popen([openssl_path, "req", "-in", csr_path, "-outform", "DER"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    code, result, headers = send_signed_request(
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
            chain_format = probe_cert__format(_tmpfile_chain.name)
            if chain_format == 'pem':
                chained_pem_text = chain_data
            elif chain_format == 'der':
                chained_pem_text = convert_der_to_pem(der_data=chain_data)
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

    return cert_pem_text, chained_pem_text, chain_url, datetime_signed, datetime_expires


def cleanup_pem_text(pem_text):
    """ensures a trailing newline
    """
    pem_text = pem_text.strip() + "\n"
    return pem_text


def validate_key__pem_filepath(pem_filepath):
    # openssl rsa -in {KEY} -check
    proc = subprocess.Popen([openssl_path, "rsa", "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidKey(err)
    return True


def validate_csr__pem_filepath(pem_filepath):
    # openssl req -text -noout -verify -in {CSR}
    proc = subprocess.Popen([openssl_path, "req", "-text", "-noout", "-verify", "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCSR(err)
    return True


def validate_cert__pem_filepath(pem_filepath):
    # openssl x509 -in {CERTIFICATE} -inform pem -noout -text
    proc = subprocess.Popen([openssl_path, "x509", "-in", pem_filepath, "-inform", "pem", "-noout", "-text"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCertificate(err)
    return True


def validate_cert__der_filepath(der_filepath):
    # openssl x509 -in {CERTIFICATE} -inform der -noout -text
    proc = subprocess.Popen([openssl_path, "x509", "-in", der_filepath, "-inform", "der", "-noout", "-text"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCertificate(err)
    return True


def modulus_md5_key__pem_filepath(pem_filepath):
    # openssl rsa -noout -modulus -in {KEY} | openssl md5
    proc = subprocess.Popen([openssl_path, "rsa", "-noout", "-modulus", "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError(err)
    data = data.strip()
    return utils.md5_text(data)


def modulus_md5_csr__pem_filepath(pem_filepath):
    # openssl req -noout -modulus -in {CSR} | openssl md5
    proc = subprocess.Popen([openssl_path, "req", "-noout", "-modulus", "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCSR(err)
    data = data.strip()
    return utils.md5_text(data)


def modulus_md5_cert__pem_filepath(pem_filepath):
    # openssl x509 -noout -modulus -in {CERT} | openssl md5
    proc = subprocess.Popen([openssl_path, "x509", "-noout", "-modulus", "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCertificate(err)
    data = data.strip()
    return utils.md5_text(data)


def cert_single_op__pem_filepath(pem_filepath, single_op):
    """handles a single pem operation to `openssl x509`

        openssl x509 -noout -issuer_hash -in {CERT}
        returns the data found in
           X509v3 extensions:
               X509v3 Authority Key Identifier:
                   keyid:{VALUE}

        openssl x509 -noout -subject_hash -in {CERT}
        returns the data found in
           X509v3 extensions:
               X509v3 Subject Key Identifier:
                   {VALUE}
    """
    if single_op not in ('-issuer_hash', '-issuer', '-subject_hash', '-subject', '-startdate', '-enddate'):
        raise ValueError('invalid `single_op`')

    proc = subprocess.Popen([openssl_path, "x509", "-noout", single_op, "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCertificate(err)
    data = data.strip()
    return data


def key_single_op__pem_filepath(pem_filepath, single_op):
    """handles a single pem operation to `openssl rsa`

        openssl rsa -noout -check -in {KEY}
        openssl rsa -noout -modulus -in {KEY}
        openssl rsa -noout -text -in {KEY}

    """
    if single_op not in ('-check', '-modulus', '-text'):
        raise ValueError('invalid `single_op`')

    proc = subprocess.Popen([openssl_path, "rsa", "-noout", single_op, "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCertificate(err)
    data = data.strip()
    return data


def parse_enddate_cert__pem_filepath(pem_filepath):
    # openssl x509 -enddate -noout -in {CERT}
    proc = subprocess.Popen([openssl_path, "x509", "-enddate", "-noout", "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCertificate(err)
    if data[:9] != 'notAfter=':
        raise errors.OpenSslError_InvalidCertificate('unexpected format')
    data_date = data[9:]
    date = dateutil_parser.parse(data_date)
    date = date.replace(tzinfo=None)
    return date


def parse_startdate_cert__pem_filepath(pem_filepath):
    # openssl x509 -startdate -noout -in {CERT}
    proc = subprocess.Popen([openssl_path, "x509", "-startdate", "-noout", "-in", pem_filepath],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = proc.communicate()
    if not data:
        raise errors.OpenSslError_InvalidCertificate(err)
    if data[:10] != 'notBefore=':
        raise errors.OpenSslError_InvalidCertificate('unexpected format')
    data_date = data[10:]
    date = dateutil_parser.parse(data_date)
    date = date.replace(tzinfo=None)
    return date


def convert_der_to_pem(der_data=None):
    # PEM is just a b64 encoded DER certificate with the header/footer (FOR REAL!)
    as_pem = """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(der_data).decode('utf8'), 64)))
    return as_pem


def convert_pem_to_der(pem_data=None):
    # PEM is just a b64 encoded DER certificate with the header/footer (FOR REAL!)
    lines = [l.strip() for l in pem_data.strip().split('\n')]
    # remove the BEGIN CERT
    if 'BEGIN CERTIFICATE' in lines[0]:
        lines = lines[1:]
    if 'END CERTIFICATE' in lines[-1]:
        lines = lines[:-1]
    lines = ''.join(lines)
    result = base64.b64decode(lines)
    return result


def probe_cert__format(filepath):
    """returns "der" or "pem" (lowercase)"""
    try:
        validate_cert__pem_filepath(filepath)
        return "pem"
    except errors.OpenSslError_InvalidCertificate, e:
        validate_cert__der_filepath(filepath)
        return "der"
    except errors.OpenSslError_InvalidCertificate, e:
        raise errors.OpenSslError_InvalidCertificate("not PEM or DER")


CA_CERTS_DATA = [{'name': "ISRG Root X1",
                  'url_pem': "https://letsencrypt.org/certs/isrgrootx1.pem",
                  'is_ca_certificate': True,
                  'formfield_base': 'isrgrootx1',
                  },
                 {'name': "Let's Encrypt Authority X1 (IdenTrust cross-signed)",
                  'url_pem': "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem",
                  'le_authority_name': "Let's Encrypt Authority X1",
                  'is_authority_certificate': True,
                  'is_cross_signed_authority_certificate': True,
                  'formfield_base': 'le_x1_cross_signed',
                  },
                 {'name': "Let's Encrypt Authority X1",
                  'url_pem': "https://letsencrypt.org/certs/letsencryptauthorityx1.pem",
                  'le_authority_name': "Let's Encrypt Authority X1",
                  'is_authority_certificate': True,
                  'is_cross_signed_authority_certificate': False,
                  'formfield_base': 'le_x1_auth',
                  },
                 {'name': "Let's Encrypt Authority X2 (IdenTrust cross-signed)",
                  'url_pem': "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem",
                  'le_authority_name': "Let's Encrypt Authority X2",
                  'is_authority_certificate': True,
                  'is_cross_signed_authority_certificate': True,
                  'formfield_base': 'le_x2_cross_signed',
                  },
                 {'name': "Let's Encrypt Authority X2",
                  'url_pem': "https://letsencrypt.org/certs/letsencryptauthorityx2.pem",
                  'le_authority_name': "Let's Encrypt Authority X2",
                  'is_authority_certificate': True,
                  'is_cross_signed_authority_certificate': False,
                  'formfield_base': 'le_x1_auth',
                  },
                 ]


def probe_letsencrypt_certificates():
    """last checked 2016.03.24
    probes the known LetsEncrypt certificates
    THIS DOES NOT APPLY `cleanup_pem_text`
    """
    certs = copy.deepcopy(CA_CERTS_DATA)
    tmpfile = None
    try:
        for c in certs:
            resp = urlopen(c['url_pem'])
            if resp.getcode() != 200:
                raise ValueError("Could not load certificate")
            cert_pem_text = resp.read()
            cert_pem_text = cleanup_pem_text(cert_pem_text)
            c['cert_pem'] = cert_pem_text
            c['cert_pem_md5'] = utils.md5_text(cert_pem_text)
    finally:
        if tmpfile:
            tmpfile.close()

    return certs


def parse_key(key_pem=None, pem_filepath=None):
    if not any((key_pem, pem_filepath)) or all((key_pem, pem_filepath)):
        raise ValueError("only submit `key_pem` OR `pem_filepath`")

    tmpfile_pem = None
    try:
        if pem_filepath:
            raise NotImplemented
        else:
            tmpfile_pem = tempfile.NamedTemporaryFile()
            tmpfile_pem.write(key_pem)
            tmpfile_pem.seek(0)
            pem_filepath = tmpfile_pem.name

        rval = {}
        rval['modulus'] = key_single_op__pem_filepath(pem_filepath, '-modulus')
        rval['check'] = key_single_op__pem_filepath(pem_filepath, '-check')
        rval['text'] = key_single_op__pem_filepath(pem_filepath, '-text')
        return rval
    except:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_cert(cert_pem=None, pem_filepath=None):
    if not any((cert_pem, pem_filepath)) or all((cert_pem, pem_filepath)):
        raise ValueError("only submit `cert_pem` OR `pem_filepath`")

    tmpfile_pem = None
    try:
        if pem_filepath:
            raise NotImplemented
        else:
            tmpfile_pem = tempfile.NamedTemporaryFile()
            tmpfile_pem.write(cert_pem)
            tmpfile_pem.seek(0)
            pem_filepath = tmpfile_pem.name

        rval = {}
        rval['issuer_hash'] = cert_single_op__pem_filepath(pem_filepath, '-issuer_hash')
        rval['issuer'] = cert_single_op__pem_filepath(pem_filepath, '-issuer')
        rval['subject_hash'] = cert_single_op__pem_filepath(pem_filepath, '-subject_hash')
        rval['subject'] = cert_single_op__pem_filepath(pem_filepath, '-subject')
        rval['startdate'] = cert_single_op__pem_filepath(pem_filepath, '-startdate')
        rval['enddate'] = cert_single_op__pem_filepath(pem_filepath, '-enddate')
        rval['parse_enddate_cert__pem_filepath'] = str(parse_enddate_cert__pem_filepath(pem_filepath))
        rval['parse_startdate_cert__pem_filepath'] = str(parse_startdate_cert__pem_filepath(pem_filepath))

        return rval
    except:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()
