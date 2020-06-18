from __future__ import print_function

import logging


if False:
    # use when debugging
    log = logging.getLogger(__name__)
    log.addHandler(logging.StreamHandler())
    log.setLevel(logging.DEBUG)


# stdlib
from io import open  # overwrite `open` in Python2
import base64
import binascii
import json
import re
import hashlib
import subprocess
import sys
import tempfile
import textwrap

# pypi
from dateutil import parser as dateutil_parser
import psutil
import six

try:
    from acme import crypto_util as acme_crypto_util
    from certbot import crypto_util as certbot_crypto_util

    # from Crypto.Util import crypto_util_asn1
    from OpenSSL import crypto as openssl_crypto
    from cryptography.hazmat.primitives import (
        serialization as cryptography_serialization,
    )
    import jwt
    import cryptography

except ImportError as exc:
    acme_crypto_util = None
    certbot_crypto_util = None
    # crypto_util_asn1 = None
    openssl_crypto = None
    jwt = None
    cryptography_serialization = None
    cryptography = None

# localapp
from . import errors
from . import utils
from .. import (
    lib,
)  # only here to access `lib.letsencrypt_info` without a circular import

# ==============================================================================


openssl_path = "openssl"
openssl_path_conf = "/etc/ssl/openssl.cnf"

# TODO - is this better?
openssl_path = "/usr/local/bin/openssl"
openssl_path_conf = "/usr/local/ssl/openssl.cnf"


ACME_VERSION = "v2"
openssl_version = None
_RE_openssl_version = re.compile(r"OpenSSL ((\d+\.\d+\.\d+)\w*) ", re.I)
_RE_rn = re.compile(r"\r\n")
_openssl_behavior = None  # 'a' or 'b'


# ==============================================================================


def check_openssl_version(replace=False):
    global openssl_version
    global _openssl_behavior
    if (openssl_version is None) or replace:
        with psutil.Popen(
            [openssl_path, "version",], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) as proc:
            version_text, err = proc.communicate()
        if err:
            raise errors.OpenSslError("could not check version")
        if six.PY3:
            version_text = version_text.decode("utf8")
        # version_text will be something like "OpenSSL 1.0.2g  1 Mar 2016\n"
        # version_text.strip().split(' ')[1] == '1.0.2g'
        # but... regex!
        m = _RE_openssl_version.search(version_text)
        if not m:
            raise ValueError("could not regex OpenSSL version")
        # m.groups == ('1.0.2g', '1.0.2')
        v = m.groups()[1]
        v = [int(i) for i in v.split(".")]
        openssl_version = v
        _openssl_behavior = "a"  # default to old behavior
        # OpenSSL 1.1.1 doesn't need a tempfile for SANs
        if (v[0] >= 1) and (v[1] >= 1) and (v[2] >= 1):
            _openssl_behavior = "b"
    return openssl_version


def new_pem_tempfile(pem_data):
    """this is just a convenience wrapper to create a tempfile and seek(0)
    """
    tmpfile_pem = tempfile.NamedTemporaryFile()
    if six.PY3:
        if isinstance(pem_data, str):
            pem_data = pem_data.encode()
    tmpfile_pem.write(pem_data)
    tmpfile_pem.seek(0)
    return tmpfile_pem


def _write_pem_tempfile(tmpfile_pem, pem_data):
    if six.PY3:
        if isinstance(pem_data, str):
            pem_data = pem_data.encode()
    tmpfile_pem.write(pem_data)
    tmpfile_pem.seek(0)


def make_csr(domain_names, key_pem=None, key_pem_filepath=None, tmpfiles_tracker=None):
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("make_csr >")
    max_domains_certificate = lib.letsencrypt_info.LIMITS["names/certificate"]["limit"]
    if len(domain_names) > max_domains_certificate:
        raise errors.OpenSslError_CsrGeneration(
            "LetsEncrypt can only allow `%s` domains per certificate"
            % max_domains_certificate
        )

    # first try with python
    if acme_crypto_util:
        try:
            csr_text = acme_crypto_util.make_csr(key_pem, domain_names)
        except Exception as exc:
            raise errors.OpenSslError_CsrGeneration(exc)
        return csr_text

    log.debug(".make_csr > openssl fallback")

    if openssl_version is None:
        check_openssl_version()

    _acme_generator_strategy = None
    if ACME_VERSION == "v1":
        if len(domain_names) == 1:
            _acme_generator_strategy = 1
        else:
            _acme_generator_strategy = 2
    elif ACME_VERSION == "v2":
        _acme_generator_strategy = 2

    if _acme_generator_strategy == 1:
        """
        This is the ACME-V1 method for single domain certificates
        * the certificate's subject (commonName) is `/CN=yourdomain`
        """
        _csr_subject = "/CN=%s" % domain_names[0]
        with psutil.Popen(
            [
                openssl_path,
                "req",
                "-new",
                "-sha256",
                "-key",
                key_pem_filepath,
                "-subj",
                _csr_subject,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            csr_text, err = proc.communicate()
            if err:
                raise errors.OpenSslError_CsrGeneration("could not create a CSR")
            if six.PY3:
                csr_text = csr_text.decode("utf8")

    elif _acme_generator_strategy == 2:
        """
        This is the ACME-V2 method for single domain certificates. It works on ACME-V1.
        * the certificate's subject (commonName) is `/`
        * ALL domains appear in subjectAltName

        The ACME Spec allows for the domain to be provided in:
            * commonName
            * SAN
            * both

        LetsEncrypt interpreted the relevant passage as not requiring the server to accept each of these.
        """

        # getting subprocess to work right is a pain, because we need to chain a bunch of commands
        # to get around this, we'll do two things:
        # 1. cat the [SAN] and openssl path file onto a tempfile
        # 2. use shell=True

        domain_names = sorted(domain_names)

        # the subject should be /, which will become the serial number
        # see https://community.letsencrypt.org/t/certificates-with-serialnumber-in-subject/11891
        _csr_subject = "/"

        if _openssl_behavior == "a":
            # earlier OpenSSL versions require us to pop in the subjectAltName via a cat'd file

            # generate the [SAN]
            _csr_san = "[SAN]\nsubjectAltName=" + ",".join(
                ["DNS:%s" % d for d in domain_names]
            )

            # store some data in a tempfile
            with open(openssl_path_conf, "rt", encoding="utf-8") as _f_conf:
                _conf_data = _f_conf.read()

            _newline = "\n\n"
            if six.PY3:
                _conf_data = _conf_data.encode()
                _csr_san = _csr_san.encode()
                _newline = _newline.encode()

            with tempfile.NamedTemporaryFile() as tmpfile_csr_san:
                tmpfile_csr_san.write(_conf_data)
                tmpfile_csr_san.write(_newline)
                tmpfile_csr_san.write(_csr_san)
                tmpfile_csr_san.seek(0)

                # note that we use /bin/cat (!)
                _command = (
                    """%s req -new -sha256 -key %s -subj "/" -reqexts SAN -config < /bin/cat %s"""
                    % (openssl_path, key_pem_filepath, tmpfile_csr_san.name)
                )
                with psutil.Popen(
                    _command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                ) as proc:
                    csr_text, err = proc.communicate()
                    if err:
                        raise errors.OpenSslError_CsrGeneration(
                            "could not create a CSR"
                        )
                    if six.PY3:
                        csr_text = csr_text.decode("utf8")
                    csr_text = cleanup_pem_text(csr_text)

        elif _openssl_behavior == "b":
            # new OpenSSL versions support passing in the `subjectAltName` via the commandline

            # generate the [SAN]
            _csr_san = "subjectAltName = " + ", ".join(
                ["DNS:%s" % d for d in domain_names]
            )
            _command = '''%s req -new -sha256 -key %s -subj "/" -addext "%s"''' % (
                openssl_path,
                key_pem_filepath,
                _csr_san,
            )
            with psutil.Popen(
                _command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ) as proc:
                csr_text, err = proc.communicate()
                if err:
                    raise errors.OpenSslError_CsrGeneration("could not create a CSR")
                if six.PY3:
                    csr_text = csr_text.decode("utf8")
                csr_text = cleanup_pem_text(csr_text)
    else:
        raise errors.OpenSslError_CsrGeneration("invalid ACME generator")

    return csr_text


def parse_cert_domains(cert_pem=None, cert_pem_filepath=None):
    """
    gets ALL domains from a certificate
        * san (subjectAlternateName)
        * subject (commonName)

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("parse_cert_domains >")
    if certbot_crypto_util:
        all_domains = certbot_crypto_util.get_names_from_cert(cert_pem)
        return all_domains

    log.debug(".parse_cert_domains > openssl fallback")
    # fallback onto OpenSSL
    # `openssl x509 -in MYCERT -noout -text`
    with psutil.Popen(
        [openssl_path, "x509", "-in", cert_pem_filepath, "-noout", "-text"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("Error loading {0}: {1}".format(cert_pem_filepath, err))
        if six.PY3:
            out = out.decode("utf8")
    # init
    subject_domain = None
    san_domains = set([])
    # regex!
    # note the conditional whitespace before/after CN
    _common_name = re.search(r"Subject:.*? CN ?= ?([^\s,;/]+)", out)
    if _common_name is not None:
        subject_domain = _common_name.group(1).lower()
    _subject_alt_names = re.search(
        r"X509v3 Subject Alternative Name: \n +([^\n]+)\n",
        out,
        re.MULTILINE | re.DOTALL,
    )
    if _subject_alt_names is not None:
        for _san in _subject_alt_names.group(1).split(", "):
            if _san.startswith("DNS:"):
                san_domains.add(_san[4:].lower())
    san_domains = list(san_domains)
    if subject_domain is not None and subject_domain not in san_domains:
        san_domains.insert(0, subject_domain)
    san_domains.sort()
    return san_domains


def parse_csr_domains(csr_pem=None, csr_pem_filepath=None, submitted_domain_names=None):
    """
    checks found names against `submitted_domain_names`

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    `submitted_domain_names` should be all lowecase
    """
    log.info("parse_csr_domains >")
    if openssl_crypto and certbot_crypto_util:
        load_func = openssl_crypto.load_certificate_request
        found_domains = certbot_crypto_util._get_names_from_cert_or_req(
            csr_pem, load_func, typ=openssl_crypto.FILETYPE_PEM
        )
    else:
        log.debug(".parse_csr_domains > openssl fallback")
        # fallback onto OpenSSL
        # openssl req -in MYCSR -noout -text
        with psutil.Popen(
            [openssl_path, "req", "-in", csr_pem_filepath, "-noout", "-text"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            out, err = proc.communicate()
            if proc.returncode != 0:
                raise IOError("Error loading {0}: {1}".format(csr_pem_filepath, err))
        if six.PY3:
            out = out.decode("utf8")
        found_domains = set([])
        # note the conditional whitespace before/after CN
        common_name = re.search(r"Subject:.*? CN ?= ?([^\s,;/]+)", out)
        if common_name is not None:
            found_domains.add(common_name.group(1))
        subject_alt_names = re.search(
            r"X509v3 Subject Alternative Name: \n +([^\n]+)\n",
            out,
            re.MULTILINE | re.DOTALL,
        )
        if subject_alt_names is not None:
            for san in subject_alt_names.group(1).split(", "):
                if san.startswith("DNS:"):
                    found_domains.add(san[4:])
        found_domains = list(found_domains)

    # ensure our CERT matches our submitted_domain_names
    if submitted_domain_names is not None:
        for domain in found_domains:
            if domain not in submitted_domain_names:
                raise ValueError("domain %s not in submitted_domain_names" % domain)
        for domain in submitted_domain_names:
            if domain not in found_domains:
                raise ValueError("domain %s not in found_domains" % domain)

    return sorted(found_domains)


def cleanup_pem_text(pem_text):
    """
    standardizes newlines;
    ensures a trailing newline
    """
    pem_text = _RE_rn.sub("\n", pem_text)
    pem_text = pem_text.strip() + "\n"
    return pem_text


def validate_key(key_pem=None, key_pem_filepath=None):
    """
    raises an error if invalid

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("validate_key >")
    if certbot_crypto_util:
        data = certbot_crypto_util.valid_privkey(key_pem)
        if not data:
            raise errors.OpenSslError_InvalidKey()
        return True

    log.debug(".validate_key > openssl fallback")
    # openssl rsa -in {KEY} -check
    with psutil.Popen(
        [openssl_path, "rsa", "-in", key_pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            raise errors.OpenSslError_InvalidKey(err)
        if six.PY3:
            data = data.decode("utf8")
    return True


def validate_csr(csr_pem=None, csr_pem_filepath=None):
    """
    raises an error if invalid

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("validate_csr >")
    if certbot_crypto_util:
        data = certbot_crypto_util.valid_csr(csr_pem)
        if not data:
            raise errors.OpenSslError_InvalidCSR()
        return True

    log.debug(".validate_csr > openssl fallback")
    # openssl req -text -noout -verify -in {CSR}
    with psutil.Popen(
        [openssl_path, "req", "-text", "-noout", "-verify", "-in", csr_pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            raise errors.OpenSslError_InvalidCSR(err)
        if six.PY3:
            data = data.decode("utf8")
    return True


def validate_cert(cert_pem=None, cert_pem_filepath=None):
    """
    raises an error if invalid

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("validate_cert >")
    if openssl_crypto:
        try:
            data = openssl_crypto.load_certificate(
                openssl_crypto.FILETYPE_PEM, cert_pem
            )
        except Exception as exc:
            raise errors.OpenSslError_InvalidCertificate(exc)
        if not data:
            raise errors.OpenSslError_InvalidCertificate()
        return True

    log.debug(".validate_cert > openssl fallback")
    # openssl x509 -in {CERTIFICATE} -inform pem -noout -text
    with psutil.Popen(
        [
            openssl_path,
            "x509",
            "-in",
            cert_pem_filepath,
            "-inform",
            "pem",
            "-noout",
            "-text",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            raise errors.OpenSslError_InvalidCertificate(err)
        if six.PY3:
            data = data.decode("utf8")
    return True


def _cleanup_openssl_md5(data):
    """
    some versions of openssl handle the md5 as:
        '1231231231'
    others handle as
        "(stdin)= 123123'
    """
    data = data.strip()
    if six.PY3:
        data = data.decode("utf8")
    if len(data) == 32 and (data[:9] != "(stdin)= "):
        return data
    if data[:9] != "(stdin)= " or not data:
        raise errors.OpenSslError("error reading md5 (i)")
    data = data[9:]
    if len(data) != 32:
        raise errors.OpenSslError("error reading md5 (ii)")
    return data


def _cleanup_openssl_modulus(data):
    data = data.strip()
    if data[:8] == "Modulus=":
        data = data[8:]
    return data


def modulus_md5_key(key_pem=None, key_pem_filepath=None):
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("modulus_md5_key >")
    if openssl_crypto:
        privkey = openssl_crypto.load_privatekey(openssl_crypto.FILETYPE_PEM, key_pem)
        modn = privkey.to_cryptography_key().public_key().public_numbers().n
        data = "{:X}".format(modn)
    else:
        log.debug(".modulus_md5_key > openssl fallback")
        # original code was:
        # openssl rsa -noout -modulus -in {KEY} | openssl md5
        # BUT
        # that pipes into md5: "Modulus={MOD}\n"
        with psutil.Popen(
            [openssl_path, "rsa", "-noout", "-modulus", "-in", key_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_modulus:
            data, err = proc_modulus.communicate()
            data = _cleanup_openssl_modulus(data)
    data = hashlib.md5(data).hexdigest()
    return data


def modulus_md5_csr(csr_pem=None, csr_pem_filepath=None):
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("modulus_md5_csr >")
    if openssl_crypto:
        csr = openssl_crypto.load_certificate_request(
            openssl_crypto.FILETYPE_PEM, csr_pem
        )
        modn = csr.get_pubkey().to_cryptography_key().public_numbers().n
        data = "{:X}".format(modn)
    else:
        log.debug(".modulus_md5_csr > openssl fallback")
        # original code was:
        # openssl req -noout -modulus -in {CSR} | openssl md5
        # BUT
        # that pipes into md5: "Modulus={MOD}\n"
        with psutil.Popen(
            [openssl_path, "req", "-noout", "-modulus", "-in", csr_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_modulus:
            data, err = proc_modulus.communicate()
            data = _cleanup_openssl_modulus(data)
    data = hashlib.md5(data).hexdigest()
    return data


def modulus_md5_cert(cert_pem=None, cert_pem_filepath=None):
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("modulus_md5_cert >")
    if openssl_crypto:
        cert = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, cert_pem)
        modn = cert.get_pubkey().to_cryptography_key().public_numbers().n
        data = "{:X}".format(modn)
    else:
        log.debug(".modulus_md5_cert > openssl fallback")
        # original code was:
        # openssl x509 -noout -modulus -in {CERT} | openssl md5
        # BUT
        # that pipes into md5: "Modulus={MOD}\n"
        with psutil.Popen(
            [openssl_path, "x509", "-noout", "-modulus", "-in", cert_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_modulus:
            data, err = proc_modulus.communicate()
            data = _cleanup_openssl_modulus(data)
    data = hashlib.md5(data).hexdigest()
    return data


def cert_single_op__pem_filepath(pem_filepath, single_op):
    """handles a single pem operation to `openssl x509`

        openssl x509 -noout -issuer -in cert.pem
        openssl x509 -noout -issuer_hash -in cert.pem

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
    if single_op not in (
        "-issuer_hash",
        "-issuer",
        "-subject_hash",
        "-subject",
        "-startdate",
        "-enddate",
    ):
        raise ValueError("invalid `single_op`")
    with psutil.Popen(
        [openssl_path, "x509", "-noout", single_op, "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            raise errors.OpenSslError_InvalidCertificate(err)
        if six.PY3:
            data = data.decode("utf8")
        data = data.strip()
    return data


def cert_ext__pem_filepath(pem_filepath, ext):
    """handles a single pem operation to `openssl x509`
        /usr/local/bin/openssl x509  -noout -ext subjectAltName -in cert.pem
    """
    if ext not in ("subjectAltName",):
        raise ValueError("invalid `ext`")
    with psutil.Popen(
        [openssl_path, "x509", "-noout", "-ext", ext, "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            raise errors.OpenSslError_InvalidCertificate(err)
        if six.PY3:
            data = data.decode("utf8")
        data = data.strip()
    return data


def key_single_op__pem_filepath(pem_filepath, single_op):
    """
    handles a single pem operation to `openssl rsa`

        openssl rsa -noout -check -in {KEY}
        openssl rsa -noout -modulus -in {KEY}
        openssl rsa -noout -text -in {KEY}

    THIS SHOULD NOT BE USED BY INTERNAL CODE
    """
    if single_op not in ("-check", "-modulus", "-text"):
        raise ValueError("invalid `single_op`")
    with psutil.Popen(
        [openssl_path, "rsa", "-noout", single_op, "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            raise errors.OpenSslError_InvalidCertificate(err)
        if six.PY3:
            data = data.decode("utf8")
        data = data.strip()
    return data


def parse_cert_enddate(cert_pem=None, cert_pem_filepath=None):
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("parse_cert_enddate >")
    if openssl_crypto:
        cert = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, cert_pem)
        date = cert.to_cryptography().not_valid_after
    else:
        log.debug(".parse_cert_enddate > openssl fallback")

        # openssl x509 -enddate -noout -in {CERT}
        with psutil.Popen(
            [openssl_path, "x509", "-enddate", "-noout", "-in", cert_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data, err = proc.communicate()
            if not data:
                raise errors.OpenSslError_InvalidCertificate(err)
            if six.PY3:
                data = data.decode("utf8")
            if data[:9] != "notAfter=":
                raise errors.OpenSslError_InvalidCertificate("unexpected format")
            data_date = data[9:]
            date = dateutil_parser.parse(data_date)
            date = date.replace(tzinfo=None)
    return date


def parse_cert_startdate(cert_pem=None, cert_pem_filepath=None):
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("parse_cert_startdate >")
    if openssl_crypto:
        cert = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, cert_pem)
        date = cert.to_cryptography().not_valid_before
    else:
        log.debug(".parse_cert_enddate > openssl fallback")
        # openssl x509 -startdate -noout -in {CERT}
        with psutil.Popen(
            [openssl_path, "x509", "-startdate", "-noout", "-in", cert_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data, err = proc.communicate()
            if not data:
                raise errors.OpenSslError_InvalidCertificate(err)
            if six.PY3:
                data = data.decode("utf8")
            if data[:10] != "notBefore=":
                raise errors.OpenSslError_InvalidCertificate("unexpected format")
            data_date = data[10:]
            date = dateutil_parser.parse(data_date)
            date = date.replace(tzinfo=None)
    return date


def convert_der_to_pem(der_data=None):
    # PEM is just a b64 encoded DER certificate with the header/footer (FOR REAL!)
    as_pem = """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(der_data).decode("utf8"), 64))
    )
    return as_pem


def convert_der_to_pem__csr(der_data=None):
    # PEM is just a b64 encoded DER certificate with the header/footer (FOR REAL!)
    as_pem = """-----BEGIN CERTIFICATE REQUEST-----\n{0}\n-----END CERTIFICATE REQUEST-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(der_data).decode("utf8"), 64))
    )
    return as_pem


def convert_der_to_pem__rsakey(der_data=None):
    # PEM is just a b64 encoded DER certificate with the header/footer (FOR REAL!)
    """
    proc = psutil.Popen([openssl_path, "rsa", "-in", tmpfile_der.name, "-inform", 'der', '-outform', 'pem'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    generated, err = proc.communicate()
    if err and (err != 'writing RSA key\n'):
        raise ValueError(err)
    as_pem = generated
    """
    as_pem = """-----BEGIN RSA PRIVATE KEY-----\n{0}\n-----END RSA PRIVATE KEY-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(der_data).decode("utf8"), 64))
    )
    return as_pem


def convert_pem_to_der(pem_data=None):
    # PEM is just a b64 encoded DER certificate with the header/footer (FOR REAL!)
    lines = [l.strip() for l in pem_data.strip().split("\n")]
    # remove the BEGIN CERT
    if (
        ("BEGIN CERTIFICATE" in lines[0])
        or ("BEGIN RSA PRIVATE KEY" in lines[0])
        or ("BEGIN PRIVATE KEY" in lines[0])
        or ("BEGIN CERTIFICATE REQUEST" in lines[0])
    ):
        lines = lines[1:]
    if (
        ("END CERTIFICATE" in lines[-1])
        or ("END RSA PRIVATE KEY" in lines[-1])
        or ("END PRIVATE KEY" in lines[-1])
        or ("END CERTIFICATE REQUEST" in lines[-1])
    ):
        lines = lines[:-1]
    lines = "".join(lines)
    result = base64.b64decode(lines)
    return result


def parse_key(key_pem=None, key_pem_filepath=None):
    """
    !!!: This is a debugging display function. The output is not guaranteed across installations.

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("parse_key >")
    rval = {
        "check": None,
        "text": None,
        "modulus": None,
    }
    if openssl_crypto and certbot_crypto_util:
        try:
            rval["check"] = validate_key(key_pem=key_pem)
        except Exception as exc:
            rval["check"] = str(exc)
        # TODO: crypto version of `--text`
        try:
            _crypto_privkey = openssl_crypto.load_privatekey(
                openssl_crypto.FILETYPE_PEM, key_pem
            )
            modn = _crypto_privkey.to_cryptography_key().public_key().public_numbers().n
            modn = "{:X}".format(modn)
            rval["modulus"] = hashlib.md5(modn).hexdigest()
        except Exception as exc:
            rval["modulus"] = str(exc)
        return rval

    log.debug(".parse_key > openssl fallback")
    tmpfile_pem = None
    try:
        if not key_pem_filepath:
            tmpfile_pem = new_pem_tempfile(key_pem)
            key_pem_filepath = tmpfile_pem.name
        rval["check"] = key_single_op__pem_filepath(key_pem_filepath, "-check")
        rval["text"] = key_single_op__pem_filepath(key_pem_filepath, "-text")
        rval["modulus"] = key_single_op__pem_filepath(key_pem_filepath, "-modulus")
        return rval
    except Exception as exc:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_cert(cert_pem=None, cert_pem_filepath=None):
    """
    !!!: This is a debugging display function. The output is not guaranteed across installations.

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("parse_cert >")
    rval = {
        "issuer": None,
        "issuer_hash": None,
        "subject": None,
        "subject_hash": None,
        "enddate": None,
        "startdate": None,
    }
    if openssl_crypto:
        cert = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, cert_pem)

        rval["issuer"] = "%s" % cert.get_issuer()
        rval["subject"] = "%s" % cert.get_subject()
        rval["enddate"] = cert.to_cryptography().not_valid_after
        rval["startdate"] = cert.to_cryptography().not_valid_before
        ext = cert.to_cryptography().extensions.get_extension_for_oid(
            cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        rval["SubjectAlternativeName"] = ext.value.get_values_for_type(
            cryptography.x509.DNSName
        )
        return rval

    log.debug(".parse_cert > openssl fallback")
    global openssl_version
    global _openssl_behavior
    tmpfile_pem = None
    try:
        if not cert_pem_filepath:
            tmpfile_pem = new_pem_tempfile(cert_pem)
            cert_pem_filepath = tmpfile_pem.name
        rval["issuer"] = cert_single_op__pem_filepath(cert_pem_filepath, "-issuer")
        rval["subject"] = cert_single_op__pem_filepath(cert_pem_filepath, "-subject")
        rval["startdate"] = cert_single_op__pem_filepath(
            cert_pem_filepath, "-startdate"
        )
        rval["enddate"] = cert_single_op__pem_filepath(cert_pem_filepath, "-enddate")
        rval["issuer_hash"] = cert_single_op__pem_filepath(
            cert_pem_filepath, "-issuer_hash"
        )
        rval["subject_hash"] = cert_single_op__pem_filepath(
            cert_pem_filepath, "-subject_hash"
        )
        if openssl_version is None:
            check_openssl_version()
        if _openssl_behavior == "b":
            rval["SubjectAlternativeName"] = cert_ext__pem_filepath(
                cert_pem_filepath, "subjectAltName"
            )
        else:
            with psutil.Popen(
                [openssl_path, "x509", "-text", "-noout", "-in", cert_pem_filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc_text:
                with psutil.Popen(
                    ["grep", "DNS"],
                    stdin=proc_text.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ) as proc_grep:
                    data, err = proc_text.communicate()
                    rval["SubjectAlternativeName"] = data

        # rval["parse_cert_enddate"] = str(
        #    parse_cert_enddate(cert_pem=cert_pem, cert_pem_filepath=pem_filepath)
        # )
        # rval["parse_cert_startdate"] = str(
        #    parse_cert_startdate(cert_pem=cert_pem, cert_pem_filepath=pem_filepath)
        # )
        return rval
    except Exception as exc:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def new_account_key(bits=2048):
    return new_rsa_key(bits=bits)


def new_private_key(bits=4096):
    return new_rsa_key(bits=bits)


def new_rsa_key(bits=4096):
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses
    """
    log.info("new_rsa_key >")
    log.debug(".new_rsa_key > bits = %s", bits)
    if certbot_crypto_util:
        key_pem = certbot_crypto_util.make_key(bits)
        key_pem = cleanup_pem_text(key_pem)
    else:
        log.debug(".new_rsa_key > openssl fallback")
        # openssl genrsa 4096 > domain.key
        bits = str(bits)
        with psutil.Popen(
            [openssl_path, "genrsa", bits],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data, err = proc.communicate()
            if not data:
                raise errors.OpenSslError_InvalidKey(err)
            if six.PY3:
                data = data.decode("utf8")
            key_pem = data
            key_pem = cleanup_pem_text(key_pem)
            # this will raise an error
            validate_key(key_pem=key_pem)
    return key_pem


def convert_jwk_to_ans1(pkey_jsons):
    """
    input is a json string
    much work from https://gist.github.com/JonLundy/f25c99ee0770e19dc595
    """
    pkey = json.loads(pkey_jsons)

    def enc(data):
        missing_padding = 4 - len(data) % 4
        if missing_padding:
            data += b"=" * missing_padding
        return "0x" + binascii.hexlify(base64.b64decode(data, b"-_")).upper()

    for k, v in list(pkey.items()):
        if k == "kty":
            continue
        pkey[k] = enc(v.encode())

    converted = []
    converted.append("asn1=SEQUENCE:private_key\n[private_key]\nversion=INTEGER:0")
    converted.append("n=INTEGER:{}".format(pkey[u"n"]))
    converted.append("e=INTEGER:{}".format(pkey[u"e"]))
    converted.append("d=INTEGER:{}".format(pkey[u"d"]))
    converted.append("p=INTEGER:{}".format(pkey[u"p"]))
    converted.append("q=INTEGER:{}".format(pkey[u"q"]))
    converted.append("dp=INTEGER:{}".format(pkey[u"dp"]))
    converted.append("dq=INTEGER:{}".format(pkey[u"dq"]))
    converted.append("qi=INTEGER:{}".format(pkey[u"qi"]))
    converted.append("")  # trailing newline
    converted = "\n".join(converted)

    return converted


def convert_lejson_to_pem(pkey_jsons):
    """
    input is a json string
    much work from https://gist.github.com/JonLundy/f25c99ee0770e19dc595

    openssl asn1parse -noout -out private_key.der -genconf <(python conv.py private_key.json)
    openssl rsa -in private_key.der -inform der > private_key.pem
    openssl rsa -in private_key.pem
    """
    log.info("convert_lejson_to_pem >")

    if jwt and cryptography_serialization:
        pkey = jwt.algorithms.RSAAlgorithm.from_jwk(pkey_jsons)
        as_pem = pkey.private_bytes(
            encoding=cryptography_serialization.Encoding.PEM,
            format=cryptography_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=cryptography_serialization.NoEncryption(),
        )
        as_pem = cleanup_pem_text(as_pem)

        # note: we don't need to provide key_pem_filepath before we won't rely on openssl
        validate_key(key_pem=as_pem)
        return as_pem

    log.debug(".convert_lejson_to_pem > openssl fallback")
    pkey_ans1 = convert_jwk_to_ans1(pkey_jsons)
    as_pem = None
    tmpfiles = []
    try:
        tmpfile_ans1 = new_pem_tempfile(pkey_ans1)
        tmpfiles.append(tmpfile_ans1)

        tmpfile_der = new_pem_tempfile("")
        tmpfiles.append(tmpfile_der)

        with psutil.Popen(
            [
                openssl_path,
                "asn1parse",
                "-noout",
                "-out",
                tmpfile_der.name,
                "-genconf",
                tmpfile_ans1.name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            generated, err = proc.communicate()
            if err:
                raise ValueError(err)
        # convert to pem
        as_pem = convert_der_to_pem__rsakey(tmpfile_der.read())

        # we need a tmpfile to validate it
        tmpfile_pem = new_pem_tempfile(as_pem)
        tmpfiles.append(tmpfile_pem)

        # validate it
        validate_key(key_pem=as_pem, key_pem_filepath=tmpfile_pem.name)
        return as_pem

    except Exception as exc:
        raise
    finally:
        for t in tmpfiles:
            t.close()
