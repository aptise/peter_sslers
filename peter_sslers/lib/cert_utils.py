from __future__ import print_function

import logging

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# stdlib
from io import open  # overwrite `open` in Python2
import base64
import binascii
import json
import re
import six
import subprocess
import sys
import tempfile
import textwrap

# pypi
from dateutil import parser as dateutil_parser
import psutil

# localapp
from . import errors
from . import utils
from .. import (
    lib,
)  # only here to access `lib.letsencrypt_info` without a circular import

# ==============================================================================


openssl_path = "openssl"
openssl_path_conf = "/etc/ssl/openssl.cnf"

ACME_VERSION = "v2"
openssl_version = None
_RE_openssl_version = re.compile("OpenSSL ((\d+\.\d+\.\d+)\w*) ", re.I)
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


def new_csr_for_domain_names(
    domain_names, private_key_path=None, tmpfiles_tracker=None
):
    if openssl_version is None:
        check_openssl_version()

    max_domains_certificate = lib.letsencrypt_info.LIMITS["names/certificate"]["limit"]
    if len(domain_names) > max_domains_certificate:
        raise errors.OpenSslError_CsrGeneration(
            "LetsEncrypt can only allow `%s` domains per certificate"
            % max_domains_certificate
        )

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
        * the certificate's subject is `/CN=yourdomain`
        """
        _csr_subject = "/CN=%s" % domain_names[0]
        with psutil.Popen(
            [
                openssl_path,
                "req",
                "-new",
                "-sha256",
                "-key",
                private_key_path,
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
        * the certificate's subject is `/`
        * all domains appear in subjectAltName
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
                    % (openssl_path, private_key_path, tmpfile_csr_san.name)
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

            # note that we use /bin/cat (!)
            _command = """%s req -new -sha256 -key %s -subj "/" -addext %s""" % (
                openssl_path,
                private_key_path,
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


def parse_cert_domains(cert_path=None,):
    subject_domain, san_domains = parse_cert_domains__segmented(cert_path=cert_path)
    if subject_domain is not None and subject_domain not in san_domains:
        san_domains.insert(0, subject_domain)
    return san_domains


def parse_cert_domains__segmented(cert_path=None,):
    log.info("Parsing CERT... | parse_cert_domains__segmented")
    # openssl x509 -in MYCERT -noout -text
    with psutil.Popen(
        [openssl_path, "x509", "-in", cert_path, "-noout", "-text"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("Error loading {0}: {1}".format(cert_path, err))
        if six.PY3:
            out = out.decode("utf8")
    # init
    subject_domain = None
    san_domains = set([])  # convert to list on return

    _common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out)
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
    return subject_domain, list(san_domains)


def parse_csr_domains(csr_path=None, submitted_domain_names=None, is_der=None):
    """checks found names against `submitted_domain_names`
    """
    log.info("Parsing CSR... | parse_csr_domains")
    if is_der:
        with psutil.Popen(
            [openssl_path, "req", "-in", csr_path, "-inform", "DER", "-noout", "-text"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            out, err = proc.communicate()
            if proc.returncode != 0:
                raise IOError("Error loading {0}: {1}".format(csr_path, err))
    else:
        # openssl req -in MYCSR -noout -text
        with psutil.Popen(
            [openssl_path, "req", "-in", csr_path, "-noout", "-text"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            out, err = proc.communicate()
            if proc.returncode != 0:
                raise IOError("Error loading {0}: {1}".format(csr_path, err))
    if six.PY3:
        out = out.decode("utf8")
    found_domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out)
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

    # ensure our CERT matches our submitted_domain_names
    if submitted_domain_names is not None:
        for domain in found_domains:
            if domain not in submitted_domain_names:
                raise ValueError("domain not in submitted_domain_names")
        for domain in submitted_domain_names:
            if domain not in found_domains:
                raise ValueError("domain not in found_domains")

    return found_domains


def cleanup_pem_text(pem_text):
    """ensures a trailing newline
    """
    pem_text = pem_text.strip() + "\n"
    return pem_text


def validate_key__pem(key_pem):
    tmpfile_pem = None
    try:
        tmpfile_pem = new_pem_tempfile(key_pem)
        pem_filepath = tmpfile_pem.name
        return validate_key__pem_filepath(pem_filepath)
    except Exception as exc:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def validate_key__pem_filepath(pem_filepath):
    # openssl rsa -in {KEY} -check
    with psutil.Popen(
        [openssl_path, "rsa", "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            raise errors.OpenSslError_InvalidKey(err)
        if six.PY3:
            data = data.decode("utf8")
    return True


def validate_csr__pem_filepath(pem_filepath):
    # openssl req -text -noout -verify -in {CSR}
    with psutil.Popen(
        [openssl_path, "req", "-text", "-noout", "-verify", "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            raise errors.OpenSslError_InvalidCSR(err)
        if six.PY3:
            data = data.decode("utf8")
    return True


def validate_cert__pem_filepath(pem_filepath):
    # openssl x509 -in {CERTIFICATE} -inform pem -noout -text
    with psutil.Popen(
        [
            openssl_path,
            "x509",
            "-in",
            pem_filepath,
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


def validate_cert__der_filepath(der_filepath):
    # openssl x509 -in {CERTIFICATE} -inform der -noout -text
    with psutil.Popen(
        [
            openssl_path,
            "x509",
            "-in",
            der_filepath,
            "-inform",
            "der",
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


def _cleanup_md5(data):
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


def modulus_md5_key__pem_filepath(pem_filepath):
    # openssl rsa -noout -modulus -in {KEY} | openssl md5

    with psutil.Popen(
        [openssl_path, "rsa", "-noout", "-modulus", "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc_modulus:
        with psutil.Popen(
            [openssl_path, "md5"],
            stdin=proc_modulus.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_md5:
            data, err = proc_md5.communicate()

    return _cleanup_md5(data)


def modulus_md5_csr__pem_filepath(pem_filepath):
    # openssl req -noout -modulus -in {CSR} | openssl md5
    with psutil.Popen(
        [openssl_path, "req", "-noout", "-modulus", "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc_modulus:
        with psutil.Popen(
            [openssl_path, "md5"],
            stdin=proc_modulus.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_md5:
            data, err = proc_md5.communicate()

    return _cleanup_md5(data)


def modulus_md5_cert__pem_filepath(pem_filepath):
    # openssl x509 -noout -modulus -in {CERT} | openssl md5
    with psutil.Popen(
        [openssl_path, "x509", "-noout", "-modulus", "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc_modulus:
        with psutil.Popen(
            [openssl_path, "md5"],
            stdin=proc_modulus.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_md5:
            data, err = proc_md5.communicate()
    return _cleanup_md5(data)


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


def key_single_op__pem_filepath(pem_filepath, single_op):
    """handles a single pem operation to `openssl rsa`

        openssl rsa -noout -check -in {KEY}
        openssl rsa -noout -modulus -in {KEY}
        openssl rsa -noout -text -in {KEY}

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


def parse_enddate_cert__pem_filepath(pem_filepath):
    # openssl x509 -enddate -noout -in {CERT}
    with psutil.Popen(
        [openssl_path, "x509", "-enddate", "-noout", "-in", pem_filepath],
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


def parse_startdate_cert__pem_filepath(pem_filepath):
    # openssl x509 -startdate -noout -in {CERT}
    with psutil.Popen(
        [openssl_path, "x509", "-startdate", "-noout", "-in", pem_filepath],
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


def verify_partial_chain__paths(pem_filepath_chain=None, pem_filepath_cert=None):
    """
    openssl verify -partial_chain -CAfile example.com.chain.pem -CApath - example.com.cert.pem
    note the '-' between "-CApath - example.com.cert.pem"
    openssl will hang without it

    #TODO This may not be working correctly.  Needs more testing.
    """
    raise NotImplementedError()
    with psutil.Popen(
        [
            openssl_path,
            "verify",
            "-partial_chain",
            "-CAfile",
            pem_filepath_chain,
            "-CApath",
            "-",
            pem_filepath_cert,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data, err = proc.communicate()
        if not data:
            return False
        return True


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


def probe_cert__format(filepath):
    """returns "der" or "pem" (lowercase)"""
    try:
        validate_cert__pem_filepath(filepath)
        return "pem"
    except errors.OpenSslError_InvalidCertificate as exc:
        validate_cert__der_filepath(filepath)
        return "der"
    except errors.OpenSslError_InvalidCertificate as exc:
        raise errors.OpenSslError_InvalidCertificate("not PEM or DER")


def parse_key(key_pem=None, pem_filepath=None):
    if not any((key_pem, pem_filepath)) or all((key_pem, pem_filepath)):
        raise ValueError("only submit `key_pem` OR `pem_filepath`")

    tmpfile_pem = None
    try:
        if not pem_filepath:
            tmpfile_pem = new_pem_tempfile(key_pem)
            pem_filepath = tmpfile_pem.name

        rval = {}
        rval["modulus"] = key_single_op__pem_filepath(pem_filepath, "-modulus")
        rval["check"] = key_single_op__pem_filepath(pem_filepath, "-check")
        rval["text"] = key_single_op__pem_filepath(pem_filepath, "-text")
        return rval
    except Exception as exc:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_cert(cert_pem=None, pem_filepath=None):
    if not any((cert_pem, pem_filepath)) or all((cert_pem, pem_filepath)):
        raise ValueError("only submit `cert_pem` OR `pem_filepath`")

    tmpfile_pem = None
    try:
        if not pem_filepath:
            tmpfile_pem = new_pem_tempfile(cert_pem)
            pem_filepath = tmpfile_pem.name

        rval = {}
        rval["issuer_hash"] = cert_single_op__pem_filepath(pem_filepath, "-issuer_hash")
        rval["issuer"] = cert_single_op__pem_filepath(pem_filepath, "-issuer")
        rval["subject_hash"] = cert_single_op__pem_filepath(
            pem_filepath, "-subject_hash"
        )
        rval["subject"] = cert_single_op__pem_filepath(pem_filepath, "-subject")
        rval["startdate"] = cert_single_op__pem_filepath(pem_filepath, "-startdate")
        rval["enddate"] = cert_single_op__pem_filepath(pem_filepath, "-enddate")
        rval["parse_enddate_cert__pem_filepath"] = str(
            parse_enddate_cert__pem_filepath(pem_filepath)
        )
        rval["parse_startdate_cert__pem_filepath"] = str(
            parse_startdate_cert__pem_filepath(pem_filepath)
        )

        return rval
    except Exception as exc:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_cert__dates(cert_pem=None, pem_filepath=None):
    if not any((cert_pem, pem_filepath)) or all((cert_pem, pem_filepath)):
        raise ValueError("only submit `cert_pem` OR `pem_filepath`")
    tmpfile_pem = None
    try:
        if not pem_filepath:
            tmpfile_pem = new_pem_tempfile(cert_pem)
            pem_filepath = tmpfile_pem.name

        rval = {}
        rval["startdate"] = cert_single_op__pem_filepath(pem_filepath, "-startdate")
        rval["enddate"] = cert_single_op__pem_filepath(pem_filepath, "-enddate")
        return rval
    except Exception as exc:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def new_private_key():
    # openssl genrsa 4096 > domain.key
    with psutil.Popen(
        [openssl_path, "genrsa", "4096"],
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
        validate_key__pem(key_pem)
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


def convert_lejson(pkey_jsons, to="pem"):
    """
    input is a json string
    much work from https://gist.github.com/JonLundy/f25c99ee0770e19dc595

    openssl asn1parse -noout -out private_key.der -genconf <(python conv.py private_key.json)
    openssl rsa -in private_key.der -inform der > private_key.pem
    openssl rsa -in private_key.pem
    """
    ans1 = convert_jwk_to_ans1(pkey_jsons)
    as_pem = None

    tmpfiles = []
    try:
        tmpfile_ans1 = new_pem_tempfile(ans1)
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
        as_pem = convert_der_to_pem__rsakey(tmpfile_der.read())
        validate_key__pem(as_pem)
        return as_pem

    except Exception as exc:
        raise
    finally:
        for t in tmpfiles:
            t.close()

    return as_pem
