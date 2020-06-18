# stdlib
import subprocess

# pypi
import psutil
import six

# local
from .cert_utils import openssl_path
from .cert_utils import validate_cert
from . import errors


# ==============================================================================

def parse_cert__dates(cert_pem=None, pem_filepath=None):
    if not any((cert_pem, pem_filepath)) or all((cert_pem, pem_filepath)):
        raise ValueError("only submit `cert_pem` OR `pem_filepath`")

    log.info("parse_cert__dates >")
    if crypto:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        date = cert.to_cryptography().not_valid_after

        # todo: cleanup dates
        rval = {}
        rval["startdate"] = cert.to_cryptography().not_valid_before
        rval["enddate"] = cert.to_cryptography().not_valid_after
        return rval

    log.debug(".parse_cert__dates > openssl fallback")

    tmpfile_pem = None
    try:
        if not pem_filepath:
            tmpfile_pem = new_pem_tempfile(cert_pem)
            pem_filepath = tmpfile_pem.name

        # todo: cleanup dates
        rval = {}
        rval["startdate"] = cert_single_op__pem_filepath(pem_filepath, "-startdate")
        rval["enddate"] = cert_single_op__pem_filepath(pem_filepath, "-enddate")
        return rval
    except Exception as exc:
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_csr_domains__der(csr_pem_filepath):
    with psutil.Popen(
        [
            openssl_path,
            "req",
            "-in",
            csr_pem_filepath,
            "-inform",
            "DER",
            "-noout",
            "-text",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("Error loading {0}: {1}".format(csr_pem_filepath, err))


def verify_partial_chain__paths(pem_filepath_chain=None, pem_filepath_cert=None):
    """
    openssl verify -partial_chain -CAfile example.com.chain.pem -CApath - example.com.cert.pem
    note the '-' between "-CApath - example.com.cert.pem"
    openssl will hang without it
    """
    # NOTE: this may not work
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


def validate_cert__der_filepath(der_filepath):
    """this is only used by `probe_cert__format` which is deprecated"""
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


def probe_cert__format(filepath):
    """returns "der" or "pem" (lowercase)"""
    try:
        validate_cert(cert_pem_filepath=filepath)
        return "pem"
    except errors.OpenSslError_InvalidCertificate as exc:
        validate_cert__der_filepath(filepath)
        return "der"
    except errors.OpenSslError_InvalidCertificate as exc:
        raise errors.OpenSslError_InvalidCertificate("not PEM or DER")
