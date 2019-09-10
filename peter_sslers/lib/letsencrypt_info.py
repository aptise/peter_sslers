# stdlib
import copy

try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2

# localapp
from . import cert_utils
from . import utils


# ==============================================================================


# updated ratelimits are published at:
# https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769

# last checked on 2016/04/01
LIMITS = {
    "names/certificate": {"limit": 100},
    "certificates/domain": {"limit": 20, "timeframe": "1 week"},
    "certificates/fqdn": {"limit": 5, "timeframe": "1 week"},
    "registrations/ip_address": {"limit": 500, "timeframe": "3 hours"},
    "pending_authorizations/account": {"limit": 300, "timeframe": "1 week"},
}


# ==============================================================================


# certificates are published online
# https://letsencrypt.org/certificates/

# last checked 2016.04.02
CA_CROSS_SIGNED_X = ("x1", "x2", "x3", "x4")
CA_AUTH_X = ("x1", "x2")
CA_CERTS_DATA = [
    {
        "name": "ISRG Root X1",
        "url_pem": "https://letsencrypt.org/certs/isrgrootx1.pem",
        "is_ca_certificate": True,
        "formfield_base": "isrgrootx1",
    },
    {
        "name": "Let's Encrypt Authority X1 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X1",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": True,
        "formfield_base": "le_x1_cross_signed",
    },
    {
        "name": "Let's Encrypt Authority X1",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx1.pem",
        "le_authority_name": "Let's Encrypt Authority X1",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": False,
        "formfield_base": "le_x1_auth",
    },
    {
        "name": "Let's Encrypt Authority X2 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X2",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": True,
        "formfield_base": "le_x2_cross_signed",
    },
    {
        "name": "Let's Encrypt Authority X2",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx2.pem",
        "le_authority_name": "Let's Encrypt Authority X2",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": False,
        "formfield_base": "le_x2_auth",
    },
    {
        "name": "Let's Encrypt Authority X3 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X3",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": True,
        "formfield_base": "le_x3_cross_signed",
    },
    {
        "name": "Let's Encrypt Authority X4 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X4",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": True,
        "formfield_base": "le_x4_cross_signed",
    },
]


def probe_letsencrypt_certificates():
    """
    probes the known LetsEncrypt certificates
    THIS DOES NOT APPLY `cleanup_pem_text`
    """
    certs = copy.deepcopy(CA_CERTS_DATA)
    tmpfile = None
    try:
        for c in certs:
            resp = urlopen(c["url_pem"])
            if resp.getcode() != 200:
                raise ValueError("Could not load certificate")
            cert_pem_text = resp.read()
            cert_pem_text = cert_utils.cleanup_pem_text(cert_pem_text)
            c["cert_pem"] = cert_pem_text
            c["cert_pem_md5"] = utils.md5_text(cert_pem_text)
    finally:
        if tmpfile:
            tmpfile.close()

    return certs
