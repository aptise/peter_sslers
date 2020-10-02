# stdlib
import copy

# pypi
import requests

# localapp
from . import cert_utils
from . import utils


# ==============================================================================


# updated ratelimits are published at:
# https://letsencrypt.org/docs/rate-limits/
# last checked: 2020.07.06

LIMITS = {
    "names/certificate": {"limit": 100},  # "Names per Certificate"
    "certificates/domain": {
        "limit": 50,
        "timeframe": "1 week",
        "includes_renewals": False,
    },  # "Certificates per Registered Domain"
    "certificates/fqdn": {"limit": 5, "timeframe": "1 week"},  # "Duplicate Certificate"
    "registrations/ip_address": {
        "limit": 10,
        "timeframe": "3 hours",
    },  # "Accounts per IP Address"
    "registrations/ip_range": {
        "limit": 500,
        "timeframe": "3 hours",
        "range": "IPv6 /48",
    },  # "Accounts per IP Range"
    "new_orders": {
        "limit": 300,
        "timeframe": "3 hours",
        "acme-v2-only": True,
    },  # "New Orders"
    "pending_authorizations/account": {
        "limit": 300,
        "timeframe": "1 week",
    },  # "Pending Authorizations"
    "failed_validation/account/hostname": {
        "limit": 5,
        "timeframe": "1 hour",
    },  # "Failed Validation"
    "endpoints": {
        "new-reg": {
            "overall_requests": 20,
            "timeframe": "1 second",
        },  # ACME-V1
        "new-authz": {
            "overall_requests": 20,
            "timeframe": "1 second",
        },  # ACME-V1
        "new-cert": {
            "overall_requests": 20,
            "timeframe": "1 second",
        },  # ACME-V1
        "new-nonce": {
            "overall_requests": 20,
            "timeframe": "1 second",
        },  # ACME-V2
        "new-account": {
            "overall_requests": 20,
            "timeframe": "1 second",
        },  # ACME-V2
        "new-order": {
            "overall_requests": 20,
            "timeframe": "1 second",
        },  # ACME-V2
        "revoke-cert": {
            "overall_requests": 20,
            "timeframe": "1 second",
        },  # ACME-V2
        "/directory": {
            "overall_requests": 40,
            "timeframe": "1 second",
        },
        "/acme": {
            "overall_requests": 40,
            "timeframe": "1 second",
        },
        "/acme/*": {
            "overall_requests": 40,
            "timeframe": "1 second",
        },
    },  # "Overall Requests"; enforced by gateway/cdn/balancer
}


# ==============================================================================


# certificates are published online
# https://letsencrypt.org/certificates/
# last checked: 2020.07.06

CA_CROSS_SIGNED_X = ("x1", "x2", "x3", "x4")
CA_AUTH_X = ("x1", "x2", "x3", "x4")
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
        "name": "Let's Encrypt Authority X3",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx3.pem.txt",
        "le_authority_name": "Let's Encrypt Authority X3",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": False,
        "formfield_base": "le_x3_auth",
    },
    {
        "name": "Let's Encrypt Authority X4 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X4",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": True,
        "formfield_base": "le_x4_cross_signed",
    },
    {
        "name": "Let's Encrypt Authority X4",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx4.pem.txt",
        "le_authority_name": "Let's Encrypt Authority X4",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": False,
        "formfield_base": "le_x4_auth",
    },
    {
        "name": "Fake LE Root X1",
        "url_pem": "https://letsencrypt.org/certs/fakelerootx1.pem",
        "is_ca_certificate": True,
        "formfield_base": "fakelerootx1",
    },
    {
        "name": "Fake LE Intermediate X1",
        "url_pem": "https://letsencrypt.org/certs/fakeleintermediatex1.pem",
        "le_authority_name": "Fake LE Intermediate X1",
        "is_authority_certificate": True,
        "is_cross_signed_authority_certificate": False,
        "formfield_base": "fakeleintermediatex1",
    },
]


def download_letsencrypt_certificates():
    """
    download the known LetsEncrypt certificates
    THIS DOES NOT APPLY `cleanup_pem_text`

    * correct usage of `requests`
    - currently using `.content`, which is raw bytes
    - usually one uses `.text`, which is `.content` that is decoded
    - there was some concern that triggered this utf8 decode at some point...
    """
    certs = copy.deepcopy(CA_CERTS_DATA)
    for c in certs:
        resp = requests.get(c["url_pem"])
        if resp.status_code != 200:
            raise ValueError("Could not load certificate")
        cert_pem_text = resp.content
        cert_pem_text = cert_pem_text.decode("utf8")
        cert_pem_text = cert_utils.cleanup_pem_text(cert_pem_text)
        c["cert_pem"] = cert_pem_text
        c["cert_pem_md5"] = utils.md5_text(cert_pem_text)
    return certs
