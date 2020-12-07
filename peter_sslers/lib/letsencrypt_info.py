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
# last checked: 2020.12.03

CA_CROSS_SIGNED_X = ("x1", "x2", "x3", "x4", "r3", "r4")
CA_AUTH_X = ("x1", "x2", "x3", "x4", "r3", "r4", "e1", "e2")
CA_CERTS_DATA = {
    "trustid_root_x3": {
        "name": "DST Root CA X3",
        "url_pem": "https://letsencrypt.org/certs/trustid-x3-root.pem",
        "is_trusted_root": True,
        "formfield_base": "trustid_x3_root",
        "is_active": True,
        "is_letsencrypt_certificate": False,
        "key_technology": "RSA",
    },
    "isrg_root_x1": {
        "name": "ISRG Root X1",
        "url_pem": "https://letsencrypt.org/certs/isrgrootx1.pem",
        "is_trusted_root": True,
        "is_letsencrypt_certificate": True,
        "formfield_base": "isrgrootx1",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
    },
    "isrg_root_x2": {
        "name": "ISRG Root X2",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-x2.pem",
        # x2 is self-signed by default, but can be cross-signed by isrgrootx1
        "url_pem_crosssigned": "https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem",
        "is_trusted_root": True,
        "is_letsencrypt_certificate": True,
        "formfield_base": "isrgrootx2",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "cross_signed_by": "isrg_root_x1",
        "key_technology": "EC",  # ECDSA
    },
    "letsencrypt_intermediate_x1_cross": {
        "name": "Let's Encrypt Authority X1 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X1",
        "formfield_base": "le_x1_cross_signed",
        "is_active": False,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "cross_signed_by": "trustid_root_x3",
    },
    "letsencrypt_intermediate_x1": {
        "name": "Let's Encrypt Authority X1",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx1.pem",
        "le_authority_name": "Let's Encrypt Authority X1",
        "formfield_base": "le_x1_auth",
        "is_active": False,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
    },
    "letsencrypt_intermediate_x2_cross": {
        "name": "Let's Encrypt Authority X2 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X2",
        "formfield_base": "le_x2_cross_signed",
        "is_active": False,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "cross_signed_by": "trustid_root_x3",
    },
    "letsencrypt_intermediate_x2": {
        "name": "Let's Encrypt Authority X2",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx2.pem",
        "le_authority_name": "Let's Encrypt Authority X2",
        "formfield_base": "le_x2_auth",
        "is_active": False,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
    },
    "letsencrypt_intermediate_x3_cross": {
        "name": "Let's Encrypt Authority X3 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X3",
        "formfield_base": "le_x3_cross_signed",
        "is_active": False,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "cross_signed_by": "trustid_root_x3",
    },
    "letsencrypt_intermediate_x3": {
        "name": "Let's Encrypt Authority X3",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx3.pem",
        "le_authority_name": "Let's Encrypt Authority X3",
        "formfield_base": "le_x3_auth",
        "is_active": False,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
    },
    "letsencrypt_intermediate_x4_cross": {
        "name": "Let's Encrypt Authority X4 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem",
        "le_authority_name": "Let's Encrypt Authority X4",
        "formfield_base": "le_x4_cross_signed",
        "is_active": False,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "cross_signed_by": "trustid_root_x3",
    },
    "letsencrypt_intermediate_x4": {
        "name": "Let's Encrypt Authority X4",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx4.pem",
        "le_authority_name": "Let's Encrypt Authority X4",
        "formfield_base": "le_x4_auth",
        "is_active": False,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
    },
    "letsencrypt_intermediate_r3_cross": {
        "name": "Let's Encrypt R3 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem",
        "le_authority_name": "Let's Encrypt R3",
        "formfield_base": "le_r3_cross_signed",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "cross_signed_by": "trustid_root_x3",
    },
    "letsencrypt_intermediate_r3": {
        "name": "Let's Encrypt R3",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
        "le_authority_name": "Let's Encrypt R3",
        "formfield_base": "le_r3_auth",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
    },
    "letsencrypt_intermediate_r4_cross": {
        "name": "Let's Encrypt R4 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r4-cross-signed.pem",
        "le_authority_name": "Let's Encrypt R4",
        "formfield_base": "le_r4_cross_signed",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "cross_signed_by": "trustid_root_x3",
    },
    "letsencrypt_intermediate_r4": {
        "name": "Let's Encrypt R4",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r4.pem",
        "le_authority_name": "Let's Encrypt R4",
        "formfield_base": "le_r4_auth",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
    },
    "letsencrypt_intermediate_e1": {
        "name": "Let's Encrypt E1",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-e1.pem",
        "le_authority_name": "Let's Encrypt E1",
        "formfield_base": "le_e1_auth",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "EC",  # ECDSA
        "signed_by": "isrg_root_x2",
    },
    "letsencrypt_intermediate_e2": {
        "name": "Let's Encrypt E2",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-e2.pem",
        "le_authority_name": "Let's Encrypt E2",
        "formfield_base": "le_e2_auth",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "EC",  # ECDSA
        "signed_by": "isrg_root_x2",
    },
    "letsencrypt_ocsp_root_x1": {
        "name": "Let's Encrypt E2",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-ocsp-x1.pem    ",
        "le_authority_name": "Let's Encrypt E2",
        "formfield_base": "le_e2_auth",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "EC",  # ECDSA
        "signed_by": "isrg_root_x1",
    },
    "staging_letsencrypt_root_x1": {
        "name": "Fake LE Root X1",
        "url_pem": "https://letsencrypt.org/certs/fakelerootx1.pem",
        "is_trusted_root": True,  # not really, but we pretend!
        "formfield_base": "fakelerootx1",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
    },
    "staging_letsencrypt_intermediate_x1": {
        "name": "Fake LE Intermediate X1",
        "url_pem": "https://letsencrypt.org/certs/fakeleintermediatex1.pem",
        "le_authority_name": "Fake LE Intermediate X1",
        "formfield_base": "fakeleintermediatex1",
        "is_active": True,
        "is_letsencrypt_certificate": True,
        "key_technology": "RSA",
        "signed_by": "staging_letsencrypt_root_x1",
    },
}


def download_letsencrypt_certificates():
    """
    download the known LetsEncrypt certificates

    * correct usage of `requests`
    - currently using `.content`, which is raw bytes
    - usually one uses `.text`, which is `.content` that is decoded
    - there was some concern that triggered this utf8 decode at some point...
    """
    certs = copy.deepcopy(CA_CERTS_DATA)
    for c in list(certs.keys()):
        resp = requests.get(certs[c]["url_pem"])
        if resp.status_code != 200:
            raise ValueError("Could not load certificate")
        cert_pem_text = resp.content
        cert_pem_text = cert_pem_text.decode("utf8")
        cert_pem_text = cert_utils.cleanup_pem_text(cert_pem_text)
        certs[c]["cert_pem"] = cert_pem_text
        certs[c]["cert_pem_md5"] = utils.md5_text(cert_pem_text)
    return certs
