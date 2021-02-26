# stdlib
import copy
import datetime
import os

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

# this info is checked for compliance with
# * tests.test_unit.UnitTest_LetsEncrypt_Data


CERT_CAS_VERSION = 2  # update when the information below changes
"""
format details:

the KEY in the dictionary is a unique string

the payload can have one of these two values, which reference another key:
    "alternates": ["isrg_root_x2_cross"],
    "alternate_of": "isrg_root_x2",
    
Special Values
    ".enddate": the args to datetime.datetime()

"""
CERT_CAS_DATA = {
    "trustid_root_x3": {
        "display_name": "DST Root CA X3",
        "url_pem": "https://letsencrypt.org/certs/trustid-x3-root.pem",
        "is_trusted_root": True,
        "is_self_signed": True,
        "signed_by": "trustid_root_x3",
        "is_active": True,
        "key_technology": "RSA",
        "cert.fingerprints": {
            "sha1": "DA:C9:02:4F:54:D8:F6:DF:94:93:5F:B1:73:26:38:CA:6A:D7:7C:13",
        },
        ".enddate": (2021, 9, 30, 14, 1, 15),
    },
    "isrg_root_x1": {
        "display_name": "ISRG Root X1",
        "url_pem": "https://letsencrypt.org/certs/isrgrootx1.pem",
        "is_trusted_root": True,
        "is_self_signed": True,
        "signed_by": "isrg_root_x1",
        "is_active": True,
        "key_technology": "RSA",
        "alternates": ["isrg_root_x1_cross"],
        "cert.fingerprints": {
            "sha1": "CA:BD:2A:79:A1:07:6A:31:F2:1D:25:36:35:CB:03:9D:43:29:A5:E8",
        },
        ".enddate": (2035, 6, 4, 11, 4, 38),
    },
    "isrg_root_x1_cross": {
        # x1 this is cross signed by x1 to act as an intermediate!
        "display_name": "ISRG Root X1 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-x1-cross-signed.pem",
        "is_trusted_root": False,
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "isrg_root_x1",
    },
    "isrg_root_x2": {
        # x2 is self-signed by default, but is available as cross-signed by isrgrootx1
        "display_name": "ISRG Root X2",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-x2.pem",
        "is_trusted_root": True,
        "is_self_signed": True,
        "signed_by": "isrg_root_x2",
        "is_active": True,
        "key_technology": "EC",  # ECDSA
        "alternates": ["isrg_root_x2_cross"],
        "cert.fingerprints": {
            "sha1": "BD:B1:B9:3C:D5:97:8D:45:C6:26:14:55:F8:DB:95:C7:5A:D1:53:AF",
        },
        ".enddate": (2040, 9, 17, 16, 0),
    },
    "isrg_root_x2_cross": {
        # x2 this is cross signed by x1 to act as an intermediate!
        "display_name": "ISRG Root X2 (Cross-signed by ISRG Root X1)",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem",
        "is_trusted_root": False,
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternate_of": "isrg_root_x2",
    },
    "letsencrypt_ocsp_root_x1": {
        "display_name": "Let's Encrypt OSCP Root X1",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-ocsp-x1.pem",
        "is_active": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
    },
    "letsencrypt_intermediate_x1": {
        "display_name": "Let's Encrypt Authority X1",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx1.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_x1_cross"],
        "letsencrypt_serial": "x1",
    },
    "letsencrypt_intermediate_x1_cross": {
        "display_name": "Let's Encrypt Authority X1 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_x1",
        "letsencrypt_serial": "x1",
    },
    "letsencrypt_intermediate_x2": {
        "display_name": "Let's Encrypt Authority X2",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx2.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_x2_cross"],
        "letsencrypt_serial": "x2",
    },
    "letsencrypt_intermediate_x2_cross": {
        "display_name": "Let's Encrypt Authority X2 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_x2",
        "letsencrypt_serial": "x2",
    },
    "letsencrypt_intermediate_x3": {
        "display_name": "Let's Encrypt Authority X3",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx3.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_x3_cross"],
        "letsencrypt_serial": "x3",
    },
    "letsencrypt_intermediate_x3_cross": {
        "display_name": "Let's Encrypt Authority X3 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_x3",
        "letsencrypt_serial": "x3",
    },
    "letsencrypt_intermediate_x4": {
        "display_name": "Let's Encrypt Authority X4",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx4.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_x4_cross"],
        "letsencrypt_serial": "x4",
    },
    "letsencrypt_intermediate_x4_cross": {
        "display_name": "Let's Encrypt Authority X4 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_x4",
        "letsencrypt_serial": "x4",
    },
    "letsencrypt_intermediate_r3": {
        "display_name": "Let's Encrypt R3",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
        "is_active": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_r3_cross"],
        "letsencrypt_serial": "r3",
    },
    "letsencrypt_intermediate_r3_cross": {
        "display_name": "Let's Encrypt R3 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem",
        "is_active": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_r3",
        "letsencrypt_serial": "r3",
    },
    "letsencrypt_intermediate_r4": {
        "display_name": "Let's Encrypt R4",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r4.pem",
        "is_active": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_r4_cross"],
        "letsencrypt_serial": "r4",
    },
    "letsencrypt_intermediate_r4_cross": {
        "display_name": "Let's Encrypt R4 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r4-cross-signed.pem",
        "is_active": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_r4",
        "letsencrypt_serial": "r4",
    },
    "letsencrypt_intermediate_e1": {
        "display_name": "Let's Encrypt E1",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-e1.pem",
        "is_active": True,
        "key_technology": "EC",  # ECDSA
        "signed_by": "isrg_root_x2",
        "letsencrypt_serial": "e1",
    },
    "letsencrypt_intermediate_e2": {
        "display_name": "Let's Encrypt E2",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-e2.pem",
        "is_active": True,
        "key_technology": "EC",  # ECDSA
        "signed_by": "isrg_root_x2",
        "letsencrypt_serial": "e2",
    },
    "staging_letsencrypt_root_x1": {
        "display_name": "Fake LE Root X1",
        "url_pem": "https://letsencrypt.org/certs/fakelerootx1.pem",
        "is_trusted_root": True,  # not really, but we pretend!
        "is_self_signed": True,
        "is_active": True,
        "key_technology": "RSA",
        "signed_by": "staging_letsencrypt_root_x1",
    },
    "staging_letsencrypt_intermediate_x1": {
        "display_name": "Fake LE Intermediate X1",
        "url_pem": "https://letsencrypt.org/certs/fakeleintermediatex1.pem",
        "is_active": True,
        "key_technology": "RSA",
        "signed_by": "staging_letsencrypt_root_x1",
    },
}


# what are our default root preferences?
DEFAULT_CA_PREFERENCES = [
    "trustid_root_x3",
    "isrg_root_x2",
    "isrg_root_x1",
]


# these should be a listing of serials
# e.g.: ("x1", "x2", "x3", "x4", "r3", "r4", "e1", "e2")
CA_LE_INTERMEDIATES = []
CA_LE_INTERMEDIATES_CROSSED = []
for _cert_id, _payload in CERT_CAS_DATA.items():
    _serial = _payload.get("letsencrypt_serial")
    if not _serial:
        continue
    if not _payload.get("alternate_of"):
        if not _payload.get("is_trusted_root"):
            CA_LE_INTERMEDIATES.append(_serial)
    else:
        CA_LE_INTERMEDIATES_CROSSED.append(_serial)


# LOAD THE CERTS INTO THE SYSTEM
_dir_here = os.path.abspath(os.path.dirname(__file__))
_dir_certs = os.path.join(_dir_here, "letsencrypt-certs")
for cert_id, cert_data in CERT_CAS_DATA.items():
    _filename = cert_data["url_pem"].split("/")[-1]
    _filepath = os.path.join(_dir_certs, _filename)
    with open(_filepath, "r") as _fp:
        cert_pem_text = _fp.read()
        # cert_pem_text = cert_pem_text.decode("utf8")
        cert_pem_text = cert_utils.cleanup_pem_text(cert_pem_text)
        cert_data["cert_pem"] = cert_pem_text


def download_letsencrypt_certificates():
    """
    DEPRECATED

    nothing calls this. may be useful for testing to ensure the certs have not
    changed on disk, such as the whitespace issue in 2021/02

    download the known LetsEncrypt certificates

    * correct usage of `requests`
    - currently using `.content`, which is raw bytes
    - usually one uses `.text`, which is `.content` that is decoded
    - there was some concern that triggered this utf8 decode at some point...
    """
    # ???: raise Exception if the cert_pem changes?
    certs = copy.deepcopy(CERT_CAS_DATA)
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
