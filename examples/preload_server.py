"""

This script:

* Creates an EnrollmentFactory named `preload_server`
* Crates RenewalConfigration by enrolling multiple domains into the system via the `preload_server` EnrollmentFactory (based on the NATO alphabet)
* Orders a PRIMARY certificate for each RenewalConfigration

After running this script, run

    routine__automatic_orders data_staging/config.ini

the above command should order the backup certificates

This file is expected to run against 2 pebble accounts; this can be done using:

        python run_dev_servers.py

Do not run this against production servers.
"""

# stdlib
import pprint  # noqa: F401
from typing import Dict

# pypi
import requests

# - - -

URL_BASE = "http://127.0.0.1:5002/.well-known/peter_sslers"

# = = =

NATO_ALPHABET = [
    "alfa",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliett",
    "kilo",
    "lima",
    "mike",
    "november",
    "oscar",
    "papa",
    "quebec",
    "romeo",
    "sierra",
    "tango",
    "uniform",
    "victor",
    "whiskey",
    "xray",
    "yankee",
    "zulu",
]


#
# Because this is a test-system, in which the db is ephemeral due to testing
# and development, some work is required to ensure we get the right servers...
#
mapping = {
    "AcmeServer": {
        "primary": None,
        "backup": None,
    },
    "AcmeAccount": {
        "primary": None,
        "backup": None,
    },
    "EnrollmentFactory": {},
    "RenewalConfiguration": {},
}
#
# inspect the AcmeServers; targets MUST exist
#
r = requests.get(URL_BASE + "/acme-servers.json")
r_json = r.json()
for id_, acmeServer in r_json["AcmeServers"].items():
    if acmeServer["name"] == "pebble":
        mapping["AcmeServer"]["primary"] = acmeServer
    elif acmeServer["name"] == "pebble-alt":
        mapping["AcmeServer"]["backup"] = acmeServer
assert mapping["AcmeServer"]["primary"] is not None
assert mapping["AcmeServer"]["backup"] is not None
#
# inspect the AcmeAccounts; targets may or may not exist
#
r = requests.get(URL_BASE + "/acme-accounts.json")
r_json = r.json()
for id_, acmeAccount in r_json["AcmeAccounts"].items():
    if acmeAccount["acme_server_name"] == "pebble":
        mapping["AcmeAccount"]["primary"] = acmeAccount
    elif acmeAccount["acme_server_name"] == "pebble-alt":
        mapping["AcmeAccount"]["backup"] = acmeAccount


def new_account(acme_server_id: int) -> Dict:
    form = {
        "account__contact": "a@2xlp.com",
        "account__order_default_acme_server": "shortlived",
        "account__order_default_private_key_cycle": "single_use__reuse_1_year",
        "account__order_default_private_key_technology": "EC_P256",
        "account__private_key_technology": "EC_P256",
        "acme_server_id": acme_server_id,
    }
    r = requests.post(URL_BASE + "/acme-account/new.json", form)
    r_json = r.json()
    assert r_json["result"] == "success"
    return r_json["AcmeAccount"]


if not mapping["AcmeAccount"]["primary"]:
    mapping["AcmeAccount"]["primary"] = new_account(
        mapping["AcmeServer"]["primary"]["id"]
    )

if not mapping["AcmeAccount"]["backup"]:
    mapping["AcmeAccount"]["backup"] = new_account(
        mapping["AcmeServer"]["backup"]["id"]
    )


#
# Okay, setup is complete
#

#
# 1. Look to see if we have a `preload_server` EnrollmentFactory
# If not, create it
#
_exists = False
page = 1
while page:
    r = requests.get(URL_BASE + "/enrollment-factorys/%s.json" % page)
    r_json = r.json()
    for ef in r_json["EnrollmentFactorys"]:
        if ef["name"] == "preload_server":
            _exists = True
            mapping["EnrollmentFactory"][ef["name"]] = ef
            break
    if _exists:
        break
    page = r_json["pagination"]["page_next"]

if not _exists:
    print("Creating EnrollmentFactory...")

    # the NEW endpoint will document possible AcmeAccounts
    r = requests.get(URL_BASE + "/enrollment-factorys/new.json")
    r_json = r.json()
    # make sure our intended AcmeAcconts are the right ones!

    # the API provides a shortcut of valid options
    _acmeAccounts = {
        aa["id"]: aa["label"] for aa in r_json["valid_options"]["AcmeAccounts"]
    }

    # ensure the primary is in there, and on pebble
    assert mapping["AcmeAccount"]["primary"]["id"] in _acmeAccounts
    assert _acmeAccounts[mapping["AcmeAccount"]["primary"]["id"]].endswith("@ pebble")

    # ensure the backup is in there, and on pebble-alt
    assert mapping["AcmeAccount"]["backup"]["id"] in _acmeAccounts
    assert _acmeAccounts[mapping["AcmeAccount"]["backup"]["id"]].endswith(
        "@ pebble-alt"
    )

    form_data = {
        # core
        "domain_template_dns01": "",
        "domain_template_http01": "{DOMAIN}",
        "name": "preload_server",
        "note": "created by the preload_server script",
        # primary cert
        "acme_account_id__primary": mapping["AcmeAccount"]["primary"]["id"],
        "acme_profile__primary": "shortlived",
        "private_key_cycle__primary": "single_use__reuse_1_year",
        "private_key_technology__primary": "EC_P256",
        # backup cert
        "acme_account_id__backup": mapping["AcmeAccount"]["backup"]["id"],
        "acme_profile__backup": "shortlived",
        "private_key_cycle__backup": "single_use__reuse_1_year",
        "private_key_technology__backup": "EC_P256",
    }

    r = requests.post(URL_BASE + "/enrollment-factorys/new.json", form_data)
    r_json = r.json()
    assert r_json["result"] == "success"
    mapping["EnrollmentFactory"]["preload_server"] = r_json["EnrollmentFactory"]


# 2. enroll a domain for each letter of the alphabet

print("Creating RenewalConfigurations...")
ENROLLMENT_FACTORY_ID = mapping["EnrollmentFactory"]["preload_server"]["id"]
for phonetic in NATO_ALPHABET:
    r = requests.get(
        URL_BASE
        + "/renewal-configuration/new-enrollment.json?enrollment_factory_id=%s"
        % ENROLLMENT_FACTORY_ID
    )
    r_json = r.json()
    assert "form_fields" in r_json

    form_data = {
        "domain_name": "%s.com" % phonetic,
        "enrollment_factory_id": ENROLLMENT_FACTORY_ID,
        "note": "preload_server scripted",
    }
    r = requests.post(
        URL_BASE + "/renewal-configuration/new-enrollment.json", form_data
    )
    r_json = r.json()
    assert r_json["result"] == "success"
    mapping["RenewalConfiguration"][phonetic] = r_json["RenewalConfiguration"]
    if r_json["is_duplicate_renewal"]:
        print("RenewalConfiguration[%s] : already created" % phonetic)
    else:
        print("RenewalConfiguration[%s] : NEW" % phonetic)


# 3. loop our RenewalConfigurations to order certs
print("Ordering Certificates...")
for phonetic in mapping["RenewalConfiguration"].keys():
    rc_id = mapping["RenewalConfiguration"][phonetic]["id"]

    # only generate a primary cert; we can pull a backup via automated means
    if not mapping["RenewalConfiguration"][phonetic]["CertificateSigneds_5_primary"]:
        # r = requests.get(URL_BASE + "/renewal-configuration/%s/new-order.json" % rc_id)
        # r_json = r.json()
        form_data = {
            "processing_strategy": "process_single",
        }
        r = requests.post(
            URL_BASE + "/renewal-configuration/%s/new-order.json" % rc_id, form_data
        )
        r_json = r.json()
        assert r_json["result"] == "success"
        print(
            "RenewalConfiguration[%s|%s] : NEW Order [PRIMARY]"
            % (
                phonetic,
                rc_id,
            )
        )
    else:
        print(
            "RenewalConfiguration[%s|%s] : has certificates"
            % (
                phonetic,
                rc_id,
            )
        )
