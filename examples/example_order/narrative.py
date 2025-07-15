"""
This is an example script with narrative comments and print statements.

A streamlined version is available as `streamlined.py`

This script expects a peter_sslers instance running on `URL_BASE`.

Using three Terminal windows:

    Terminal 1 - PeterSSLers WebApp
        pserve --reload data_testing/config.ini

    Terminal 2 - Two (2) Pebble Servers
        python run_dev_servers.py

    Terminal 3 - This script
        python example.py
"""

# stdlib
import pprint

# pypi
import requests

# - - -

URL_BASE = "http://127.0.0.1:5002/.well-known/peter_sslers"

# = = =

# is the domain registered on the system?

domain_name: str = "example-script.example.com"
domain_id: int

# domain existence
# show instructions
r = requests.get(URL_BASE + "/domains/search.json")
print("\n\nSearch Instructions:")
pprint.pprint(r.json())
r = requests.post(URL_BASE + "/domains/search.json", {"domain": domain_name})
print("\n\nSearch Query:")
_rjson = r.json()
pprint.pprint(_rjson)
assert _rjson["result"] == "success"
if _rjson["search_results"]["Domain"]:
    domain_id = _rjson["search_results"]["Domain"]["id"]

    # run the db calculations; should be done daily
    # this just ensures the cached `latest` records are updated
    r = requests.post(URL_BASE + "/api/update-recents.json")
    print("\n\nUpdate Recents:")
    pprint.pprint(r.json())

else:
    # New Domain: show instructions
    r = requests.get(URL_BASE + "/domain/new.json")
    print("\n\nNew Instructions:")
    print(r.json())

    # Create the domain
    r = requests.post(URL_BASE + "/domain/new.json", {"domain_name": domain_name})
    print("\n\nCreated:")
    _rjson = r.json()
    pprint.pprint(_rjson)
    assert _rjson["result"] == "success"
    assert _rjson["is_created"] is True
    domain_id = _rjson["Domain"]["id"]

# Get the domain record;
r = requests.get(URL_BASE + "/domain/%s.json" % domain_id)
print("\n\nDomain Record:")
_rjson = r.json()
pprint.pprint(_rjson)

# these are the last 5 certs for ONLY this domain
domain_primary_certs = _rjson["Domain"]["certificate_signeds__single_primary_5"]
if not domain_primary_certs:

    # The globals can be grabbed from the main accounts page...
    # BUT The globals are also inserted into the GET view of forms
    r = requests.get(URL_BASE + "/acme-accounts.json")
    _rjson = r.json()

    pprint.pprint(_rjson)

    # the example would be too complex without these
    _global = _rjson["SystemConfiguration_global"]

    acme_account_id__primary = _global["acme_account_id__primary"]
    acme_server_id__primary = _global["acme_server_id__primary"]
    assert acme_account_id__primary
    assert acme_server_id__primary
    print("")
    print("")
    print("ACME Account ID Primary: %s" % acme_account_id__primary)
    print("ACME Server ID Primary: %s" % acme_server_id__primary)

    acme_account_id__backup = _global["acme_account_id__backup"]
    acme_server_id__backup = _global["acme_server_id__backup"]
    assert acme_account_id__backup
    assert acme_server_id__backup
    print("")
    print("")
    print("ACME Account ID Backup: %s" % acme_account_id__backup)
    print("ACME Server ID Backup: %s" % acme_server_id__backup)

    # for each of these accounts, refresh their support aginst the acme-sever
    # to ensure we get the current profiles:

    r = requests.post(
        URL_BASE + "/acme-server/%s/check-support.json" % acme_server_id__primary
    )
    print("\n\nAcmeServer [Primary] Support:")
    _rjson = r.json()
    pprint.pprint(_rjson)
    assert _rjson["result"] == "success"
    assert "AcmeServer" in _rjson
    assert _rjson["AcmeServer"]["name"] == "pebble"
    assert "default" in _rjson["AcmeServer"]["profiles"]
    assert "shortlived" in _rjson["AcmeServer"]["profiles"]

    r = requests.post(
        URL_BASE + "/acme-server/%s/check-support.json" % acme_server_id__backup
    )
    print("\n\nAcmeServer [Backup] Support:")
    _rjson = r.json()
    pprint.pprint(_rjson)
    assert _rjson["result"] == "success"
    assert "AcmeServer" in _rjson
    assert _rjson["AcmeServer"]["name"] == "pebble-alt"
    assert "default" in _rjson["AcmeServer"]["profiles"]
    assert "shortlived" in _rjson["AcmeServer"]["profiles"]

    # Check to see if there are any potential renewal configurations
    r = requests.get(
        URL_BASE + "/domain/%s/renewal-configurations/single.json" % domain_id
    )
    _rjson = r.json()
    pprint.pprint(_rjson)

    if not _rjson["RenewalConfigurations"]:

        r = requests.get(URL_BASE + "/acme-order/new/freeform.json")
        print("\n\nAcmeOrder New Freeform - Instructions:")
        _rjson = r.json()
        pprint.pprint(_rjson)

        form = {
            # core
            "domain_names_http01": domain_name,
            "processing_strategy": "process_single",
            "note": "API Request; Record X",
            # primary cert
            "account_key_option__primary": "acme_account_id",
            "acme_account_id__primary": acme_account_id__primary,
            "acme_profile__primary": "shortlived",
            "private_key_cycle__primary": "account_default",
            "private_key_option__primary": "account_default",
            # backup cert
            "account_key_option__backup": "acme_account_id",
            "acme_account_id__backup": acme_account_id__backup,
            "acme_profile__backup": "shortlived",
            "private_key_cycle__backup": "account_default",
            "private_key_option__backup": "account_default",
        }
        print("Making the order... (this can take a bit)")
        r = requests.post(URL_BASE + "/acme-order/new/freeform.json", form)
        print("\n\nAcmeOrder New Freeform Result:")
        _rjson = r.json()
        pprint.pprint(_rjson)


r = requests.get(URL_BASE + "/domain/%s.json" % domain_id)
print("\n\nDomain Record:")
_rjson = r.json()
pprint.pprint(_rjson)

# these are the last 5 certs for ONLY this domain
assert len(_rjson["Domain"]["certificate_signeds__single_primary_5"]) >= 1

cert_id = _rjson["Domain"]["certificate_signeds__single_primary_5"][0]["id"]

r = requests.get(URL_BASE + "/certificate-signed/%s.json" % cert_id)
print("\n\nCert Record:")
_rjson = r.json()
pprint.pprint(_rjson)
pkey_id = _rjson["CertificateSigned"]["private_key_id"]

r = requests.get(URL_BASE + "/private-key/%s.json" % pkey_id)
print("\n\nPrivate Key Record:")
_rjson = r.json()
pprint.pprint(_rjson)


r = requests.get(URL_BASE + "/certificate-signed/%s/config.json" % cert_id)
print("\n\nCert Config:")
_rjson = r.json()
pprint.pprint(_rjson)
