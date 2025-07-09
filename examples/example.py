"""
This is an example script with narrative comments and print statements.

A streamlined version is available as `example-streamlined.py`
"""

# stdlib
import pprint

# pypi
import requests

# - - -

URL_BASE = "http://127.0.0.1:7201/.well-known/peter_sslers"

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
    import pprint

    pprint.pprint(_rjson)
    _default = _rjson["globals"]["default"]
    _backup = _rjson["globals"]["backup"]
    # the example would be too complex without these
    assert _default
    assert _backup
    print("")
    print("")
    print("Account Default: %s" % _default["id"])
    print("Account Backup: %s" % _backup["id"])

    # for each of these accounts, refresh their support aginst the acme-sever
    # to ensure we get the current profiles:

    r = requests.post(
        URL_BASE + "/acme-server/%s/check-support.json" % _default["acme_server_id"]
    )
    print("\n\nAcmeServer [Default] Support:")
    _rjson = r.json()
    pprint.pprint(_rjson)
    assert _rjson["result"] == "success"
    assert "AcmeServer" in _rjson
    assert "default" in _rjson["AcmeServer"]["profiles"]
    assert "shortlived" in _rjson["AcmeServer"]["profiles"]

    r = requests.post(
        URL_BASE + "/acme-server/%s/check-support.json" % _backup["acme_server_id"]
    )
    print("\n\nAcmeServer [Backup] Support:")
    _rjson = r.json()
    pprint.pprint(_rjson)
    assert _rjson["result"] == "success"
    assert "AcmeServer" in _rjson
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
            "account_key_option__primary": "account_key_global__primary",
            "account_key_global__primary": _default["AcmeAccountKey"]["key_pem_md5"],
            "acme_profile__primary": "shortlived",
            "private_key_cycle__primary": "account_default",
            "private_key_option__primary": "account_default",
            # backup cert
            "account_key_option__backup": "account_key_global__backup",
            "account_key_global__backup": _backup["AcmeAccountKey"]["key_pem_md5"],
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
