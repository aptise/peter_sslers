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
r = requests.post(URL_BASE + "/domains/search.json", {"domain": domain_name})
_rjson = r.json()
assert _rjson["result"] == "success"
if _rjson["search_results"]["Domain"]:
    domain_id = _rjson["search_results"]["Domain"]["id"]
    # update cached info
    r = requests.post(URL_BASE + "/api/update-recents.json")
else:
    r = requests.post(URL_BASE + "/domain/new.json", {"domain_name": domain_name})
    _rjson = r.json()
    assert _rjson["result"] == "success"
    assert _rjson["is_created"] is True
    domain_id = _rjson["Domain"]["id"]

# Get the domain record;
r = requests.get(URL_BASE + "/domain/%s.json" % domain_id)
_rjson = r.json()
domain_primary_certs = _rjson["Domain"]["certificate_signeds__single_primary_5"]
if not domain_primary_certs:
    r = requests.get(URL_BASE + "/acme-accounts.json")
    _rjson = r.json()
    _default = _rjson["globals"]["default"]
    _backup = _rjson["globals"]["backup"]
    assert _default
    assert _backup

    # for each of these accounts, refresh their support aginst the acme-sever
    # to ensure we get the current profiles:
    r = requests.post(
        URL_BASE + "/acme-server/%s/check-support.json" % _default["acme_server_id"]
    )
    _rjson = r.json()
    assert _rjson["result"] == "success"
    assert "AcmeServer" in _rjson
    assert "default" in _rjson["AcmeServer"]["profiles"]
    assert "shortlived" in _rjson["AcmeServer"]["profiles"]

    r = requests.post(
        URL_BASE + "/acme-server/%s/check-support.json" % _backup["acme_server_id"]
    )
    _rjson = r.json()
    assert _rjson["result"] == "success"
    assert "AcmeServer" in _rjson
    assert "default" in _rjson["AcmeServer"]["profiles"]
    assert "shortlived" in _rjson["AcmeServer"]["profiles"]

    # Check to see if there are any potential renewal configurations
    r = requests.get(
        URL_BASE + "/domain/%s/renewal-configurations/single.json" % domain_id
    )
    _rjson = r.json()
    if not _rjson["RenewalConfigurations"]:
        form = {
            "account_key_option": "account_key_global_default",
            "account_key_global_default": _default["AcmeAccountKey"]["key_pem_md5"],
            "profile": "shortlived",
            "account_key_option__backup": "account_key_global__backup",
            "account_key_global__backup": _backup["AcmeAccountKey"]["key_pem_md5"],
            "profile": "shortlived",
            "key_technology": "account_default",
            "private_key_cycle": "account_default",
            "private_key_option": "account_default",
            "domain_names_http01": domain_name,
            "processing_strategy": "process_single",
            "note": "API Request; Record X",
        }
        r = requests.post(URL_BASE + "/acme-order/new/freeform.json", form)
        _rjson = r.json()
        assert "AcmeOrder" in _rjson

r = requests.get(URL_BASE + "/domain/%s.json" % domain_id)
_rjson = r.json()

# these are the last 5 certs for ONLY this domain
assert len(_rjson["Domain"]["certificate_signeds__single_primary_5"]) >= 1
cert_id = _rjson["Domain"]["certificate_signeds__single_primary_5"][0]["id"]

r = requests.get(URL_BASE + "/certificate-signed/%s/config.json" % cert_id)
print("\n\nCert Config:")
_rjson = r.json()
pprint.pprint(_rjson)
