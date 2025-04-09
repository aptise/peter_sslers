"""
This script iterates over a `acme_dns_audit-accounts.json` file, and updates
Cloudflare records as needed.

This script requires::

    pip install --upgrade "cloudflare<3"
    export CLOUDFLARE_API_TOKEN="{YOUR_API_TOKEN}"
"""

import json
import sys
from typing import Dict
from typing import Union

# pip install --upgrade "cloudflare<3"
import CloudFlare
from typing_extensions import Literal

# ==============================================================================

filename = "acme_dns_audit-process_cloudflare.py"
if len(sys.argv) == 2:
    filename = sys.argv[1]

audit_results = json.loads(open(filename, "r").read())

CF_ZONES: Dict[str, Union[str, Literal[-1]]] = {}

cf = CloudFlare.CloudFlare(raw=True)

for result in audit_results:
    if result["registered_domain"] == "aptise.":
        continue

    domain_name = result["domain_name"]

    _errors_cname_source = [
        i for i in result["errors"] if result["errors"] and i.startswith("cname_source")
    ]
    _errors_cname_target = [
        i for i in result["errors"] if result["errors"] and i.startswith("cname_target")
    ]

    if not (_errors_cname_source or _errors_cname_target):
        print("nothing to do for ")
        continue

    if _errors_cname_source:

        # the cloudflare credentials will be on the registered_domain
        registered_domain = result["registered_domain"]
        zone_id = CF_ZONES.get(registered_domain)
        if zone_id is None:
            try:
                params = {"name": "aptise.com"}
                _api_result = cf.zones.get(params=params)
                zone_id = -1
                if _api_result["result"]:
                    zone_id = _api_result["result"][0]["id"]
                CF_ZONES[registered_domain] = zone_id
            except Exception:
                raise
        if zone_id == -1:
            print("bypassing %s; not on Cloudflare" % registered_domain)
            continue

        _cname_source = result["cname_source"]
        _cname_source = (
            _cname_source if _cname_source[-1] != "." else _cname_source[:-1]
        )
        if _cname_source[-1] == ".":
            _cname_source = _cname_source[:-1]
        try:
            _cname_target = result["cname_target"]
            _cname_target = (
                _cname_target if _cname_target[-1] != "." else _cname_target[:-1]
            )
            _record_target = {
                "name": _cname_source,
                "type": "CNAME",
                "content": _cname_target,
                "proxied": False,
            }
            _api_result = cf.zones.dns_records.get(
                zone_id, params={"name": _cname_source}
            )
            _write: bool = True
            if _api_result["result"]:
                if (_api_result["result"][0]["type"] == "CNAME") and (
                    _api_result["result"][0]["content"] == _cname_target
                ):
                    print("records match?!?", _cname_source)
                    _write = False
                else:
                    _record_id = _api_result["result"][0]["id"]
                    _api_result2 = cf.zones.dns_records.delete(zone_id, _record_id)
                    assert len(_api_result2["result"].keys()) == 1
                    assert _api_result2["result"]["id"] == _record_id
            if _write is True:
                _api_result3 = cf.zones.dns_records.post(zone_id, data=_record_target)
                assert _api_result3["result"]
                assert _api_result3["result"]["name"] == _cname_source
                assert _api_result3["result"]["type"] == "CNAME"
                assert _api_result3["result"]["content"] == _cname_target
        except Exception as exc:  # noqa: F841
            raise
