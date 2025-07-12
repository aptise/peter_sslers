"""
This script was written to generate the initial A records in Cloudflare for the
following domains:

    testing.opensource.aptise.com
    peter-sslers.testing.opensource.aptise.com
    (dns-01|http-01).[a-z].peter-sslers.testing.opensource.aptise.com


This script requires cloudflare python library version 2.x

    pip install --upgrade "cloudflare<3"

You MUST export the following

    export CLOUDFLARE_API_TOKEN="{YOUR_API_TOKEN}"
    export ROOT_DOMAIN="{YOUR_DOMAIN}"
    export CLOUDFLARE_ZONE_ID="{YOUR_ZONE_ID}"

e.g.

    export CLOUDFLARE_API_TOKEN="12345"
    export ROOT_DOMAIN="aptise.com"
    export CLOUDFLARE_ZONE_ID="abcd"
    export CLOUDFLARE_TARGET_IP="127.0.0.1"


"""

# stdlib
import os
from typing import Dict
from typing import List

# pypi
# pip install --upgrade "cloudflare<3"
import CloudFlare


ROOT_DOMAIN = os.environ.get("ROOT_DOMAIN")
CLOUDFLARE_ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID")
CLOUDFLARE_TARGET_IP = os.environ.get("CLOUDFLARE_TARGET_IP")

if not all((ROOT_DOMAIN, CLOUDFLARE_ZONE_ID, CLOUDFLARE_TARGET_IP)):
    raise ValueError("required ENV vars not found")

ALL_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".lower()
targeted_letters = ALL_LETTERS[:5]

# ==============================================================================


def ensure_test_zones(
    cf: CloudFlare.CloudFlare,  # must be RAW
    root_domain: str,
    zone_id: str,
    server_ipv4: str,
):
    DNS_RECORDS: Dict[str, List[Dict]] = {}
    next_page = 1
    while next_page:
        result = cf.zones.dns_records.get(
            zone_id, params={"page": next_page, "per_page": 100}
        )
        for _record in result["result"]:
            fqdn = _record["name"]
            if fqdn not in DNS_RECORDS:
                DNS_RECORDS[fqdn] = []
            DNS_RECORDS[fqdn].append(_record)
        next_page = result["result_info"]["page"] + 1
        if next_page > result["result_info"]["total_pages"]:
            next_page = 0

    domains_a = [
        "testing.opensource.%s" % root_domain,
        "peter-sslers.testing.opensource.%s" % root_domain,
    ]
    for letter in targeted_letters:
        for chall in ("dns-01", "http-01"):
            _domain = "%s.%s.peter-sslers.testing.opensource.%s" % (
                chall,
                letter,
                root_domain,
            )
            domains_a.append(_domain)
    for _domain in domains_a:
        print("---")
        print(_domain)
        if _domain in DNS_RECORDS:
            if len(DNS_RECORDS[_domain]) > 1:
                print("?!?", DNS_RECORDS[_domain])
                raise ValueError("What to do?")

            _record = DNS_RECORDS[_domain][0]

            # exit early for the next loop
            if (_record["type"] == "A") and (_record["content"] == server_ipv4):
                print("good!")
                continue

            print("delete existing!")
            # delete the existing record
            _api_result = cf.zones.dns_records.delete(zone_id, _record["id"])
            assert len(_api_result["result"].keys()) == 1
            assert _api_result["result"]["id"] == _record["id"]

        print("create new!")
        # create a new record; both new and deletes
        _record = {
            "name": _domain,
            "type": "A",
            "content": server_ipv4,
            "proxied": False,
        }
        _api_result_2 = cf.zones.dns_records.post(zone_id, data=_record)
        assert _api_result_2["result"]["name"] == _domain
        assert _api_result_2["result"]["type"] == "A"
        assert _api_result_2["result"]["content"] == server_ipv4


if __name__ == "__main__":
    assert ROOT_DOMAIN
    assert CLOUDFLARE_TARGET_IP
    assert CLOUDFLARE_ZONE_ID
    cf = CloudFlare.CloudFlare(raw=True)
    ensure_test_zones(
        cf,
        root_domain=ROOT_DOMAIN,
        zone_id=CLOUDFLARE_ZONE_ID,
        server_ipv4=CLOUDFLARE_TARGET_IP,
    )
