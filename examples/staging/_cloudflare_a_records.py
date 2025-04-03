# stdlib
from typing import Dict
from typing import List
from typing import Tuple

# pypi
# pip install --upgrade "cloudflare<3"
import CloudFlare


# ==============================================================================

def ensure_test_zones(
    cf: CloudFlare.CloudFlare,  # must be RAW
    zone_id: str,
    server_ipv4: str,
):
    DNS_RECORDS: Dict[str, List[Dict]] = {}
    next_page = 1
    while next_page:
        result = cf.zones.dns_records.get(zone_id, params={"page": next_page, "per_page": 100})
        for _record in result["result"]:
            fqdn = _record["name"]
            if fqdn not in DNS_RECORDS:
                DNS_RECORDS[fqdn] = []
            DNS_RECORDS[fqdn].append(_record)
        next_page = result["result_info"]["page"] + 1
        if next_page > result["result_info"]["total_pages"]:
            next_page = 0


    domains_a = [
        "testing.opensource.aptise.com",
        "peter-sslers.testing.opensource.aptise.com",
    ]
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ".lower():
        for chall in ("dns-01", "http-01"):
            _domain = "%s.%s.peter-sslers.testing.opensource.aptise.com" % (chall, letter)
            domains_a.append(_domain)
    for _domain in domains_a:
        if _domain in DNS_RECORDS:
            if len(DNS_RECORDS[_domain]) > 1:
                print("?!?", DNS_RECORDS[_domain])
                raise ValueError("What to do?")

            _record = DNS_RECORDS[_domain][0]

            # exit early for the next loop
            if (_record["type"] == "A") and (_record["content"] == server_ipv4):
                continue

            # delete the existing record
            _api_result = cf.zones.dns_records.delete(zone_id, _record["id"])
            assert len(_api_result["result"].keys()) == 1
            assert _api_result["result"]["id"] == _record["id"]

        # create a new record; both new and deletes
        _record = {"name": _domain, "type": "A", "content": server_ipv4, "proxied": False,}
        _api_result_2 = cf.zones.dns_records.post(zone_id, data=_record)
        assert _api_result["result"]["name"] = _domain
        assert _api_result["result"]["type"] = "A"
        assert _api_result["result"]["content"] = server_ipv4


if __name__ == "__main__":
    cf = CloudFlare.CloudFlare(raw=True)
    ensure_test_zones(
        cf,
        zone_id = "bda33f76b42c14e41ddb6494cc871ab6",  # aptise.com
        server_ipv4 = "66.228.44.231",  # linode ip
    )
