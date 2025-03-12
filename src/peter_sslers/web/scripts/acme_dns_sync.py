from . import _disable_warnings  # noqa:F401

# stdlib
import csv  # noqa: I100
import os
import sys
from typing import List
from typing import Optional

# pypi
from pyramid.scripts.common import parse_vars
from typing_extensions import TypedDict

# local
from ...lib import db as lib_db
from ...lib import utils_dns
from ...lib.utils import new_scripts_setup

# from ...lib import acmedns as lib_acmedns

# ==============================================================================


class AccountAudit(TypedDict):
    id: int
    status: bool
    domain_name: str
    cname_source: str
    cname_target: str
    actual_cname: Optional[List[str]]
    actual_txt: Optional[List[str]]


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> [var=value]\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])

    ctx = new_scripts_setup(config_uri, options=options)

    audits = []
    acmeDnsAccounts = lib_db.get.get__AcmeDnsServerAccount__paginated(ctx)
    for acc in acmeDnsAccounts:
        r_cname = utils_dns.get_records(acc.cname_source, "CNAME")
        r_txt = utils_dns.get_records(acc.cname_source, "TXT")
        _status = True if r_cname == acc.cname_target else False
        if not _status:
            _audit: AccountAudit = {
                "id": acc.id,
                "status": _status,
                "domain_name": acc.domain.domain_name,
                "cname_source": acc.cname_source,
                "cname_target": acc.cname_target,
                "actual_cname": r_cname,
                "actual_txt": r_txt,
            }
            audits.append(_audit)

    if audits:
        with open("acme_dns_audit.csv", "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=audits[0].keys())
            writer.writeheader()
            for audit in audits:
                writer.writerow(audit)
