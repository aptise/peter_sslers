from . import _disable_warnings  # noqa:F401

# stdlib
import csv  # noqa: I100
import json
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
    registered_domain: str
    domain_name: str
    cname_source: str
    cname_target: str
    errors: Optional[List[str]]


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

    # first, ensure all our domains have accounts
    results = lib_db.actions.acme_dns__ensure_accounts(
        ctx,
        acknowledge_transaction_commits=True,
    )
    print("acme_dns__ensure_accounts(existing, new) ==", results)

    audits = []
    acmeDnsServerAccounts = lib_db.get.get__AcmeDnsServerAccount__paginated(ctx)
    for dbAcmeDnsServerAccount in acmeDnsServerAccounts:
        print(
            "auditing:",
            dbAcmeDnsServerAccount.id,
            dbAcmeDnsServerAccount.domain.domain_name,
        )
        _audit = utils_dns.audit_AcmeDnsSererAccount(ctx, dbAcmeDnsServerAccount)
        _row: AccountAudit = {
            "id": dbAcmeDnsServerAccount.id,
            "registered_domain": dbAcmeDnsServerAccount.domain.registered_domain,
            "domain_name": dbAcmeDnsServerAccount.domain.domain_name,
            "cname_source": dbAcmeDnsServerAccount.cname_source,
            "cname_target": dbAcmeDnsServerAccount.cname_target,
            "errors": _audit["errors"],
        }
        audits.append(_row)

    if not audits:
        print("No AcmeDnsServerAccounts to audit")

    _format = options.get("format")
    if _format not in ("csv", "json"):
        _format = "csv"
    if _format == "csv":
        print("OUTPUTTING: acme_dns_audit-accounts.csv")
        with open("acme_dns_audit-accounts.csv", "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=audits[0].keys())
            writer.writeheader()
            for audit in audits:
                writer.writerow(audit)
    elif _format == "json":
        print("OUTPUTTING: acme_dns_audit-accounts.json")
        with open("acme_dns_audit-accounts.json", "w") as jsonfile:
            json.dump(audits, jsonfile)
