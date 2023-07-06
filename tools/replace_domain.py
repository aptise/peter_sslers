"""
This is an EXPERIMENTAL tool for manipulating an acme-dns database.

An early attempt to use acme-dns for PAAS/SAAS clients was to pre-generate a large
number of account+domain combinations in acme-dns, and then assign the domains
to customers on-demand.

The flow:

    Client reads docs on how to get a SSL Certificate from Vendor
    Client asks Vendor for HTTPS Certificate
    Vendor creates acme-dns account
    Vendor provides Client with acme-dns Account
    Client CNAMES _acme-challenge onto Vendor identified subdomain
    Client notifies Vendor
    Vendor provisions SSL Certificate

The goal of this script is a better approach: generate the acme-dns credentials
on-demand, but then update the domains to something predictable. This approach
allows a PAAS/SAAS host to instruct the client on how to setup the acme-challenge
without having to create an acme-dns account first.

The flow:

    Client reads docs on how to get a SSL Certificate from Vendor
    Client CNAMES _acme-challenge onto predictable subdomain
    Client notifies Vendor
    Vendor creates acme-dns account
    Vendor renames domain in acme-dns
    Vendor provisions SSL Certificate

This requires a recent version of acme-dns, since the following pull was merged:

    https://github.com/joohoi/acme-dns/pull/243

Why?

This strategy will allow a whitelabel/hosting service/pass/saas system to give
their customers a simle predictable domain to CNAME _acme_challenge TXT
records onto.

acme-dns is popular and stable. not everyone has the resources to build a dns/api
system from scratch, or to fork the acme-dns project into providing more specific
functionality.

For example:

    # acme-dns generates a subdomain with a random uuid
    domain = "8e5700ea-a4bf-41c7-8a77-e990661dcc6a.auth.acme-dns.io"

    # the customer's domain is "customer1.example.com"
    python replace_domain("8e5700ea-a4bf-41c7-8a77-e990661dcc6a", "customer1.example.com")

    # the new domain in acme-dns is now
    domain = "customer1.example.com.auth.acme-dns.io"

Because the domains are predictable, there is not back-and-forth between
the participants in this process.

To use:

    export ACMEDNS_DB=/path/to/file
    python replace_domain.py {OLD_DOMAIN} {NEW_DOMAIN}
"""

# stdlib
import os
import re
import sqlite3
import sys

# ==============================================================================

_args = sys.argv
try:
    if len(_args) != 3:
        raise ValueError("wrong number of args")
    (_subdomain_old, _subdomain_new) = _args[1:3]
    if not all((_subdomain_old, _subdomain_new)):
        raise ValueError("Missing old or new subdomain")
    # validate the domain inputs
    _regex_subdomain = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")
    if not _regex_subdomain.match(_subdomain_old):
        raise ValueError("Invalid domain: old")
    if not _regex_subdomain.match(_subdomain_new):
        raise ValueError("Invalid domain: new")

except Exception as exc:  # noqa: F841
    print(r"Please invoke this as `replace_domain.py {OLD_DOMAIN} {NEW_DOMAIN}`")
    raise

_database_path = os.environ.get("ACMEDNS_DB", "acme-dns.db")
print("Using acme-dns database at: %s" % _database_path)
if not os.path.exists(_database_path):
    raise ValueError(
        "XXX Invalid Database Path. Please override with `ACMEDNS_DB=` environment variable"
    )

with sqlite3.connect(_database_path) as connection:
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM records WHERE subdomain=?", (_subdomain_new,))
    row = cursor.fetchone()
    if row is not None:
        raise ValueError("New Subdomain already in acme-dns")

    cursor.execute("SELECT * FROM records WHERE subdomain=?", (_subdomain_old,))
    row = cursor.fetchone()
    if row is None:
        raise ValueError("Old Subdomain not found in acme-dns")

    print("updating the database...")
    if True:
        # don't update the records, because we need that for auth?
        cursor.execute(
            "UPDATE records SET subdomain=? WHERE subdomain=?",
            (_subdomain_new, _subdomain_old),
        )
    cursor.execute(
        "UPDATE txt SET subdomain=? WHERE subdomain=?", (_subdomain_new, _subdomain_old)
    )
    connection.commit()
    print("done!")
