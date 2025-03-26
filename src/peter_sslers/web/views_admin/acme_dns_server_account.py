# stdlib
import csv
import tempfile
from typing import List
from typing import Optional

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.response import Response
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.handler import Handler
from ...lib import db as lib_db
from ...lib import utils_dns
from ...model.objects import AcmeDnsServerAccount

# ==============================================================================


def csv_AcmeDnsServerAccounts(
    items_paged: List["AcmeDnsServerAccount"],
) -> tempfile.SpooledTemporaryFile:

    fieldnames = [
        "id",
        "username",
        "password",
        "cname_source",
        "cname_target",
        "acme_dns_server_id",
        "acme_dns_server_domain",
        "acme_dns_server_api_url",
    ]
    tmpfile = tempfile.SpooledTemporaryFile(mode="w+t")
    writer = csv.DictWriter(tmpfile, fieldnames=fieldnames)
    writer.writeheader()
    for dbAcmeDnsServerAccount in items_paged:
        _row = {
            "id": dbAcmeDnsServerAccount.id,
            "username": dbAcmeDnsServerAccount.username,
            "password": dbAcmeDnsServerAccount.password,
            "cname_source": dbAcmeDnsServerAccount.cname_source,
            "cname_target": dbAcmeDnsServerAccount.cname_target,
            "acme_dns_server_id": dbAcmeDnsServerAccount.acme_dns_server.id,
            "acme_dns_server_domain": dbAcmeDnsServerAccount.acme_dns_server.domain,
            "acme_dns_server_api_url": dbAcmeDnsServerAccount.acme_dns_server.api_url,
        }
        writer.writerow(_row)
    tmpfile.seek(0)
    return tmpfile


class View_List(Handler):
    @view_config(
        route_name="admin:acme_dns_server_accounts",
        renderer="/admin/acme_dns_server_accounts.mako",
    )
    @view_config(route_name="admin:acme_dns_server_accounts|json", renderer="json")
    @view_config(
        route_name="admin:acme_dns_server_accounts-paginated",
        renderer="/admin/acme_dns_server_accounts.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server_accounts-paginated|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-dns-server-accounts.json",
            "section": "acme-dns-server-account",
            "about": """list AcmeDnsServerAccounts(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-dns-server-accounts.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-dns-server-accounts/{PAGE}.json",
            "section": "acme-dns-server-account",
            "example": "curl {ADMIN_PREFIX}/acme-dns-server-accounts/1.json",
            "variant_of": "/acme-dns-server-accounts.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__AcmeDnsServerAccount__count(
            self.request.api_context
        )
        items_paged = lib_db.get.get__AcmeDnsServerAccount__paginated(
            self.request.api_context
        )
        if self.request.wants_json:
            return {
                "AcmeDnsServerAccounts": [s.as_json for s in items_paged],
                "AcmeDnsServerAccounts_count": items_count,
            }
        return {
            "project": "peter_sslers",
            "AcmeDnsServerAccounts": items_paged,
            "AcmeDnsServerAccounts_count": items_count,
        }

    @view_config(route_name="admin:acme_dns_server_accounts:all|csv")
    def list_accounts_all_csv(self):
        self._focus_url = "%s/acme-dns-server-accounts" % (self.request.admin_url)
        if self.request.method != "POST":
            url_post_required = (
                "%s?result=error&error=post+required&operation=csv" % self._focus_url
            )
            return HTTPSeeOther(url_post_required)

        items_paged = lib_db.get.get__AcmeDnsServerAccount__paginated(
            self.request.api_context
        )
        try:
            # this is dirty
            # 1- loading ALL items from the db, no windows or anything
            # 2- csv needs a string file, so we write to a TEXT tempfile
            # 3- Response `body_file` needs bytes, so we read that entire TEXT to submit as `body` which is the only way to handle strings
            tmpfile = csv_AcmeDnsServerAccounts(items_paged)
            response = Response(
                content_type="text/csv", body=tmpfile.read(), status=200
            )
            response.headers["Content-Disposition"] = (
                "attachment; filename= acme_dns_server-accounts.csv"
            )
            return response

        except Exception as exc:  # noqa: F841
            return HTTPSeeOther(
                "%s?result=error&error=could+not+generate+csv" % self._focus_url
            )

    @view_config(route_name="admin:acme_dns_server_accounts:all|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-dns-server-accounts/all.json",
            "section": "acme-dns-server-accounts",
            "about": """list AcmeDns Server Accounts(s)""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/acme-dns-server-accounts/all.json",
        }
    )
    def list_accounts_all_json(self):
        self._focus_url = "%s/acme-dns-server-accounts" % (self.request.admin_url)
        if self.request.method != "POST":
            return formatted_get_docs(self, "/acme-dns-server-accounts/all.json")

        items_count = lib_db.get.get__AcmeDnsServerAccount__count(
            self.request.api_context
        )
        items_paged = lib_db.get.get__AcmeDnsServerAccount__paginated(
            self.request.api_context
        )
        return {
            "AcmeDnsServerAccounts": [s.as_json for s in items_paged],
            "AcmeDnsServerAccounts_count": items_count,
        }


class View_Focus(Handler):
    dbAcmeDnsServerAccount: Optional[AcmeDnsServerAccount] = None

    def _focus(self, eagerload_web=False) -> AcmeDnsServerAccount:
        if self.dbAcmeDnsServerAccount is None:
            dbAcmeDnsServerAccount = lib_db.get.get__AcmeDnsServerAccount__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbAcmeDnsServerAccount:
                raise HTTPNotFound("the acme-dns server account was not found")
            self.dbAcmeDnsServerAccount = dbAcmeDnsServerAccount
            self._focus_url = "%s/acme-dns-server-account/%s" % (
                self.request.admin_url,
                self.dbAcmeDnsServerAccount.id,
            )
        return self.dbAcmeDnsServerAccount

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_dns_server_account:focus",
        renderer="/admin/acme_dns_server_account-focus.mako",
    )
    @view_config(route_name="admin:acme_dns_server_account:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-dns-server-account/{ID}.json",
            "section": "acme-dns-server-account",
            "about": """AcmeDnsServerAccount""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-dns-server-account/1.json",
        }
    )
    def focus(self):
        dbAcmeDnsServerAccount = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "AcmeDnsServerAccount": dbAcmeDnsServerAccount.as_json,
            }
        return {
            "project": "peter_sslers",
            "AcmeDnsServerAccount": dbAcmeDnsServerAccount,
        }

    @view_config(
        route_name="admin:acme_dns_server_account:focus:audit",
        renderer="/admin/acme_dns_server_account-focus-audit.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server_account:focus:audit|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-dns-server-account/{ID}/audit.json",
            "section": "acme-dns-server-account",
            "about": """AcmeDnsServerAccount audit""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/acme-dns-server-account/1/audit.json",
        }
    )
    def audit(self):

        dbAcmeDnsServerAccount = self._focus(eagerload_web=True)  # noqa: F841
        if self.request.method == "POST":
            return self._audit__submit()
        return self._audit__print()

    def _audit__print(self):
        dbAcmeDnsServerAccount = self._focus(eagerload_web=True)  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-dns-server-account/{ID}/audit.json")
        url_post_required = "%s?result=error&error=post+required&operation=audit" % (
            self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _audit__submit(self):
        dbAcmeDnsServerAccount = self._focus(eagerload_web=True)
        auditResults = utils_dns.audit_AcmeDnsSererAccount(
            self.request.api_context,
            dbAcmeDnsServerAccount=dbAcmeDnsServerAccount,
        )

        if self.request.wants_json:
            return {
                "result": "success",
                "AcmeDnsServerAccount": dbAcmeDnsServerAccount.as_json,
                "audit": auditResults,
            }
        return {
            "project": "peter_sslers",
            "AcmeDnsServerAccount": dbAcmeDnsServerAccount,
            "AuditResults": auditResults,
        }
