# stdlib
from typing import Optional

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ...lib import db as lib_db
from ...model.objects import AcmeDnsServerAccount

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:acme_dns_server_accounts",
        renderer="/admin/acme_dns_server_accounts.mako",
    )
    @view_config(route_name="admin:acme_dns_server_accounts|json", renderer="json")
    @view_config(
        route_name="admin:acme_dns_server_accounts_paginated",
        renderer="/admin/acme_dns_server_accounts.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server_accounts_paginated|json", renderer="json"
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
