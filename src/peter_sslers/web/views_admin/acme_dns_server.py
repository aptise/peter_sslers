# stdlib
import csv
import tempfile
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
import cert_utils
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.response import Response
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_AcmeDnsServer_edit
from ..lib.forms import Form_AcmeDnsServer_ensure_domains
from ..lib.forms import Form_AcmeDnsServer_import_domain
from ..lib.forms import Form_AcmeDnsServer_mark
from ..lib.forms import Form_AcmeDnsServer_new
from ..lib.handler import Handler
from ...lib import acmedns as lib_acmedns
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...lib.utils import new_BrowserSession
from ...model import utils as model_utils
from ...model.objects import AcmeDnsServer

if TYPE_CHECKING:
    from pyramid.request import Request
    from ...lib.db.associate import TYPE_DomainName_2_AcmeDnsServerAccount
    from ...lib.db.associate import TYPE_DomainName_2_DomainObject
    from ...model.objects import AcmeDnsServerAccount

# ==============================================================================


def submit__new(
    request: "Request",
    count_servers: Optional[int] = None,
) -> Tuple[AcmeDnsServer, bool]:
    if count_servers is None:
        _mode = request.api_context.application_settings["acme_dns_support"]
        if _mode != "experimental":
            count_servers = lib_db.get.get__AcmeDnsServer__count(request.api_context)
            if count_servers >= 1:
                raise ValueError("Only one acme-dns Server can be supported")

    (result, formStash) = formhandling.form_validate(
        request,
        schema=Form_AcmeDnsServer_new,
        validate_get=False,
    )
    if not result:
        raise formhandling.FormInvalid(formStash=formStash)

    (
        dbAcmeDnsServer,
        _is_created,
    ) = lib_db.getcreate.getcreate__AcmeDnsServer(
        request.api_context,
        api_url=formStash.results["api_url"],
        domain=formStash.results["domain"],
    )

    # in "basic" mode we only have a single server,
    # so it should be the default
    if request.api_context.application_settings["acme_dns_support"] == "basic":
        if count_servers == 0:
            (
                event_status,
                alt_info,
            ) = lib_db.update.update_AcmeDnsServer__set_global_default(
                request.api_context, dbAcmeDnsServer
            )
    return dbAcmeDnsServer, _is_created


def csv_AcmeDnsServerAccounts(
    items_paged: List["AcmeDnsServerAccount"],
) -> tempfile.SpooledTemporaryFile:

    fieldnames = ["id", "username", "password", "cname_source", "cname_target"]
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
        }
        writer.writerow(_row)
    tmpfile.seek(0)
    return tmpfile


def encode_AcmeDnsServerAccounts(dbAcmeDnsServerAccountsMap: List) -> Dict:
    domain_matrix: Dict = {}
    for _dbAcmeDnsServerAccount in dbAcmeDnsServerAccountsMap:
        _dbDomain = _dbAcmeDnsServerAccount.domain
        domain_matrix[_dbDomain.domain_name] = {
            "Domain": {
                "id": _dbDomain.id,
                "domain_name": _dbDomain.domain_name,
            },
            "AcmeDnsServerAccount": {
                "id": _dbAcmeDnsServerAccount.id,
                "subdomain": _dbAcmeDnsServerAccount.subdomain,
                "fulldomain": _dbAcmeDnsServerAccount.fulldomain,
            },
        }
    return domain_matrix


class View_List(Handler):
    @view_config(
        route_name="admin:acme_dns_servers",
        renderer="/admin/acme_dns_servers.mako",
    )
    @view_config(route_name="admin:acme_dns_servers|json", renderer="json")
    @view_config(
        route_name="admin:acme_dns_servers-paginated",
        renderer="/admin/acme_dns_servers.mako",
    )
    @view_config(route_name="admin:acme_dns_servers-paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-dns-servers.json",
            "section": "acme-dns-server",
            "about": """list AcmeDns Servers(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-dns-servers.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-dns-servers/{PAGE}.json",
            "section": "acme-dns-server",
            "example": "curl {ADMIN_PREFIX}/acme-dns-servers/1.json",
            "variant_of": "/acme-dns-servers.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__AcmeDnsServer__count(self.request.api_context)
        items_paged = lib_db.get.get__AcmeDnsServer__paginated(self.request.api_context)
        if self.request.wants_json:
            return {
                "AcmeDnsServers": [s.as_json for s in items_paged],
                "AcmeDnsServers_count": items_count,
            }
        return {
            "project": "peter_sslers",
            "AcmeDnsServers": items_paged,
            "AcmeDnsServers_count": items_count,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_New(Handler):

    _count_servers: int = 0

    def _acme_dns_support_check(self):
        _mode = self.request.api_context.application_settings["acme_dns_support"]
        if _mode == "experimental":
            return True
        self._count_servers = lib_db.get.get__AcmeDnsServer__count(
            self.request.api_context
        )
        if self._count_servers >= 1:
            raise HTTPSeeOther(
                "%s/acme-dns-servers?error=only-one-server-supported"
                % (self.request.admin_url,)
            )
        return True

    @view_config(route_name="admin:acme_dns_server:new")
    @view_config(route_name="admin:acme_dns_server:new|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-dns-server/new.json",
            "section": "acme-dns-server",
            "about": """new AcmeDns Servers""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/acme-dns-server/new.json",
            "form_fields": {
                "api_url": "The root url of the api",
                "domain": "The domain DNS records point to",
            },
        }
    )
    def new(self):
        self._acme_dns_support_check()
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-dns-server/new.json")
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_dns_server-new.mako",
            {},
            self.request,
        )

    def _new__submit(self):
        try:
            (dbAcmeDnsServer, _is_created) = submit__new(
                self.request, count_servers=self._count_servers
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeDnsServer": dbAcmeDnsServer.as_json,
                    "is_created": True if _is_created else False,
                }
            return HTTPSeeOther(
                "%s/acme-dns-server/%s?result=success&operation=new%s"
                % (
                    self.request.admin_url,
                    dbAcmeDnsServer.id,
                    ("&is_created=1" if _is_created else "&is_existing=1"),
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": exc.formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)


class View_Focus(Handler):
    dbAcmeDnsServer: Optional[AcmeDnsServer] = None

    def _focus(self, eagerload_web=False) -> AcmeDnsServer:
        if self.dbAcmeDnsServer is None:
            dbAcmeDnsServer = lib_db.get.get__AcmeDnsServer__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbAcmeDnsServer:
                raise HTTPNotFound("the acme-dns server was not found")
            self.dbAcmeDnsServer = dbAcmeDnsServer
            self._focus_url = "%s/acme-dns-server/%s" % (
                self.request.admin_url,
                self.dbAcmeDnsServer.id,
            )
        return self.dbAcmeDnsServer

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_dns_server:focus",
        renderer="/admin/acme_dns_server-focus.mako",
    )
    @view_config(route_name="admin:acme_dns_server:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}.json",
            "section": "acme-dns-server",
            "about": """AcmeDnsServer""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-dns-server/1.json",
        }
    )
    def focus(self):
        dbAcmeDnsServer = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "AcmeDnsServer": dbAcmeDnsServer.as_json,
            }
        return {"project": "peter_sslers", "AcmeDnsServer": dbAcmeDnsServer}

    @view_config(route_name="admin:acme_dns_server:focus:check", renderer=None)
    @view_config(route_name="admin:acme_dns_server:focus:check|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/check.json",
            "section": "acme-dns-server",
            "about": """AcmeDnsServer check""",
            "POST": True,
            "GET": None,
            "example": """curl -X POST {ADMIN_PREFIX}/acme-dns-server/{ID}/check.json""",
        }
    )
    def check(self):
        dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._check__submit(dbAcmeDnsServer)
        return self._check__print(dbAcmeDnsServer)

    def _check__print(self, dbAcmeDnsServer):
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-dns-server/{ID}/check.json")
        url_post_required = (
            "%s?result=error&error=post+required&operation=check" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _check__submit(self, dbAcmeDnsServer):
        try:
            sess = new_BrowserSession()
            resp = sess.get("%s/health" % dbAcmeDnsServer.api_url)
            if resp.status_code != 200:
                raise ValueError("invalid status_code: %s" % resp.status_code)
            if self.request.wants_json:
                return {"result": "success", "health": True}
            url_success = "%s?result=success&operation=check" % (self._focus_url,)
            return HTTPSeeOther(url_success)
        except Exception as exc:  # noqa: F841
            if self.request.wants_json:
                return {
                    "result": "error",
                    "health": None,
                    "error": "Error communicating with the acme-dns server.",
                }
            url_failure = "%s?result=error&operation=check" % (self._focus_url,)
            return HTTPSeeOther(url_failure)

    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts",
        renderer="/admin/acme_dns_server-focus-acme_dns_server_accounts.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts-paginated",
        renderer="/admin/acme_dns_server-focus-acme_dns_server_accounts.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/acme-dns-server-accounts.json",
            "section": "acme-dns-server",
            "about": """list AcmeDns Servers - accounts(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-dns-server/{ID}/acme-dns-server-accounts.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/acme-dns-server-accounts/{PAGE}.json",
            "section": "acme-dns-server",
            "example": "curl {ADMIN_PREFIX}/acme-dns-server/{ID}/acme-dns-server-accounts/1.json",
            "variant_of": "/acme-dns-server/{ID}/acme-dns-server-accounts.json",
        }
    )
    def list_accounts(self):
        dbAcmeDnsServer = self._focus(eagerload_web=True)
        items_count = lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__count(
            self.request.api_context, dbAcmeDnsServer.id
        )
        items_paged = (
            lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__paginated(
                self.request.api_context, dbAcmeDnsServer.id
            )
        )
        if self.request.wants_json:
            return {
                "AcmeDnsServer": dbAcmeDnsServer.as_json,
                "AcmeDnsServerAccounts": [s.as_json for s in items_paged],
                "AcmeDnsServerAccounts_count": items_count,
            }
        return {
            "project": "peter_sslers",
            "AcmeDnsServer": dbAcmeDnsServer,
            "AcmeDnsServerAccounts": items_paged,
            "AcmeDnsServerAccounts_count": items_count,
        }

    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts:all|csv"
    )
    def list_accounts_all_csv(self):
        dbAcmeDnsServer = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            url_post_required = (
                "%s?result=error&error=post+required&operation=csv" % self._focus_url
            )
            return HTTPSeeOther(url_post_required)
        items_paged = (
            lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__paginated(
                self.request.api_context, dbAcmeDnsServer.id
            )
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
                "attachment; filename= acme_dns_server-%s-accounts.csv"
                % dbAcmeDnsServer.id
            )
            return response

        except Exception as exc:  # noqa: F841
            return HTTPSeeOther(
                "%s/acme-dns-server-accounts?result=error&error=could+not+generate+csv"
                % self._focus_url
            )

    @view_config(
        route_name="admin:acme_dns_server:focus:acme_dns_server_accounts:all|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/acme-dns-server-accounts/all.json",
            "section": "acme-dns-server",
            "about": """list AcmeDns Servers - accounts(s)""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/acme-dns-server/{ID}/acme-dns-server-accounts/all.json",
        }
    )
    def list_accounts_all_json(self):
        dbAcmeDnsServer = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            return formatted_get_docs(
                self, "/acme-dns-server/{ID}/acme-dns-server-accounts/all.json"
            )
        items_count = lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__count(
            self.request.api_context, dbAcmeDnsServer.id
        )
        items_paged = (
            lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId__paginated(
                self.request.api_context, dbAcmeDnsServer.id
            )
        )
        return {
            "AcmeDnsServer": dbAcmeDnsServer.as_json,
            "AcmeDnsServerAccounts": [s.as_json for s in items_paged],
            "AcmeDnsServerAccounts_count": items_count,
        }

    @view_config(route_name="admin:acme_dns_server:focus:ensure_domains", renderer=None)
    @view_config(
        route_name="admin:acme_dns_server:focus:ensure_domains|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/ensure-domains.json",
            "section": "acme-dns-server",
            "about": """AcmeDnsServer ensure domains""",
            "POST": True,
            "GET": None,
            "example": """curl """
            """--form 'domain_names=domain_names' """
            """{ADMIN_PREFIX}/acme-dns-server/{ID}/ensure-domains.json""",
            "form_fields": {
                "domain_names": "A comma separated list of domain names",
            },
        }
    )
    def ensure_domains(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._ensure_domains__submit()
        return self._ensure_domains__print()

    def _ensure_domains__print(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-dns-server/{ID}/ensure-domains.json")
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_dns_server-focus-ensure_domains.mako",
            {"AcmeDnsServer": dbAcmeDnsServer},
            self.request,
        )

    def _ensure_domains__submit(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if TYPE_CHECKING:
            assert dbAcmeDnsServer is not None
        try:
            if lib_acmedns.pyacmedns is None:
                raise formhandling.FormInvalid("`pyacmedns` is not installed")
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeDnsServer_ensure_domains,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                # this function checks the domain names match a simple regex
                # domains will also be lowercase+strip
                domain_names = cert_utils.utils.domains_from_string(
                    formStash.results["domain_names"]
                )
            except ValueError as exc:  # noqa: F841
                formStash.fatal_field(
                    field="domain_names", message="invalid domain names detected"
                )
            if not domain_names:
                formStash.fatal_field(
                    field="domain_names",
                    message="invalid or no valid domain names detected",
                )
            if len(domain_names) > 100:
                formStash.fatal_field(
                    field="domain_names",
                    message="More than 100 domain names. There is a max of 100 domains per certificate.",
                )

            # Tuple[TYPE_DomainName_2_DomainObject, TYPE_DomainName_2_AcmeDnsServerAccount]
            # TYPE_DomainName_2_DomainObject = Dict[str, "Domain"]
            # TYPE_DomainName_2_AcmeDnsServerAccount = Dict[str, "AcmeDnsServerAccount"]
            domainObjectsMap: TYPE_DomainName_2_DomainObject
            dbAcmeDnsServerAccountsMap: TYPE_DomainName_2_AcmeDnsServerAccount
            try:
                (domainObjectsMap, dbAcmeDnsServerAccountsMap) = (
                    lib_db.associate.ensure_domain_names_to_acmeDnsServer(
                        self.request.api_context,
                        domain_names,
                        dbAcmeDnsServer,
                        discovery_type="via acme_dns_server._ensure_domains__submit",
                    )
                )
            except errors.AcmeDnsServerError as exc:  # noqa: F841
                # raises a `FormInvalid`
                formStash.fatal_form(
                    message="Error communicating with the acme-dns server.",
                )

            if self.request.wants_json:
                result_matrix = encode_AcmeDnsServerAccounts(
                    list(dbAcmeDnsServerAccountsMap.values())
                )
                return {"result": "success", "result_matrix": result_matrix}

            acme_dns_server_accounts = ",".join(
                [
                    str(_dbAcmeDnsServerAccount.id)
                    for _dbAcmeDnsServerAccount in dbAcmeDnsServerAccountsMap.values()
                ]
            )
            url_success = "%s/ensure-domains-results?acme-dns-server-accounts=%s" % (
                self._focus_url,
                acme_dns_server_accounts,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._ensure_domains__print)

    @view_config(
        route_name="admin:acme_dns_server:focus:ensure_domains_results",
        renderer="/admin/acme_dns_server-focus-ensure_domains-results.mako",
    )
    @view_config(
        route_name="admin:acme_dns_server:focus:ensure_domains_results|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/ensure-domains-results.json",
            "section": "acme-dns-server",
            "about": """AcmeDnsServer ensure domains - results""",
            "POST": None,
            "GET": True,
            "example": """curl """
            """--form 'acme-dns-server-accounts=1,2,3,4,5' """
            """{ADMIN_PREFIX}/acme-dns-server/{ID}/ensure-domains-results.json""",
            "form_fields": {
                "acme-dns-server-accounts": "A comma separated list of acme-dns-server-accounts. these are returned by `/acme-dns-server/{ID}/ensure-domains.json`"
            },
        }
    )
    def ensure_domains_results(self):
        try:
            dbAcmeDnsServer = self.dbAcmeDnsServer = self._focus()
            if TYPE_CHECKING:
                assert dbAcmeDnsServer is not None
            _AcmeDnsServerAccountIds = self.request.params.get(
                "acme-dns-server-accounts", ""
            )
            _AcmeDnsServerAccountIds = [
                int(i) for i in _AcmeDnsServerAccountIds.split(",")
            ]
            if not _AcmeDnsServerAccountIds:
                raise ValueError("missing `acme-dns-server-accounts`")
            if len(_AcmeDnsServerAccountIds) > 100:
                raise ValueError(
                    "More than 100 AcmeDnsServerAccounts specified; this is not allowed."
                )
            dbAcmeDnsServerAccounts = lib_db.get.get__AcmeDnsServerAccounts__by_ids(
                self.request.api_context, _AcmeDnsServerAccountIds
            )
            if not dbAcmeDnsServerAccounts:
                raise ValueError("invalid `acme-dns-server-accounts`")

            if self.request.wants_json:
                result_matrix = encode_AcmeDnsServerAccounts(dbAcmeDnsServerAccounts)
                return {"result": "success", "result_matrix": result_matrix}

            return {
                "project": "peter_sslers",
                "AcmeDnsServer": dbAcmeDnsServer,
                "AcmeDnsServerAccounts": dbAcmeDnsServerAccounts,
            }

        except Exception as exc:  # noqa: F841
            raise

    @view_config(route_name="admin:acme_dns_server:focus:import_domain", renderer=None)
    @view_config(
        route_name="admin:acme_dns_server:focus:import_domain|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/import-domain.json",
            "section": "acme-dns-server",
            "about": """AcmeDnsServer import domain""",
            "POST": True,
            "GET": None,
            "example": """curl """
            """--form 'domain_name=domain_name' """
            """--form 'username=username' """
            """--form 'password=password' """
            """--form 'fulldomain=fulldomain' """
            """--form 'subdomain=subdomain' """
            """--form 'allowfrom=allowfrom' """
            """{ADMIN_PREFIX}/acme-dns-server/{ID}/import-domain.json""",
            "form_fields": {
                "domain_name": "The domain name",
                "username": "The acme-dns username",
                "password": "The acme-dns password",
                "fulldomain": "The acme-dns fulldomain",
                "subdomain": "The acme-dns subdomain",
                "allowfrom": "The acme-dns allowfrom",
            },
        }
    )
    def import_domain(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._import_domain__submit()
        return self._import_domain__print()

    def _import_domain__print(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-dns-server/{ID}/import-domain.json")
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/acme_dns_server-focus-import_domain.mako",
            {"AcmeDnsServer": dbAcmeDnsServer},
            self.request,
        )

    def _import_domain__submit(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if TYPE_CHECKING:
            assert dbAcmeDnsServer is not None
        try:
            if lib_acmedns.pyacmedns is None:
                raise formhandling.FormInvalid("`pyacmedns` is not installed")
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeDnsServer_import_domain,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            # ensure we have these domain!
            for test_domain in ("domain_name", "fulldomain"):
                try:
                    # this function checks the domain names match a simple regex
                    # domains will also be lowercase+strip
                    _domain_names = cert_utils.utils.domains_from_string(
                        formStash.results[test_domain]
                    )
                except ValueError as exc:  # noqa: F841
                    formStash.fatal_field(
                        field=test_domain, message="invalid domain names detected"
                    )
                if not _domain_names:
                    formStash.fatal_field(
                        field=test_domain,
                        message="invalid or no valid domain names detected",
                    )
                if len(_domain_names) != 1:
                    formStash.fatal_field(
                        field=test_domain,
                        message="Only 1 domain accepted here.",
                    )
            # grab our domain
            domain_name = formStash.results["domain_name"]
            (
                _dbDomain,
                _is_created__domain,
            ) = lib_db.getcreate.getcreate__Domain__by_domainName(
                self.request.api_context,
                domain_name,
                discovery_type="via acme_dns_server._import_domain__submit",
            )
            _dbAcmeDnsServerAccount = None
            _is_created__account = None
            if not _is_created__domain:
                _dbAcmeDnsServerAccount = (
                    lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId_DomainId(
                        self.request.api_context,
                        acme_dns_server_id=dbAcmeDnsServer.id,
                        domain_id=_dbDomain.id,
                    )
                )
            if not _dbAcmeDnsServerAccount:
                _dbAcmeDnsServerAccount = lib_db.create.create__AcmeDnsServerAccount(
                    self.request.api_context,
                    dbAcmeDnsServer=dbAcmeDnsServer,
                    dbDomain=_dbDomain,
                    username=formStash.results["username"],
                    password=formStash.results["password"],
                    fulldomain=formStash.results["fulldomain"],
                    subdomain=formStash.results["subdomain"],
                    allowfrom=formStash.results["allowfrom"] or "[]",
                )
                _is_created__account = True

            if self.request.wants_json:
                result_matrix = encode_AcmeDnsServerAccounts(
                    [
                        _dbAcmeDnsServerAccount,
                    ]
                )
                result_matrix[_dbDomain.domain_name]["result"] = (
                    "success" if _is_created__account else "existing"
                )
                return {"result": "success", "result_matrix": result_matrix}

            url_success = "%s/acme-dns-server-account/%s?result=%s&operation=import" % (
                self.request.admin_url,
                _dbAcmeDnsServerAccount.id,
                "success" if _is_created__account else "existing",
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._import_domain__print)


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:acme_dns_server:focus:mark", renderer=None)
    @view_config(route_name="admin:acme_dns_server:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/mark.json",
            "section": "acme-dns-server",
            "about": """AcmeDnsServer mark""",
            "POST": True,
            "GET": None,
            "examples": [
                """curl """
                """--form 'action=active' """
                """{ADMIN_PREFIX}/acme-dns-server/{ID}/mark.json""",
            ],
            "instructions": """curl {ADMIN_PREFIX}/acme-dns-server/{ID}/mark.json""",
            "form_fields": {"action": "the intended action"},
            "valid_options": {
                "action": Form_AcmeDnsServer_mark.fields["action"].list,
            },
        }
    )
    def mark(self):
        dbAcmeDnsServer = self._focus()
        if self.request.method == "POST":
            return self._mark__submit(dbAcmeDnsServer)
        return self._mark__print(dbAcmeDnsServer)

    def _mark__print(self, dbAcmeDnsServer):
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-dns-server/{ID}/mark.json")
        url_post_required = (
            "%s?result=error&error=post+required&operation=mark" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _mark__submit(self, dbAcmeDnsServer):
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeDnsServer_mark, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string(
                "AcmeDnsServer__mark"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_dns_server.id"] = dbAcmeDnsServer.id
            event_payload_dict["action"] = formStash.results["action"]

            event_status: Optional[str] = None
            event_alt = None
            try:
                if action == "active":
                    event_status = lib_db.update.update_AcmeDnsServer__set_active(
                        self.request.api_context, dbAcmeDnsServer
                    )

                elif action == "inactive":
                    event_status = lib_db.update.update_AcmeDnsServer__unset_active(
                        self.request.api_context, dbAcmeDnsServer
                    )

                elif action == "global_default":
                    (
                        event_status,
                        alt_info,
                    ) = lib_db.update.update_AcmeDnsServer__set_global_default(
                        self.request.api_context, dbAcmeDnsServer
                    )
                    if alt_info:
                        for k, v in alt_info["event_payload_dict"].items():
                            event_payload_dict[k] = v
                        event_alt = alt_info["event_alt"]

                else:
                    raise errors.InvalidTransition("Invalid option")

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

            if TYPE_CHECKING:
                assert event_status is not None

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type, event_payload_dict
            )
            lib_db.logger._log_object_event(
                self.request.api_context,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    event_status
                ),
                dbAcmeDnsServer=dbAcmeDnsServer,
            )
            if event_alt:
                lib_db.logger._log_object_event(
                    self.request.api_context,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                        event_alt[0]
                    ),
                    dbAcmeDnsServer=event_alt[1],
                )
            if self.request.wants_json:
                return {"result": "success", "AcmeDnsServer": dbAcmeDnsServer.as_json}
            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                errors.formstash_to_querystring(formStash),
                action,
            )
            raise HTTPSeeOther(url_failure)

    @view_config(route_name="admin:acme_dns_server:focus:edit", renderer=None)
    @view_config(route_name="admin:acme_dns_server:focus:edit|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-dns-server/{ID}/edit.json",
            "section": "acme-dns-server",
            "about": """AcmeDnsServer edit""",
            "POST": True,
            "GET": None,
            "examples": [
                """curl """
                """--form 'action=api_url' """
                """{ADMIN_PREFIX}/acme-dns-server/{ID}/edit.json""",
            ],
            "instructions": """curl {ADMIN_PREFIX}/acme-dns-server/{ID}/edit.json""",
            "form_fields": {
                "api_url": "the url",
                "domain": "the domain",
            },
        }
    )
    def edit(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._edit__submit()
        return self._edit__print()

    def _edit__print(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-dns-server/{ID}/edit.json")
        return render_to_response(
            "/admin/acme_dns_server-focus-edit.mako",
            {
                "project": "peter_sslers",
                "AcmeDnsServer": dbAcmeDnsServer,
            },
            self.request,
        )

    def _edit__submit(self):
        dbAcmeDnsServer = self.dbAcmeDnsServer
        if TYPE_CHECKING:
            assert dbAcmeDnsServer is not None
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeDnsServer_edit, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            event_type_id = model_utils.OperationsEventType.from_string(
                "AcmeDnsServer__edit"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["acme_dns_server.id"] = dbAcmeDnsServer.id
            event_payload_dict["old.api_url"] = dbAcmeDnsServer.api_url
            event_payload_dict["new.api_url"] = formStash.results["api_url"]
            event_payload_dict["old.domain"] = dbAcmeDnsServer.domain
            event_payload_dict["new.domain"] = formStash.results["domain"]

            try:
                result = lib_db.update.update_AcmeDnsServer__api_url__domain(
                    self.request.api_context,
                    dbAcmeDnsServer,
                    api_url=formStash.results["api_url"],
                    domain=formStash.results["domain"],
                )
            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(exc.args[0])

            self.request.api_context.dbSession.flush(objects=[dbAcmeDnsServer])

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type_id, event_payload_dict
            )
            lib_db.logger._log_object_event(
                self.request.api_context,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    "AcmeDnsServer__edit"
                ),
                dbAcmeDnsServer=dbAcmeDnsServer,
            )
            if self.request.wants_json:
                return {"result": "success", "AcmeDnsServer": dbAcmeDnsServer.as_json}
            url_success = "%s?result=success&operation=edit" % (self._focus_url,)
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._edit__print)
