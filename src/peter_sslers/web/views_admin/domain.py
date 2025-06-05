# stdlib
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config
from typing_extensions import Literal

# local
from ..lib import form_utils as form_utils
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_Domain_AcmeDnsServer_new
from ..lib.forms import Form_Domain_new
from ..lib.forms import Form_Domain_search
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import acmedns as lib_acmedns
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils_nginx
from ...lib import utils_redis
from ...model.objects import AcmeDnsServerAccount
from ...model.objects import Domain

if TYPE_CHECKING:
    from pyramid.request import Request
    from ...model.objects import AcmeDnsServer


# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


def submit__Domain__new(
    request: "Request",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[Domain, bool]:
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    (result, formStash) = formhandling.form_validate(
        request, schema=Form_Domain_new, validate_get=False
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    try:
        domains_challenged = form_utils.form_single_domain_challenge_typed(
            request, formStash, challenge_type="http-01"
        )
        domain_name = domains_challenged["http-01"][0]

        (
            dbDomain,
            _is_created,
        ) = lib_db.getcreate.getcreate__Domain__by_domainName(
            request.api_context,
            domain_name=domain_name,
            discovery_type="upload",
        )

        return dbDomain, _is_created

    except Exception as exc:
        raise formStash.fatal_form(exc.args[0])


def submit__Domain_AcmeDnsServer__new(
    request: "Request",
    dbDomain: Domain,
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> AcmeDnsServerAccount:
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    (result, formStash) = formhandling.form_validate(
        request, schema=Form_Domain_AcmeDnsServer_new, validate_get=False
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    # validate the AcmeDnsServer
    dbAcmeDnsServer = lib_db.get.get__AcmeDnsServer__by_id(
        request.api_context, formStash.results["acme_dns_server_id"]
    )
    if not dbAcmeDnsServer:
        formStash.fatal_field(
            field="acme_dns_server_id",
            error_field="Invalid AcmeDnsServer.",
        )
    if TYPE_CHECKING:
        assert dbAcmeDnsServer is not None
    if not dbAcmeDnsServer.is_active:
        formStash.fatal_field(
            field="acme_dns_server_id",
            error_field="Inactive AcmeDnsServer.",
        )

    # In order to keep things simple, enforce two restrictions:
    # Restriction A: Any given `AcmeDnsServer` can have one set of credentials for a given `Domain`
    # Restriction B: Any given `Domain` can have one `AcmeDnsServerAccount`
    # These restrictions are only required to simplify UX.
    # In practice, there can be an infinite number AcmeDnsServerAccounts per Domain;
    #    This applies to accounts on the same AcmeDnsServer or different AcmeDnsServers.

    # Restriction A: Any given `AcmeDnsServer` can have one set of credentials for a given `Domain`
    dbAcmeDnsServerAccount = (
        lib_db.get.get__AcmeDnsServerAccount__by_AcmeDnsServerId_DomainId(
            request.api_context, dbAcmeDnsServer.id, dbDomain.id
        )
    )
    if dbAcmeDnsServerAccount:
        formStash.fatal_field(
            field="acme_dns_server_id",
            error_field="Existing record for this AcmeDnsServer.",
        )

    # Restriction B: Any given `Domain` can have one `AcmeDnsServerAccount`
    dbAcmeDnsServerAccount = lib_db.get.get__AcmeDnsServerAccount__by_DomainId(
        request.api_context, dbDomain.id
    )
    if dbAcmeDnsServerAccount:
        formStash.fatal_field(
            field="acme_dns_server_id",
            error_field="Existing record for this Domain on another AcmeDnsServer.",
        )

    # wonderful! now we need to "register" against acme-dns
    try:
        # initialize a client
        acmeDnsClient = lib_acmedns.new_client(dbAcmeDnsServer.api_url)
        account = acmeDnsClient.register_account(None)  # arg = allowlist ips
    except Exception as exc:  # noqa: F841
        # raise errors.AcmeDnsServerError("error registering an account with AcmeDns", exc)
        formStash.fatal_form(error_main="Error communicating with the acme-dns server.")

    dbAcmeDnsServerAccount = lib_db.create.create__AcmeDnsServerAccount(
        request.api_context,
        dbAcmeDnsServer=dbAcmeDnsServer,
        dbDomain=dbDomain,
        username=account["username"],
        password=account["password"],
        fulldomain=account["fulldomain"],
        subdomain=account["subdomain"],
        allowfrom=account["allowfrom"],
    )

    return dbAcmeDnsServerAccount


class View_List(Handler):
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domains", renderer="/admin/domains.mako")
    @view_config(route_name="admin:domains-paginated", renderer="/admin/domains.mako")
    @view_config(route_name="admin:domains:challenged", renderer="/admin/domains.mako")
    @view_config(
        route_name="admin:domains:challenged-paginated", renderer="/admin/domains.mako"
    )
    @view_config(
        route_name="admin:domains:authz_potential", renderer="/admin/domains.mako"
    )
    @view_config(
        route_name="admin:domains:authz_potential-paginated",
        renderer="/admin/domains.mako",
    )
    @view_config(route_name="admin:domains:expiring", renderer="/admin/domains.mako")
    @view_config(
        route_name="admin:domains:expiring-paginated", renderer="/admin/domains.mako"
    )
    @view_config(route_name="admin:domains|json", renderer="json")
    @view_config(route_name="admin:domains-paginated|json", renderer="json")
    @view_config(route_name="admin:domains:challenged|json", renderer="json")
    @view_config(route_name="admin:domains:challenged-paginated|json", renderer="json")
    @view_config(route_name="admin:domains:authz_potential|json", renderer="json")
    @view_config(
        route_name="admin:domains:authz_potential-paginated|json", renderer="json"
    )
    @view_config(route_name="admin:domains:expiring|json", renderer="json")
    @view_config(route_name="admin:domains:expiring-paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/domains.json",
            "section": "domain",
            "about": """list Domain(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domains.json",
        }
    )
    @docify(
        {
            "endpoint": "/domains/{PAGE}.json",
            "section": "domain",
            "example": "curl {ADMIN_PREFIX}/domains/1.json",
            "variant_of": "/domains.json",
        }
    )
    @docify(
        {
            "endpoint": "/domains/challenged.json",
            "section": "domain",
            "about": """list Domain(s)- Challenged""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domains/challenged.json",
        }
    )
    @docify(
        {
            "endpoint": "/domains/challenged/{PAGE}.json",
            "section": "domain",
            "example": "curl {ADMIN_PREFIX}/domains/challenged/1.json",
            "variant_of": "/domains/challenged.json",
        }
    )
    @docify(
        {
            "endpoint": "/domains/authz-potential.json",
            "section": "domain",
            "about": """list Domain(s)- Autorization Potential""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domains/authz-potential.json",
        }
    )
    @docify(
        {
            "endpoint": "/domains/authz-potential/{PAGE}.json",
            "section": "domain",
            "example": "curl {ADMIN_PREFIX}/domains/authz-potential/1.json",
            "variant_of": "/domains/authz-potential.json",
        }
    )
    @docify(
        {
            "endpoint": "/domains/expiring.json",
            "section": "domain",
            "about": """list Domain(s)- Expiring""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domains/expiring.json",
        }
    )
    @docify(
        {
            "endpoint": "/domains/expiring/{PAGE}.json",
            "section": "domain",
            "example": "curl {ADMIN_PREFIX}/domains/expiring/1.json",
            "variant_of": "/domains/expiring.json",
        }
    )
    def list(self):
        expiring_days_ux = self.request.api_context.application_settings[
            "expiring_days_ux"
        ]
        if self.request.matched_route.name in (
            "admin:domains:expiring",
            "admin:domains:expiring-paginated",
            "admin:domains:expiring|json",
            "admin:domains:expiring-paginated|json",
        ):
            sidenav_option = "expiring"
            url_template = (
                "%s/domains/expiring/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template

            items_count = lib_db.get.get__Domain__count(
                self.request.api_context, days_to_expiry=expiring_days_ux
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__Domain__paginated(
                self.request.api_context,
                days_to_expiry=expiring_days_ux,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:domains:challenged",
            "admin:domains:challenged-paginated",
            "admin:domains:challenged|json",
            "admin:domains:challenged-paginated|json",
        ):
            sidenav_option = "challenged"
            url_template = (
                "%s/domains/challenged/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__Domains_challenged__count(
                self.request.api_context
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__Domains_challenged__paginated(
                self.request.api_context,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:domains:authz_potential",
            "admin:domains:authz_potential-paginated",
            "admin:domains:authz_potential|json",
            "admin:domains:authz_potential-paginated|json",
        ):
            sidenav_option = "authz-potential"
            url_template = (
                "%s/domains/authz-potential/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__Domains_authz_potential__count(
                self.request.api_context
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__Domains_authz_potential__paginated(
                self.request.api_context,
                limit=items_per_page,
                offset=offset,
            )
        else:
            sidenav_option = "all"
            url_template = (
                "%s/domains/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__Domain__count(self.request.api_context)
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__Domain__paginated(
                self.request.api_context,
                eagerload_web=True,
                limit=items_per_page,
                offset=offset,
            )
        if self.request.wants_json:
            _domains = {d.id: d.as_json for d in items_paged}
            return {
                "Domains": _domains,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "Domains_count": items_count,
            "Domains": items_paged,
            "sidenav_option": sidenav_option,
            "expiring_days_ux": expiring_days_ux,
            "pager": pager,
        }


class View_Search(Handler):
    @view_config(
        route_name="admin:domains:search", renderer="/admin/domains-search.mako"
    )
    @docify(
        {
            "endpoint": "/domains/search.json",
            "section": "domain",
            "about": """Search Domain(s)""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/domains/search.json",
            "example": "curl "
            "--form 'domain=example.com' "
            "{ADMIN_PREFIX}/domains/search.json",
            "form_fields": {
                "domain": "the domain",
            },
        }
    )
    @view_config(route_name="admin:domains:search|json", renderer="json")
    def search(self):
        self.search_results = None
        if self.request.method == "POST":
            return self._search__submit()
        return self._search__print()

    def _search__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/domains/search.json")
        return render_to_response(
            "/admin/domains-search.mako",
            {"search_results": self.search_results, "sidenav_option": "search"},
            self.request,
        )

    def _search__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Domain_search, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            domain_name = formStash.results["domain"]
            dbDomain = lib_db.get.get__Domain__by_name(
                self.request.api_context,
                domain_name,
                preload=False,
                eagerload_web=False,
            )

            search_results = {
                "Domain": dbDomain,
                "query": domain_name,
            }
            self.search_results = search_results
            if self.request.wants_json:
                return {
                    "result": "success",
                    "query": domain_name,
                    "search_results": {
                        "Domain": dbDomain.as_json if dbDomain else None,
                    },
                }
            return self._search__print()

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._search__print)


class View_New(Handler):
    @view_config(route_name="admin:domain:new")
    @view_config(route_name="admin:domain:new|json", renderer="json")
    @docify(
        {
            "endpoint": "/domain/new.json",
            "section": "domain",
            "about": """New Domain""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/domain/new.json",
            "example": "curl "
            "--form 'domain=example.com' "
            "{ADMIN_PREFIX}/domain/new.json",
            "form_fields": {"domain_name": "the domain"},
        }
    )
    def new(self):
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/domain/new.json")
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/domain-new.mako",
            {},
            self.request,
        )

    def _new__submit(self):
        try:
            (dbDomain, _is_created) = submit__Domain__new(
                self.request,
                acknowledge_transaction_commits=True,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "Domain": dbDomain.as_json,
                    "is_created": True if _is_created else False,
                }
            return HTTPSeeOther(
                "%s/domain/%s?result=success&operation=new%s"
                % (
                    self.request.admin_url,
                    dbDomain.id,
                    ("&is_created=1" if _is_created else "&is_existing=1"),
                )
            )
        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": exc.formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)


class View_Focus(Handler):
    dbDomain: Optional[Domain] = None

    def _focus(self, eagerload_web=False) -> Domain:
        if self.dbDomain is None:
            domain_identifier = self.request.matchdict["domain_identifier"].strip()
            if domain_identifier.isdigit():
                dbDomain = lib_db.get.get__Domain__by_id(
                    self.request.api_context,
                    domain_identifier,
                    preload=True,
                    eagerload_web=eagerload_web,
                )
            else:
                dbDomain = lib_db.get.get__Domain__by_name(
                    self.request.api_context,
                    domain_identifier,
                    preload=True,
                    eagerload_web=eagerload_web,
                )
            if not dbDomain:
                raise HTTPNotFound("the domain was not found")
            self.dbDomain = dbDomain
            self._focus_item = dbDomain
            self._focus_url = "%s/domain/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbDomain.id,
            )
        return self.dbDomain

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domain:focus", renderer="/admin/domain-focus.mako")
    @view_config(route_name="admin:domain:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/domain/{ID}.json",
            "section": "domain",
            "about": """Domain focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/1.json",
        }
    )
    def focus(self):
        dbDomain = self._focus(eagerload_web=True)
        dbAcmeChallenges = lib_db.get.get__AcmeChallenges__by_DomainId__active(
            self.request.api_context,
            dbDomain.id,
        )
        if self.request.wants_json:
            return {
                "Domain": dbDomain.as_json,
                "AcmeChallenges_Active": (
                    [i.as_json for i in dbAcmeChallenges] if dbAcmeChallenges else None
                ),
            }
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "AcmeChallenges_Active": dbAcmeChallenges,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domain:focus:nginx_cache_expire", renderer=None)
    @view_config(
        route_name="admin:domain:focus:nginx_cache_expire|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/nginx-cache-expire.json",
            "section": "domain",
            "about": """Domain focus: nginx-cache-expire""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/domain/1/nginx-cache-expire.json",
            "example": "curl -X POST {ADMIN_PREFIX}/domain/1/nginx-cache-expire.json",
        }
    )
    def nginx_cache_expire(self):
        dbDomain = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/domain/{ID}/nginx-cache-expire.json")
            raise HTTPSeeOther(
                "%s?result=error&operation=nginx-cache-expire&message=POST+required"
                % self._focus_url
            )
        try:
            # could raise `InvalidRequest("nginx is not enabled")`
            self.request.api_context._ensure_nginx()

            success, dbEvent = utils_nginx.nginx_expire_cache(
                self.request, self.request.api_context, dbDomains=[dbDomain]
            )
            if self.request.wants_json:
                return {"result": "success", "operations_event": {"id": dbEvent.id}}
            return HTTPSeeOther(
                "%s?result=success&operation=nginx-cache-expire&event.id=%s"
                % (self._focus_url, dbEvent.id)
            )

        except errors.InvalidRequest as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": exc.args[0],
                }
            raise HTTPSeeOther(
                "%s?result=error&operation=nginx-cache-expire&error=nginx+is+not+enabled"
                % self._focus_url
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domain:focus:config|json", renderer="json")
    @docify(
        {
            "endpoint": "/domain/{ID}/config.json",
            "section": "domain",
            "about": """Domain focus: config""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/1/config.json",
        }
    )
    def config_json(self):
        dbDomain = self._focus()
        rval = dbDomain.as_json_config(
            id_only=self.request.params.get("id_only", None),
        )
        if self.request.params.get("openresty", None):
            try:
                utils_redis.prime_redis_domain(self.request, dbDomain)
            except utils_redis.RedisError as exc:
                log.debug("domain config.json - could not prime redis > %s", str(exc))
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domain:focus:calendar|json", renderer="json")
    @docify(
        {
            "endpoint": "/domain/{ID}/calendar.json",
            "section": "domain",
            "about": """Domain focus: calendar""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/1/calendar.json",
        }
    )
    def calendar(self) -> Dict:
        rval: Dict = {}
        dbDomain = self._focus()
        weekly_certs = lib_db.get.get_CertificateSigned_weeklyData_by_domainId(
            self.request.api_context,
            dbDomain.id,
        )
        rval["issues"] = {}
        for wc in weekly_certs:
            rval["issues"][str(wc[0])] = wc[1]
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domain:focus:update_recents", renderer=None)
    @view_config(route_name="admin:domain:focus:update_recents|json", renderer="json")
    @docify(
        {
            "endpoint": "/domain/{ID}/update-recents.json",
            "section": "domain",
            "about": """Domain focus: update-recents""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/domain/1/update-recents.json",
            "example": "curl -X POST {ADMIN_PREFIX}/domain/1/update-recents.json",
        }
    )
    def update_recents(self):
        dbDomain = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/domain/{ID}/update-recents.json")
            return HTTPSeeOther(
                "%s?result=error&operation=update-recents&message=POST+required"
                % (self._focus_url,)
            )
        try:
            operations_event = (  # noqa: F841
                lib_db.actions.operations_update_recents__domains(
                    self.request.api_context,
                    dbDomains=[
                        dbDomain,
                    ],
                )
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "Domain": dbDomain.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=update-recents" % (self._focus_url,)
            )
        except Exception as exc:  # noqa: F841
            raise

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:acme_authorizations",
        renderer="/admin/domain-focus-acme_authorizations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_authorizations-paginated",
        renderer="/admin/domain-focus-acme_authorizations.mako",
    )
    def related__AcmeAuthorizations(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__AcmeAuthorization__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/acme-authorizations/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeAuthorization__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "AcmeAuthorizations_count": items_count,
            "AcmeAuthorizations": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:acme_authorization_potentials",
        renderer="/admin/domain-focus-acme_authorization_potentials.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_authorization_potentials-paginated",
        renderer="/admin/domain-focus-acme_authorization_potentials.mako",
    )
    def related__AcmeAuthorizationPoetntials(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__AcmeAuthorizationPotentials__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/acme-authz-potentials/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__AcmeAuthorizationPotentials__by_DomainId__paginated(
                self.request.api_context,
                dbDomain.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "AcmeAuthorizationPotentials_count": items_count,
            "AcmeAuthorizationPotentials": items_paged,
            "pager": pager,
        }

    @view_config(
        route_name="admin:domain:focus:acme_challenges",
        renderer="/admin/domain-focus-acme_challenges.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_challenges-paginated",
        renderer="/admin/domain-focus-acme_challenges.mako",
    )
    def related__AcmeChallenges(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__AcmeChallenge__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/acme-challenges/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeChallenge__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "AcmeChallenges_count": items_count,
            "AcmeChallenges": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:acme_orders",
        renderer="/admin/domain-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_orders-paginated",
        renderer="/admin/domain-focus-acme_orders.mako",
    )
    def related__AcmeOrders(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__AcmeOrder__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/acme-orders/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeOrder__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:domain_autocerts",
        renderer="/admin/domain-focus-domain_autocert.mako",
    )
    @view_config(
        route_name="admin:domain:focus:domain_autocerts-paginated",
        renderer="/admin/domain-focus-domain_autocert.mako",
    )
    def related__DomainAutocerts(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__DomainAutocert__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/domain-autocerts/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__DomainAutocert__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "DomainAutocerts_count": items_count,
            "DomainAutocerts": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:certificate_requests",
        renderer="/admin/domain-focus-certificate_requests.mako",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_requests-paginated",
        renderer="/admin/domain-focus-certificate_requests.mako",
    )
    def related__CertificateRequests(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__CertificateRequest__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/certificate-requests/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateRequest__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "CertificateRequests_count": items_count,
            "CertificateRequests": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:certificate_signeds",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds-paginated",
    )
    def related__CertificateSigneds(self):
        dbDomain = self._focus()  # noqa: F841
        url_redirect = "%s/certificate-signeds/all" % self._focus_url
        if self.request.wants_json:
            url_redirect = "%s.json" % url_redirect
        return HTTPSeeOther(url_redirect)

    @view_config(
        route_name="admin:domain:focus:certificate_signeds:all",
        renderer="/admin/domain-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:all-paginated",
        renderer="/admin/domain-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:all|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:all-paginated|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:single",
        renderer="/admin/domain-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:single-paginated",
        renderer="/admin/domain-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:single|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:single-paginated|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:multi",
        renderer="/admin/domain-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:multi-paginated",
        renderer="/admin/domain-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:multi|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds:multi-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/certificate-signeds/all.json",
            "section": "domain",
            "about": """list Domain's CertificateSigned(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/{ID}/certificate-signeds/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/certificate-signeds/all/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/domain/{domain}/certificate-signeds/all/1.json",
            "variant_of": "/domain/{ID}/certificate-signeds/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/certificate-signeds/multi.json",
            "section": "domain",
            "about": """list Domain's CertificateSigned(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/{ID}/certificate-signeds/multi.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/certificate-signeds/multi/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/domain/{domain}/certificate-signeds/multi/1.json",
            "variant_of": "/domain/{ID}/certificate-signeds/multi.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/certificate-signeds/single.json",
            "section": "domain",
            "about": """list Domain's CertificateSigned(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/{ID}/certificate-signeds/single.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/certificate-signeds/single/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/domain/{domain}/certificate-signeds/single/1.json",
            "variant_of": "/domain/{ID}/certificate-signeds/single.json",
        }
    )
    def related__CertificateSigneds_faceted(self):
        dbDomain = self._focus()
        if self.request.matched_route.name in (
            "admin:domain:focus:certificate_signeds:all",
            "admin:domain:focus:certificate_signeds:all-paginated",
            "admin:domain:focus:certificate_signeds:all|json",
            "admin:domain:focus:certificate_signeds:all-paginated|json",
        ):
            sidenav_option = "all"
            url_template = "%s/certificate-signeds/all/{0}" % self._focus_url
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__CertificateSigned__by_DomainId__count(
                self.request.api_context, dbDomain.id
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__CertificateSigned__by_DomainId__paginated(
                self.request.api_context,
                dbDomain.id,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:domain:focus:certificate_signeds:single",
            "admin:domain:focus:certificate_signeds:single-paginated",
            "admin:domain:focus:certificate_signeds:single|json",
            "admin:domain:focus:certificate_signeds:single-paginated|json",
        ):
            sidenav_option = "single"
            url_template = "%s/certificate-signeds/single/{0}" % self._focus_url
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__CertificateSigned__by_DomainId__count(
                self.request.api_context, dbDomain.id, facet="single"
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__CertificateSigned__by_DomainId__paginated(
                self.request.api_context,
                dbDomain.id,
                facet="single",
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:domain:focus:certificate_signeds:multi",
            "admin:domain:focus:certificate_signeds:multi-paginated",
            "admin:domain:focus:certificate_signeds:multi|json",
            "admin:domain:focus:certificate_signeds:multi-paginated|json",
        ):
            sidenav_option = "multi"
            url_template = "%s/certificate-signeds/multi/{0}" % self._focus_url
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__CertificateSigned__by_DomainId__count(
                self.request.api_context, dbDomain.id, facet="multi"
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__CertificateSigned__by_DomainId__paginated(
                self.request.api_context,
                dbDomain.id,
                facet="multi",
                limit=items_per_page,
                offset=offset,
            )
        else:
            raise ValueError("unknown route")

        if self.request.matched_route.name.endswith("|json"):
            _certificates = {c.id: c.as_json for c in items_paged}
            return {
                "Domain": dbDomain.as_json,
                "CertificateSigneds": _certificates,
                "CertificateSigneds_count": items_count,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
            "sidenav_option": sidenav_option,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:renewal_configurations",
        renderer="/admin/domain-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations-paginated",
        renderer="/admin/domain-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations-paginated|json",
        renderer="json",
    )
    def related__RenewalConfigurations(self):
        dbDomain = self._focus()  # noqa: F841
        if self.request.matched_route.name.endswith("|json"):
            return HTTPSeeOther("%s/renewal-configurations/all.json" % self._focus_url)
        return HTTPSeeOther("%s/renewal-configurations/all" % self._focus_url)

    @view_config(
        route_name="admin:domain:focus:renewal_configurations:all",
        renderer="/admin/domain-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:single",
        renderer="/admin/domain-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:multi",
        renderer="/admin/domain-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:all-paginated",
        renderer="/admin/domain-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:single-paginated",
        renderer="/admin/domain-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:multi-paginated",
        renderer="/admin/domain-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:all|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:single|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:multi|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:all-paginated|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:single-paginated|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:domain:focus:renewal_configurations:multi-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/renewal-configurations/all.json",
            "section": "domain",
            "about": """list Domain's RenewalConfigurations(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/{ID}/renewal-configurations/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/renewal-configurations/all/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/domain/{domain}/renewal-configurations/all/1.json",
            "variant_of": "/domain/{ID}/renewal-configurations/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/renewal-configurations/multi.json",
            "section": "domain",
            "about": """list Domain's RenewalConfigurations(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/{ID}/renewal-configurations/multi.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/renewal-configurations/multi/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/domain/{domain}/renewal-configurations/multi/1.json",
            "variant_of": "/domain/{ID}/renewal-configurations/multi.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/renewal-configurations/single.json",
            "section": "domain",
            "about": """list Domain's RenewalConfigurations(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/{ID}/renewal-configurations/single.json",
        }
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/renewal-configurations/single/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/domain/{domain}/renewal-configurations/single/1.json",
            "variant_of": "/domain/{ID}/renewal-configurations/single.json",
        }
    )
    def related__RenewalConfigurations_faceted(self):
        dbDomain = self._focus()
        if self.request.matched_route.name in (
            "admin:domain:focus:renewal_configurations:all",
            "admin:domain:focus:renewal_configurations:all-paginated",
            "admin:domain:focus:renewal_configurations:all|json",
            "admin:domain:focus:renewal_configurations:all-paginated|json",
        ):
            sidenav_option = "all"
            url_template = "%s/renewal-configurations/all/{0}" % self._focus_url
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__RenewalConfigurations__by_DomainId__count(
                self.request.api_context, dbDomain.id
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__RenewalConfigurations__by_DomainId__paginated(
                self.request.api_context,
                dbDomain.id,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:domain:focus:renewal_configurations:single",
            "admin:domain:focus:renewal_configurations:single-paginated",
            "admin:domain:focus:renewal_configurations:single|json",
            "admin:domain:focus:renewal_configurations:single-paginated|json",
        ):
            sidenav_option = "single"
            url_template = "%s/renewal-configurations/single/{0}" % self._focus_url
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__RenewalConfigurations__by_DomainId__count(
                self.request.api_context, dbDomain.id, facet="single"
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__RenewalConfigurations__by_DomainId__paginated(
                self.request.api_context,
                dbDomain.id,
                facet="single",
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:domain:focus:renewal_configurations:multi",
            "admin:domain:focus:renewal_configurations:multi-paginated",
            "admin:domain:focus:renewal_configurations:multi|json",
            "admin:domain:focus:renewal_configurations:multi-paginated|json",
        ):
            sidenav_option = "multi"
            url_template = "%s/renewal-configurations/multi/{0}" % self._focus_url
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__RenewalConfigurations__by_DomainId__count(
                self.request.api_context, dbDomain.id, facet="multi"
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__RenewalConfigurations__by_DomainId__paginated(
                self.request.api_context,
                dbDomain.id,
                facet="multi",
                limit=items_per_page,
                offset=offset,
            )
        else:
            raise ValueError("unknown route")

        if self.request.matched_route.name.endswith("|json"):
            _certificates = {c.id: c.as_json for c in items_paged}
            return {
                "Domain": dbDomain.as_json,
                "RenewalConfigurations": _certificates,
                "RenewalConfigurations__count": items_count,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "RenewalConfigurations__count": items_count,
            "RenewalConfigurations": items_paged,
            "pager": pager,
            "sidenav_option": sidenav_option,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:unique_fqdn_sets",
        renderer="/admin/domain-focus-unique_fqdn_sets.mako",
    )
    @view_config(
        route_name="admin:domain:focus:unique_fqdn_sets-paginated",
        renderer="/admin/domain-focus-unique_fqdn_sets.mako",
    )
    def related__UniqueFQDNSets(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__UniqueFQDNSet__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/unique-fqdn-sets/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__UniqueFQDNSet__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "UniqueFQDNSets_count": items_count,
            "UniqueFQDNSets": items_paged,
            "pager": pager,
        }

    @view_config(
        route_name="admin:domain:focus:uniquely_challenged_fqdn_sets",
        renderer="/admin/domain-focus-uniquely_challenged_fqdn_sets.mako",
    )
    @view_config(
        route_name="admin:domain:focus:uniquely_challenged_fqdn_sets-paginated",
        renderer="/admin/domain-focus-uniquely_challenged_fqdn_sets.mako",
    )
    def related__UniquelyChallengedFQDNSets(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__UniquelyChallengedFQDNSet__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/uniquely-challenged-fqdn-sets/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__UniquelyChallengedFQDNSet__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "UniquelyChallengedFQDNSets_count": items_count,
            "UniquelyChallengedFQDNSets": items_paged,
            "pager": pager,
        }


class View_Focus_AcmeDnsServerAccounts(View_Focus):

    dbAcmeDnsServers_all: Optional[List["AcmeDnsServer"]] = None

    @view_config(
        route_name="admin:domain:focus:acme_dns_server_accounts",
        renderer="/admin/domain-focus-acme_dns_server_accounts.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_dns_server_accounts|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/acme-dns-server-accounts.json",
            "section": "domain",
            "about": """list Domain Acme-DNS Server accounts(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/{ID}/acme-dns-server-accounts.json",
        }
    )
    def list(self):
        dbDomain = self._focus()
        if self.request.wants_json:
            return {
                "Domain": dbDomain.as_json,
                "AcmeDnsServerAccounts": [
                    ads2d.as_json for ads2d in dbDomain.acme_dns_server_accounts
                ],
            }
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "AcmeDnsServerAccounts": dbDomain.acme_dns_server_accounts,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:acme_dns_server:new",
        renderer="/admin/domain-focus-acme_dns_server-new.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_dns_server:new|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/domain/{ID}/acme-dns-server/new.json",
            "section": "domain",
            "about": """Domain focus: acme-dns-server/new""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/domain/1/acme-dns-server/new.json",
            "examples": [
                """curl """
                """--form 'acme_dns_server_id=act1ive' """
                """{ADMIN_PREFIX}/domain/1/acme-dns-server/new.json""",
            ],
            "form_fields": {
                "acme_dns_server_id": "the acme-dns Server",
            },
            "valid_options": {
                "acme_dns_server_id": "{RENDER_ON_REQUEST}",
            },
        }
    )
    def new(self):
        self.dbDomain = dbDomain = self._focus()

        # In the future this should support multiple accounts
        # however, right now we only care about one single account
        if dbDomain.acme_dns_server_accounts__5:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "form_errors": {
                        "Error_Main": "There was an error with your form.",
                        "acme_dns_server_id": "Existing record for this AcmeDnsServer.",
                    },
                }
            _url = (
                "%s/acme-dns-server-accounts?result=error&error=accounts-exist&operation=new"
                % (self._focus_url,)
            )
            return HTTPSeeOther(_url)

        self.dbAcmeDnsServers_all = lib_db.get.get__AcmeDnsServer__paginated(
            self.request.api_context
        )
        if self.request.method == "POST":
            return self._new_submit()
        return self._new_print()

    def _new_print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/domain/{ID}/acme-dns-server/new.json")
        return render_to_response(
            "/admin/domain-focus-acme_dns_server-new.mako",
            {
                "project": "peter_sslers",
                "Domain": self.dbDomain,
                "AcmeDnsServers": self.dbAcmeDnsServers_all,
            },
            self.request,
        )

    def _new_submit(self):
        if TYPE_CHECKING:
            assert self.dbDomain is not None
        try:
            dbAcmeDnsServerAccount = submit__Domain_AcmeDnsServer__new(
                self.request,
                dbDomain=self.dbDomain,
                acknowledge_transaction_commits=True,
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeDnsServerAccount": dbAcmeDnsServerAccount.as_json,
                }

            url_success = "%s/acme-dns-server-accounts?result=success&operation=new" % (
                self._focus_url,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": exc.formStash.errors}
            return formhandling.form_reprint(self.request, self._new_print)
