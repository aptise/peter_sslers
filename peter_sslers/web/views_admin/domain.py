# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import sqlalchemy

# localapp
from .. import lib
from ..lib import formhandling
from ..lib import form_utils as form_utils
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_Domain_mark
from ..lib.forms import Form_Domain_new
from ..lib.forms import Form_Domain_search
from ..lib.forms import Form_Domain_AcmeDnsServer_new
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import acmedns as lib_acmedns
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...lib import utils_nginx
from ...lib import utils_redis
from ...model import utils as model_utils
from ...model import objects as model_objects


# ==============================================================================


class View_List(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domains", renderer="/admin/domains.mako")
    @view_config(route_name="admin:domains_paginated", renderer="/admin/domains.mako")
    @view_config(route_name="admin:domains:challenged", renderer="/admin/domains.mako")
    @view_config(
        route_name="admin:domains:challenged_paginated", renderer="/admin/domains.mako"
    )
    @view_config(route_name="admin:domains:expiring", renderer="/admin/domains.mako")
    @view_config(
        route_name="admin:domains:expiring_paginated", renderer="/admin/domains.mako"
    )
    @view_config(route_name="admin:domains|json", renderer="json")
    @view_config(route_name="admin:domains_paginated|json", renderer="json")
    @view_config(route_name="admin:domains:challenged|json", renderer="json")
    @view_config(route_name="admin:domains:challenged_paginated|json", renderer="json")
    @view_config(route_name="admin:domains:expiring|json", renderer="json")
    @view_config(route_name="admin:domains:expiring_paginated|json", renderer="json")
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
        expiring_days = self.request.registry.settings["app_settings"]["expiring_days"]
        if self.request.matched_route.name in (
            "admin:domains:expiring",
            "admin:domains:expiring_paginated",
            "admin:domains:expiring|json",
            "admin:domains:expiring_paginated|json",
        ):
            sidenav_option = "expiring"
            url_template = (
                "%s/domains/expiring/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template

            items_count = lib_db.get.get__Domain__count(
                self.request.api_context, expiring_days=expiring_days
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__Domain__paginated(
                self.request.api_context,
                expiring_days=expiring_days,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:domains:challenged",
            "admin:domains:challenged_paginated",
            "admin:domains:challenged|json",
            "admin:domains:challenged_paginated|json",
        ):
            sidenav_option = "challenged"
            url_template = (
                "%s/domains/challenged/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
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
        else:
            sidenav_option = "all"
            url_template = (
                "%s/domains/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
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
            "expiring_days": expiring_days,
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
            "example": "curl --form 'domain=example.com' {ADMIN_PREFIX}/domains/search.json",
            "form_fields": {"domain": "the domain"},
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
                raise formhandling.FormInvalid()

            domain_name = formStash.results["domain"]
            dbDomain = lib_db.get.get__Domain__by_name(
                self.request.api_context,
                domain_name,
                preload=None,
                eagerload_web=False,
                active_only=False,
            )
            dbQueueDomainActive = lib_db.get.get__QueueDomain__by_name__single(
                self.request.api_context, domain_name, active_only=True
            )
            dbQueueDomainsInactive = lib_db.get.get__QueueDomain__by_name__many(
                self.request.api_context,
                domain_name,
                active_only=False,
                inactive_only=True,
            )

            search_results = {
                "Domain": dbDomain,
                "QueueDomainActive": dbQueueDomainActive,
                "QueueDomainsInactive": dbQueueDomainsInactive,
                "query": domain_name,
            }
            self.search_results = search_results
            if self.request.wants_json:
                return {
                    "result": "success",
                    "query": domain_name,
                    "search_results": {
                        "Domain": dbDomain.as_json if dbDomain else None,
                        "QueueDomainActive": dbQueueDomainActive.as_json
                        if dbQueueDomainActive
                        else None,
                        "QueueDomainsInactive": [
                            q.as_json for q in dbQueueDomainsInactive
                        ],
                    },
                }
            return self._search__print()

        except formhandling.FormInvalid as exc:
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
            "example": "curl --form 'domain=example.com' {ADMIN_PREFIX}/domain/new.json",
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
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Domain_new, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            domains_challenged = form_utils.form_single_domain_challenge_typed(
                self.request, formStash, challenge_type="http-01"
            )
            domain_name = domains_challenged["http-01"][0]

            # TODO: check the queue
            (
                dbDomain,
                _is_created,
            ) = lib_db.getcreate.getcreate__Domain__by_domainName(
                self.request.api_context, domain_name=domain_name
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
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)


class View_Focus(Handler):
    dbDomain = None

    def _focus(self, eagerload_web=False):
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
                self.request.registry.settings["app_settings"]["admin_prefix"],
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
                "AcmeChallenges_Active": [i.as_json for i in dbAcmeChallenges]
                if dbAcmeChallenges
                else None,
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
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/domain/1/nginx-cache-expire.json",
        }
    )
    def nginx_expire(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/domain/{ID}/nginx-cache-expire.json")
            raise HTTPSeeOther(
                "%s?result=error&operation=nginx-cache-expire&message=POST+required"
                % self._focus_url
            )
        dbDomain = self._focus(eagerload_web=True)
        if not self.request.registry.settings["app_settings"]["enable_nginx"]:
            raise HTTPSeeOther(
                "%s?result=error&operation=nginx-cache-expire&error=no+nginx"
                % self._focus_url
            )
        success, dbEvent = utils_nginx.nginx_expire_cache(
            self.request, self.request.api_context, dbDomains=[dbDomain]
        )
        if self.request.wants_json:
            return {"result": "success", "operations_event": {"id": dbEvent.id}}
        return HTTPSeeOther(
            "%s?result=success&operation=nginx+cache+expire&event.id=%s"
            % (self._focus_url, dbEvent.id)
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
            id_only=self.request.params.get("id_only", None), active_only=True
        )
        if self.request.params.get("openresty", None):
            utils_redis.prime_redis_domain(self.request, dbDomain)
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
    def calendar(self):
        rval = {}
        dbDomain = self._focus()
        weekly_certs = (
            self.request.api_context.dbSession.query(
                model_utils.year_week(
                    model_objects.CertificateSigned.timestamp_not_before
                ).label("week_num"),
                sqlalchemy.func.count(model_objects.CertificateSigned.id),
            )
            .join(
                model_objects.UniqueFQDNSet2Domain,
                model_objects.CertificateSigned.unique_fqdn_set_id
                == model_objects.UniqueFQDNSet2Domain.unique_fqdn_set_id,
            )
            .filter(model_objects.UniqueFQDNSet2Domain.domain_id == dbDomain.id)
            .group_by("week_num")
            .order_by(sqlalchemy.asc("week_num"))
            .all()
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
            "example": "curl {ADMIN_PREFIX}/domain/1/update-recents.json",
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
            operations_event = lib_db.actions.operations_update_recents__domains(
                self.request.api_context,
                dbDomains=[
                    dbDomain,
                ],
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "Domain": dbDomain.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=update-recents" % (self._focus_url,)
            )
        except Exception as exc:
            raise

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:acme_authorizations",
        renderer="/admin/domain-focus-acme_authorizations.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_authorizations_paginated",
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
        route_name="admin:domain:focus:acme_challenges",
        renderer="/admin/domain-focus-acme_challenges.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_challenges_paginated",
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
        route_name="admin:domain:focus:acme_orders_paginated",
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
        route_name="admin:domain:focus:acme_orderlesss",
        renderer="/admin/domain-focus-acme_orderless.mako",
    )
    @view_config(
        route_name="admin:domain:focus:acme_orderlesss_paginated",
        renderer="/admin/domain-focus-acme_orderless.mako",
    )
    def related__AcmeOrderlesss(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__AcmeOrderless__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/acme-orderlesss/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeOrderless__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "AcmeOrderlesss_count": items_count,
            "AcmeOrderlesss": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:domain_autocerts",
        renderer="/admin/domain-focus-domain_autocert.mako",
    )
    @view_config(
        route_name="admin:domain:focus:domain_autocerts_paginated",
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
        route_name="admin:domain:focus:certificate_requests_paginated",
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
        renderer="/admin/domain-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:domain:focus:certificate_signeds_paginated",
        renderer="/admin/domain-focus-certificate_signeds.mako",
    )
    def related__CertificateSigneds(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__CertificateSigned__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/certificate-signeds/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateSigned__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:queue_certificates",
        renderer="/admin/domain-focus-queue_certificates.mako",
    )
    @view_config(
        route_name="admin:domain:focus:queue_certificates_paginated",
        renderer="/admin/domain-focus-queue_certificates.mako",
    )
    def related__QueueCertificates(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__QueueCertificate__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        url_template = "%s/queue-certificates/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__QueueCertificate__by_DomainId__paginated(
            self.request.api_context,
            dbDomain.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "QueueCertificates_count": items_count,
            "QueueCertificates": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domain:focus:unique_fqdn_sets",
        renderer="/admin/domain-focus-unique_fqdn_sets.mako",
    )
    @view_config(
        route_name="admin:domain:focus:unique_fqdn_sets_paginated",
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


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:domain:focus:mark", renderer=None)
    @view_config(route_name="admin:domain:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/domain/{ID}/mark.json",
            "section": "domain",
            "about": """Domain focus: mark""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/domain/1/mark.json",
            "instructions": [
                """curl --form 'action=active' {ADMIN_PREFIX}/domain/1/mark.json""",
            ],
            "form_fields": {"action": "the intended action"},
            "valid_options": {"action": ["active", "inactive"]},
        }
    )
    def mark(self):
        dbDomain = self._focus()
        if self.request.method == "POST":
            return self._mark__submit(dbDomain)
        return self._mark__print(dbDomain)

    def _mark__print(self, dbDomain):
        if self.request.wants_json:
            return formatted_get_docs(self, "/domain/{ID}/mark.json")
        url_post_required = "%s?result=error&error=post+required&operation=mark" % (
            self._focus_url,
        )
        return HTTPSeeOther(url_post_required)

    def _mark__submit(self, dbDomain):
        action = "!MISSING or !INVALID"
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Domain_mark, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string("Domain__mark")
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["domain_id"] = dbDomain.id
            event_payload_dict["action"] = action
            event_status = False

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type, event_payload_dict
            )

            if action == "active":
                if dbDomain.is_active:
                    # `formStash.fatal_form()` will raise `FormInvalid()`
                    formStash.fatal_form("Already active.")

                lib_db.update.update_Domain_enable(
                    self.request.api_context,
                    dbDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="Domain__mark__active",
                    action="activated",
                )

            elif action == "inactive":
                if not dbDomain.is_active:
                    # `formStash.fatal_form()` will raise `FormInvalid()`
                    formStash.fatal_form("Already inactive.")

                lib_db.update.update_Domain_disable(
                    self.request.api_context,
                    dbDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="Domain__mark__inactive",
                    action="deactivated",
                )

            else:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(field="action", message="Invalid option.")

            self.request.api_context.dbSession.flush(
                objects=[dbOperationsEvent, dbDomain]
            )

            if self.request.wants_json:
                return {"result": "success", "Domain": dbDomain.as_json}

            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                errors.formstash_to_querystring(formStash),
                action,
            )
            raise HTTPSeeOther(url_failure)


class View_Focus_AcmeDnsServerAccounts(View_Focus):
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
            "example": "curl {ADMIN_PREFIX}/domain/1/acme-dns-server/new.json",
            "instructions": [
                """curl --form 'acme_dns_server_id=act1ive' {ADMIN_PREFIX}/domain/1/acme-dns-server/new.json""",
            ],
            "form_fields": {"acme_dns_server_id": "the AcmeDNS Server"},
            "valid_options": {
                "acme_dns_server_id": "{RENDER_ON_REQUEST}",
            },
        }
    )
    def new(self):
        self.dbDomain = dbDomain = self._focus()

        ## In the future this should support multiple accounts
        ## however, right now we only care about one single account
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

        self.dbAcmeDnsServers = (
            dbAcmeDnsServers
        ) = lib_db.get.get__AcmeDnsServer__paginated(self.request.api_context)
        if self.request.method == "POST":
            return self._new_submit()
        return self._new_print()

    def _new_print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/domain/new.json")
        return render_to_response(
            "/admin/domain-focus-acme_dns_server-new.mako",
            {
                "project": "peter_sslers",
                "Domain": self.dbDomain,
                "AcmeDnsServers": self.dbAcmeDnsServers,
            },
            self.request,
        )

    def _new_submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Domain_AcmeDnsServer_new, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            # validate the AcmeDnsServer
            dbAcmeDnsServer = lib_db.get.get__AcmeDnsServer__by_id(
                self.request.api_context, formStash.results["acme_dns_server_id"]
            )
            if not dbAcmeDnsServer:
                # `formStash.fatal_field()` will raise `FormInvalid()`
                formStash.fatal_field(
                    field="acme_dns_server_id", message="Invalid AcmeDnsServer."
                )
            if not dbAcmeDnsServer.is_active:
                # `formStash.fatal_field()` will raise `FormInvalid()`
                formStash.fatal_field(
                    field="acme_dns_server_id", message="Inactive AcmeDnsServer."
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
                    self.request.api_context, dbAcmeDnsServer.id, self.dbDomain.id
                )
            )
            if dbAcmeDnsServerAccount:
                formStash.fatal_field(
                    field="acme_dns_server_id",
                    message="Existing record for this AcmeDnsServer.",
                )

            # Restriction B: Any given `Domain` can have one `AcmeDnsServerAccount`
            dbAcmeDnsServerAccount = lib_db.get.get__AcmeDnsServerAccount__by_DomainId(
                self.request.api_context, self.dbDomain.id
            )
            if dbAcmeDnsServerAccount:
                formStash.fatal_field(
                    field="acme_dns_server_id",
                    message="Existing record for this Domain on another AcmeDnsServer.",
                )

            # wonderful! now we need to "register" against acme-dns
            try:
                if lib_acmedns.pyacmedns is None:
                    raise formhandling.FormInvalid("`pyacmedns` is not installed")

                # initialize a client
                client = lib_acmedns.new_client(dbAcmeDnsServer.root_url)
                account = client.register_account(None)  # arg = allowlist ips
            except Exception as exc:
                raise ValueError("error registering an account with AcmeDns")

            dbAcmeDnsServerAccount = lib_db.create.create__AcmeDnsServerAccount(
                self.request.api_context,
                dbAcmeDnsServer=dbAcmeDnsServer,
                dbDomain=self.dbDomain,
                username=account["username"],
                password=account["password"],
                fulldomain=account["fulldomain"],
                subdomain=account["subdomain"],
                allowfrom=account["allowfrom"],
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

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new_print)
