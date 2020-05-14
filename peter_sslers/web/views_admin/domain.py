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
from ..lib import text as lib_text
from ..lib.forms import Form_Domain_mark
from ..lib.forms import Form_Domain_search
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...lib import utils_nginx
from ...model import utils as model_utils
from ...model import objects as model_objects


# ==============================================================================


class ViewAdmin_List(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domains", renderer="/admin/domains.mako")
    @view_config(route_name="admin:domains_paginated", renderer="/admin/domains.mako")
    @view_config(route_name="admin:domains:expiring", renderer="/admin/domains.mako")
    @view_config(
        route_name="admin:domains:expiring_paginated", renderer="/admin/domains.mako"
    )
    @view_config(route_name="admin:domains:challenged", renderer="/admin/domains.mako")
    @view_config(
        route_name="admin:domains:challenged_paginated", renderer="/admin/domains.mako"
    )
    @view_config(route_name="admin:domains|json", renderer="json")
    @view_config(route_name="admin:domains_paginated|json", renderer="json")
    @view_config(route_name="admin:domains:expiring|json", renderer="json")
    @view_config(route_name="admin:domains:expiring_paginated|json", renderer="json")
    @view_config(route_name="admin:domains:challenged|json", renderer="json")
    @view_config(route_name="admin:domains:challenged_paginated|json", renderer="json")
    def list(self):
        expiring_days = self.request.registry.settings["app_settings"]["expiring_days"]
        if self.request.matched_route.name in (
            "admin:domains:expiring",
            "admin:domains:expiring_paginated",
            "admin:domains:expiring|json",
            "admin:domains:expiring_paginated|json",
        ):
            sidenav_option = "expiring"
            if self.request.wants_json:
                url_template = (
                    "%s/domains/expiring/{0}.json"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/domains/expiring/{0}"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
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
            if self.request.wants_json:
                url_template = (
                    "%s/domains/challenged/{0}.json"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/domains/challenged/{0}"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
            items_count = lib_db.get.get__Domains_challenged__count(
                self.request.api_context
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__Domains_challenged__paginated(
                self.request.api_context, limit=items_per_page, offset=offset,
            )
        else:
            sidenav_option = "all"
            if self.request.wants_json:
                url_template = (
                    "%s/domains/{0}.json"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/domains/{0}"
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                )
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


class ViewAdmin_Search(Handler):
    @view_config(
        route_name="admin:domains:search", renderer="/admin/domains-search.mako"
    )
    @view_config(route_name="admin:domains:search|json", renderer="json")
    def search(self):
        self.search_results = None
        if self.request.method == "POST":
            return self._search__submit()
        return self._search__print()

    def _search__print(self):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'domain=example.com' %s/domains/search.json"""
                    % self.request.admin_url
                ],
                "form_fields": {"domain": "the domain"},
            }
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


class ViewAdmin_Focus(Handler):
    def _focus(self, eagerload_web=False):
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
        self._focus_item = dbDomain
        self._focus_url = "%s/domain/%s" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            dbDomain.id,
        )
        return dbDomain

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domain:focus", renderer="/admin/domain-focus.mako")
    @view_config(route_name="admin:domain:focus|json", renderer="json")
    def focus(self):
        dbDomain = self._focus(eagerload_web=True)
        dbAcmeChallenge = lib_db.get.get__AcmeChallenge__by_DomainId__active(
            self.request.api_context, dbDomain.id,
        )
        if self.request.wants_json:
            return {
                "Domain": dbDomain.as_json,
                "AcmeChallenge_Active": dbAcmeChallenge.as_json
                if dbAcmeChallenge
                else None,
            }
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "AcmeChallenge": dbAcmeChallenge,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domain:focus:nginx_cache_expire", renderer=None)
    @view_config(
        route_name="admin:domain:focus:nginx_cache_expire|json", renderer="json"
    )
    def focus_nginx_expire(self):
        dbDomain = self._focus(eagerload_web=True)
        if not self.request.registry.settings["app_settings"]["enable_nginx"]:
            raise HTTPSeeOther("%s?result=error&error=no+nginx" % self._focus_url)
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
    def focus_config_json(self):
        dbDomain = self._focus()
        rval = {
            "domain": {
                "id": str(dbDomain.id),
                "domain_name": dbDomain.domain_name,
                "is_active": dbDomain.is_active,
            },
            "server_certificate__latest_single": None,
            "server_certificate__latest_multi": None,
        }
        if dbDomain.server_certificate_id__latest_single:
            if self.request.params.get("idonly", None):
                rval[
                    "server_certificate__latest_single"
                ] = dbDomain.server_certificate__latest_single.config_payload_idonly
            else:
                rval[
                    "server_certificate__latest_single"
                ] = dbDomain.server_certificate__latest_single.config_payload
        if dbDomain.server_certificate_id__latest_multi:
            if self.request.params.get("idonly", None):
                rval[
                    "server_certificate__latest_multi"
                ] = dbDomain.server_certificate__latest_multi.config_payload_idonly
            else:
                rval[
                    "server_certificate__latest_multi"
                ] = dbDomain.server_certificate__latest_multi.config_payload
        if self.request.params.get("openresty", None):
            lib.utils.prime_redis_domain(self.request, dbDomain)
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:domain:focus:calendar|json", renderer="json")
    def focus__calendar(self):
        rval = {}
        dbDomain = self._focus()
        weekly_certs = (
            self.request.api_context.dbSession.query(
                model_utils.year_week(
                    model_objects.ServerCertificate.timestamp_signed
                ).label("week_num"),
                sqlalchemy.func.count(model_objects.ServerCertificate.id),
            )
            .join(
                model_objects.UniqueFQDNSet2Domain,
                model_objects.ServerCertificate.unique_fqdn_set_id
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
        (pager, offset) = self._paginate(
            items_count, url_template="%s/acme-authorizations/{0}" % self._focus_url
        )
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
        (pager, offset) = self._paginate(
            items_count, url_template="%s/acme-challenges/{0}" % self._focus_url
        )
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
        (pager, offset) = self._paginate(
            items_count, url_template="%s/acme-orders/{0}" % self._focus_url
        )
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
        (pager, offset) = self._paginate(
            items_count, url_template="%s/acme-orderlesss/{0}" % self._focus_url
        )
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
        (pager, offset) = self._paginate(
            items_count, url_template="%s/certificate-requests/{0}" % self._focus_url
        )
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
        route_name="admin:domain:focus:server_certificates",
        renderer="/admin/domain-focus-server_certificates.mako",
    )
    @view_config(
        route_name="admin:domain:focus:server_certificates_paginated",
        renderer="/admin/domain-focus-server_certificates.mako",
    )
    def related__ServerCertificates(self):
        dbDomain = self._focus()
        items_count = lib_db.get.get__ServerCertificate__by_DomainId__count(
            self.request.api_context, dbDomain.id
        )
        (pager, offset) = self._paginate(
            items_count, url_template="%s/server-certificates/{0}" % self._focus_url
        )
        items_paged = lib_db.get.get__ServerCertificate__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "Domain": dbDomain,
            "ServerCertificates_count": items_count,
            "ServerCertificates": items_paged,
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
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/domain/%s/queue-certificates/{0}"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                dbDomain.id,
            ),
        )
        items_paged = lib_db.get.get__QueueCertificate__by_DomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset,
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
        (pager, offset) = self._paginate(
            items_count, url_template="%s/unique-fqdn-sets/{0}" % self._focus_url
        )
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


class ViewAdmin_Focus_Manipulate(ViewAdmin_Focus):
    @view_config(route_name="admin:domain:focus:mark", renderer=None)
    @view_config(route_name="admin:domain:focus:mark|json", renderer="json")
    def focus_mark(self):
        dbDomain = self._focus()
        if self.request.method == "POST":
            return self._focus_mark__submit(dbDomain)
        return self._focus_mark__print(dbDomain)

    def _focus_mark__print(self, dbDomain):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'action=active' %s/domain/1/mark.json"""
                    % self.request.admin_url
                ],
                "form_fields": {"action": "the intended action"},
                "valid_options": {"action": ["active", "inactive"]},
            }
        url_post_required = "%s?result=error&error=post+required&operation=mark" % (
            self._focus_url,
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self, dbDomain):
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
                formStash.fatal_field(field="action", message="invalid option.")

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
