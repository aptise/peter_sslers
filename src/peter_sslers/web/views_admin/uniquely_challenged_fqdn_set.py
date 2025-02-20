# stdlib
from typing import Optional

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import UniquelyChallengedFQDNSet


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:uniquely_challenged_fqdn_sets",
        renderer="/admin/uniquely_challenged_fqdn_sets.mako",
    )
    @view_config(
        route_name="admin:uniquely_challenged_fqdn_sets-paginated",
        renderer="/admin/uniquely_challenged_fqdn_sets.mako",
    )
    @view_config(route_name="admin:uniquely_challenged_fqdn_sets|json", renderer="json")
    @view_config(
        route_name="admin:uniquely_challenged_fqdn_sets-paginated|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/uniquely-challenged-fqdn-sets.json",
            "section": "uniquely-challenged-fqdn-set",
            "about": """list UniquelyChallengedFQDNSet(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/uniquely-challenged-fqdn-sets.json",
        }
    )
    @docify(
        {
            "endpoint": "/uniquely-challenged-fqdn-sets/{PAGE}.json",
            "section": "uniquely-challenged-fqdn-set",
            "example": "curl {ADMIN_PREFIX}/uniquely-challenged-fqdn-sets/1.json",
            "variant_of": "/uniquely-challenged-fqdn-sets.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__UniquelyChallengedFQDNSet__count(
            self.request.api_context
        )
        url_template = (
            "%s/uniquely-challenged-fqdn-sets/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__UniquelyChallengedFQDNSet__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
            eagerload_web=True,
        )
        if self.request.wants_json:
            _sets = {s.id: s.as_json for s in items_paged}
            return {
                "UniquelyChallengedFQDNSets": _sets,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "UniquelyChallengedFQDNSets_count": items_count,
            "UniquelyChallengedFQDNSets": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbUniquelyChallengedFQDNSet: Optional[UniquelyChallengedFQDNSet] = None

    def _focus(self) -> UniquelyChallengedFQDNSet:
        if self.dbUniquelyChallengedFQDNSet is None:
            dbUniquelyChallengedFQDNSet = (
                lib_db.get.get__UniquelyChallengedFQDNSet__by_id(
                    self.request.api_context, self.request.matchdict["id"]
                )
            )
            if not dbUniquelyChallengedFQDNSet:
                raise HTTPNotFound("the Unique FQDN Set was not found")
            self.dbUniquelyChallengedFQDNSet = dbUniquelyChallengedFQDNSet
            self._focus_item = dbUniquelyChallengedFQDNSet
            self._focus_url = "%s/uniquely-challenged-fqdn-set/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbUniquelyChallengedFQDNSet.id,
            )
        return self.dbUniquelyChallengedFQDNSet

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:uniquely_challenged_fqdn_set:focus",
        renderer="/admin/uniquely_challenged_fqdn_set-focus.mako",
    )
    @view_config(
        route_name="admin:uniquely_challenged_fqdn_set:focus|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/uniquely-challenged-fqdn-set/{ID}.json",
            "section": "uniquely-challenged-fqdn-set",
            "about": """uniquely-challenged-fqdn-set focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/uniquely-challenged-fqdn-set/1.json",
        }
    )
    def focus(self):
        dbUniquelyChallengedFQDNSet = self._focus()
        if self.request.wants_json:
            return {"UniquelyChallengedFQDNSet": dbUniquelyChallengedFQDNSet.as_json}

        return {
            "project": "peter_sslers",
            "UniquelyChallengedFQDNSet": dbUniquelyChallengedFQDNSet,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:uniquely_challenged_fqdn_set:focus:acme_orders",
        renderer="/admin/uniquely_challenged_fqdn_set-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:uniquely_challenged_fqdn_set:focus:acme_orders-paginated",
        renderer="/admin/uniquely_challenged_fqdn_set-focus-acme_orders.mako",
    )
    def related__AcmeOrders(self):
        dbUniquelyChallengedFQDNSet = self._focus()
        items_count = lib_db.get.get__AcmeOrder__by_UniquelyChallengedFQDNSetId__count(
            self.request.api_context, dbUniquelyChallengedFQDNSet.id
        )
        url_template = "%s/acme-orders/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__AcmeOrder__by_UniquelyChallengedFQDNSetId__paginated(
                self.request.api_context,
                dbUniquelyChallengedFQDNSet.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "UniquelyChallengedFQDNSet": dbUniquelyChallengedFQDNSet,
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:uniquely_challenged_fqdn_set:focus:certificate_signeds",
        renderer="/admin/uniquely_challenged_fqdn_set-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:uniquely_challenged_fqdn_set:focus:certificate_signeds-paginated",
        renderer="/admin/uniquely_challenged_fqdn_set-focus-certificate_signeds.mako",
    )
    def related__CertificateSigneds(self):
        dbUniquelyChallengedFQDNSet = self._focus()
        items_count = (
            lib_db.get.get__CertificateSigneds__by_UniquelyChallengedFQDNSetId__count(
                self.request.api_context, dbUniquelyChallengedFQDNSet.id
            )
        )
        url_template = "%s/certificate-signeds/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateSigneds__by_UniquelyChallengedFQDNSetId__paginated(
            self.request.api_context,
            dbUniquelyChallengedFQDNSet.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "UniquelyChallengedFQDNSet": dbUniquelyChallengedFQDNSet,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
        }

    @view_config(
        route_name="admin:uniquely_challenged_fqdn_set:focus:renewal_configurations",
        renderer="/admin/uniquely_challenged_fqdn_set-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:uniquely_challenged_fqdn_set:focus:renewal_configurations-paginated",
        renderer="/admin/uniquely_challenged_fqdn_set-focus-renewal_configurations.mako",
    )
    def related__RenewalConfigurations(self):
        dbUniquelyChallengedFQDNSet = self._focus()
        items_count = (
            lib_db.get.get__RenewalConfiguration__by_UniquelyChallengedFQDNSetId__count(
                self.request.api_context, dbUniquelyChallengedFQDNSet.id
            )
        )
        url_template = "%s/renewal-configurations/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__RenewalConfiguration__by_UniquelyChallengedFQDNSetId__paginated(
            self.request.api_context,
            dbUniquelyChallengedFQDNSet.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "UniquelyChallengedFQDNSet": dbUniquelyChallengedFQDNSet,
            "RenewalConfigurations_count": items_count,
            "RenewalConfigurations": items_paged,
            "pager": pager,
        }
