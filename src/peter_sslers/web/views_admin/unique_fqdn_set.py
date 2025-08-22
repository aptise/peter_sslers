# stdlib
from typing import Dict
from typing import Optional

# pypi
import cert_utils
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_UniqueFQDNSet_modify
from ..lib.forms import Form_UniqueFQDNSet_new
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import UniqueFQDNSet


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:unique_fqdn_sets", renderer="/admin/unique_fqdn_sets.mako"
    )
    @view_config(
        route_name="admin:unique_fqdn_sets-paginated",
        renderer="/admin/unique_fqdn_sets.mako",
    )
    @view_config(route_name="admin:unique_fqdn_sets|json", renderer="json")
    @view_config(route_name="admin:unique_fqdn_sets-paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/unique-fqdn-sets.json",
            "section": "unique-fqdn-set",
            "about": """list UniqueFQDNSet(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/unique-fqdn-sets.json",
        }
    )
    @docify(
        {
            "endpoint": "/unique-fqdn-sets/{PAGE}.json",
            "section": "unique-fqdn-set",
            "example": "curl {ADMIN_PREFIX}/unique-fqdn-sets/1.json",
            "variant_of": "/unique-fqdn-sets.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__UniqueFQDNSet__count(self.request.api_context)
        url_template = (
            "%s/unique-fqdn-sets/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__UniqueFQDNSet__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
            eagerload_web=True,
        )
        if self.request.wants_json:
            _sets = {s.id: s.as_json for s in items_paged}
            return {
                "UniqueFQDNSets": _sets,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "UniqueFQDNSets_count": items_count,
            "UniqueFQDNSets": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbUniqueFQDNSet: Optional[UniqueFQDNSet] = None

    def _focus(self) -> UniqueFQDNSet:
        if self.dbUniqueFQDNSet is None:
            dbUniqueFQDNSet = lib_db.get.get__UniqueFQDNSet__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbUniqueFQDNSet:
                raise HTTPNotFound("the Unique FQDN Set was not found")
            self.dbUniqueFQDNSet = dbUniqueFQDNSet
            self._focus_item = dbUniqueFQDNSet
            self._focus_url = "%s/unique-fqdn-set/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbUniqueFQDNSet.id,
            )
        return self.dbUniqueFQDNSet

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_set:focus",
        renderer="/admin/unique_fqdn_set-focus.mako",
    )
    @view_config(route_name="admin:unique_fqdn_set:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/unique-fqdn-set/{ID}.json",
            "section": "unique-fqdn-set",
            "about": """unique-fqdn-set focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/unique-fqdn-set/1.json",
        }
    )
    def focus(self):
        dbUniqueFQDNSet = self._focus()
        if self.request.wants_json:
            return {"UniqueFQDNSet": dbUniqueFQDNSet.as_json}

        return {"project": "peter_sslers", "UniqueFQDNSet": dbUniqueFQDNSet}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_set:focus:calendar|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/unique-fqdn-set/{ID}/calendar.json",
            "section": "unique-fqdn-set",
            "about": """unique-fqdn-set focus: calendar""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/unique-fqdn-set/1/calendar.json",
        }
    )
    def calendar(self) -> Dict:
        rval: Dict = {}
        dbUniqueFQDNSet = self._focus()
        weekly_certs = lib_db.get.get_CertificateSigned_weeklyData_by_uniqueFqdnSetId(
            self.request.api_context,
            dbUniqueFQDNSet.id,
        )
        rval["issues"] = {}
        for wc in weekly_certs:
            rval["issues"][str(wc[0])] = wc[1]
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:unique_fqdn_set:focus:update_recents", renderer=None)
    @view_config(
        route_name="admin:unique_fqdn_set:focus:update_recents|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/unique-fqdn-set/{ID}/update-recents.json",
            "section": "unique-fqdn-set",
            "about": """unique-fqdn-set focus: update-recents""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/unique-fqdn-set/1/update-recents.json",
            "example": "curl -X POST {ADMIN_PREFIX}/unique-fqdn-set/1/update-recents.json",
        }
    )
    def update_recents(self):
        dbUniqueFQDNSet = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self, "/unique-fqdn-set/{ID}/update-recents.json"
                )
            return HTTPSeeOther(
                "%s?result=error&operation=update-recents&message=POST+required"
                % (self._focus_url,)
            )
        try:
            operations_event = (  # noqa: F841
                lib_db.actions.operations_update_recents__domains(
                    self.request.api_context,
                    dbUniqueFQDNSets=[
                        dbUniqueFQDNSet,
                    ],
                )
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "UniqueFQDNSet": dbUniqueFQDNSet.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=update-recents" % (self._focus_url,)
            )

        except Exception as exc:  # noqa: F841
            raise

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_set:focus:acme_orders",
        renderer="/admin/unique_fqdn_set-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:unique_fqdn_set:focus:acme_orders-paginated",
        renderer="/admin/unique_fqdn_set-focus-acme_orders.mako",
    )
    def related__AcmeOrders(self):
        dbUniqueFQDNSet = self._focus()
        items_count = lib_db.get.get__AcmeOrder__by_UniqueFQDNSetId__count(
            self.request.api_context, dbUniqueFQDNSet.id
        )
        url_template = "%s/acme-orders/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeOrder__by_UniqueFQDNSetId__paginated(
            self.request.api_context,
            dbUniqueFQDNSet.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "UniqueFQDNSet": dbUniqueFQDNSet,
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_set:focus:x509_certificate_requests",
        renderer="/admin/unique_fqdn_set-focus-x509_certificate_requests.mako",
    )
    @view_config(
        route_name="admin:unique_fqdn_set:focus:x509_certificate_requests-paginated",
        renderer="/admin/unique_fqdn_set-focus-x509_certificate_requests.mako",
    )
    def related__X509CertificateRequests(self):
        dbUniqueFQDNSet = self._focus()
        items_count = lib_db.get.get__X509CertificateRequest__by_UniqueFQDNSetId__count(
            self.request.api_context, dbUniqueFQDNSet.id
        )
        url_template = "%s/x509-certificate-requests/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__X509CertificateRequest__by_UniqueFQDNSetId__paginated(
                self.request.api_context,
                dbUniqueFQDNSet.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "UniqueFQDNSet": dbUniqueFQDNSet,
            "X509CertificateRequests_count": items_count,
            "X509CertificateRequests": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_set:focus:certificate_signeds",
        renderer="/admin/unique_fqdn_set-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:unique_fqdn_set:focus:certificate_signeds-paginated",
        renderer="/admin/unique_fqdn_set-focus-certificate_signeds.mako",
    )
    def related__CertificateSigneds(self):
        dbUniqueFQDNSet = self._focus()
        items_count = lib_db.get.get__CertificateSigned__by_UniqueFQDNSetId__count(
            self.request.api_context, dbUniqueFQDNSet.id
        )
        url_template = "%s/certificate-signeds/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateSigned__by_UniqueFQDNSetId__paginated(
            self.request.api_context,
            dbUniqueFQDNSet.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "UniqueFQDNSet": dbUniqueFQDNSet,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
        }

    @view_config(
        route_name="admin:unique_fqdn_set:focus:uniquely_challenged_fqdn_sets",
        renderer="/admin/unique_fqdn_set-focus-uniquely_challenged_fqdn_sets.mako",
    )
    @view_config(
        route_name="admin:unique_fqdn_set:focus:uniquely_challenged_fqdn_sets-paginated",
        renderer="/admin/unique_fqdn_set-focus-uniquely_challenged_fqdn_sets.mako",
    )
    def related__UniquelyChallengedFQDNSets(self):
        dbUniqueFQDNSet = self._focus()
        items_count = (
            lib_db.get.get__UniquelyChallengedFQDNSet__by_UniqueFQDNSetId__count(
                self.request.api_context, dbUniqueFQDNSet.id
            )
        )
        url_template = "%s/certificate-signeds/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__UniquelyChallengedFQDNSet__by_UniqueFQDNSetId__paginated(
                self.request.api_context,
                dbUniqueFQDNSet.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "UniqueFQDNSet": dbUniqueFQDNSet,
            "UniquelyChallengedFQDNSets_count": items_count,
            "UniquelyChallengedFQDNSets": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:unique_fqdn_set:focus:modify",
        renderer="/admin/unique_fqdn_set-focus-modify.mako",
    )
    @view_config(route_name="admin:unique_fqdn_set:focus:modify|json", renderer="json")
    @docify(
        {
            "endpoint": "/unique-fqdn-set/{ID}/modify.json",
            "section": "unique-fqdn-set",
            "about": """UniqueFQDNSet focus: modify""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/unique-fqdn-set/1/modify.json",
            "examples": [
                """curl """
                """--form 'domains_add=example.com,foo.example.com' """
                """--form 'domains_del=bar.example.com' """
                """{ADMIN_PREFIX}/modify.json"""
            ],
            "form_fields": {
                "domain_names_add": "a comma separated list of domains to add",
                "domain_names_del": "a comma separated list of domains to delete",
            },
        }
    )
    def modify(self):
        if self.request.method != "POST":
            return self._modify__print()
        return self._modify__submit()

    def _modify__print(self):
        """
        shared printing function
        """
        dbUniqueFQDNSet = self._focus()
        if self.request.wants_json:
            return formatted_get_docs(self, "/unique-fqdn-set/{ID}/modify.json")
        params = {
            "project": "peter_sslers",
            "UniqueFQDNSet": dbUniqueFQDNSet,
        }
        return render_to_response(
            "/admin/unique_fqdn_set-focus-modify.mako", params, self.request
        )

    def _modify__submit(self):
        dbUniqueFQDNSet = self._focus()
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_UniqueFQDNSet_modify,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            # localize form values
            domain_names_add = formStash.results["domain_names_add"]
            domain_names_del = formStash.results["domain_names_del"]

            # ensure domain names are submitted
            if not domain_names_add and not domain_names_del:
                formStash.fatal_form(error_main="no domain names submitted")

            # Pass 1- Validate Input
            # validate the domain names - add:
            try:
                # this function checks the domain names match a simple regex
                # domains will also be lowercase+strip
                domain_names_add = cert_utils.utils.domains_from_string(
                    domain_names_add,
                    allow_hostname=True,
                    allow_ipv4=True,
                    allow_ipv6=True,
                    ipv6_require_compressed=True,
                )
            except ValueError as exc:  # noqa: F841
                formStash.fatal_field(
                    field="domain_names_add",
                    error_field="invalid domain names detected",
                )
            # validate the domain names - del:
            try:
                # this function checks the domain names match a simple regex
                # domains will also be lowercase+strip
                domain_names_del = cert_utils.utils.domains_from_string(
                    domain_names_del,
                    allow_hostname=True,
                    allow_ipv4=True,
                    allow_ipv6=True,
                    ipv6_require_compressed=True,
                )
            except ValueError as exc:  # noqa: F841
                formStash.fatal_field(
                    field="domain_names_del",
                    error_field="invalid domain names detected",
                )

            # Pass 2- Aggregate Input
            # okay, and then again...
            if not domain_names_add and not domain_names_del:
                formStash.fatal_form(error_main="no valid domain names submitted")

            # any overlap?
            domain_names_add = set(domain_names_add)
            domain_names_del = set(domain_names_del)
            if not domain_names_add.isdisjoint(domain_names_del):
                formStash.fatal_form(
                    error_main="Identical domain names submitted for add and delete operations",
                )

            # calculate the validity of the new UniqueFQDNSet
            existing_domains = dbUniqueFQDNSet.domains_as_list
            _proposed_domains = set(existing_domains)
            _proposed_domains.update(domain_names_add)
            _proposed_domains.difference_update(domain_names_del)
            proposed_domains = list(_proposed_domains)
            if len(proposed_domains) > 100:
                formStash.fatal_form(
                    error_main="The proposed set contains more than 100 domain names. "
                    "There is a max of 100 domains per certificate.",
                )
            elif len(proposed_domains) < 1:
                formStash.fatal_form(
                    error_main="The proposed set contains less than 1 domain name.",
                )
            if set(existing_domains) == set(proposed_domains):
                formStash.fatal_form(
                    error_main="The proposed UniqueFQDNSet is identical to the existing UniqueFQDNSet.",
                )

            # okay, try to add it
            try:
                (
                    dbUniqueFQDNSet,
                    is_created,
                ) = lib_db.getcreate.getcreate__UniqueFQDNSet__by_domains(
                    self.request.api_context,
                    proposed_domains,
                    allow_blocklisted_domains=False,
                    discovery_type="fqdn modify",
                )
            except Exception as exc:  # noqa: F841
                raise

            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "modify",
                    "is_created": is_created,
                    "UniqueFQDNSet": dbUniqueFQDNSet.as_json,
                }
            return HTTPSeeOther(
                "%s/unique-fqdn-set/%s?result=success&operation=modify&is_created=%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbUniqueFQDNSet.id,
                    is_created,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._modify__print)


class ViewNew(Handler):
    @view_config(route_name="admin:unique_fqdn_set:new")
    @view_config(route_name="admin:unique_fqdn_set:new|json", renderer="json")
    @docify(
        {
            "endpoint": "/unique-fqdn-set/new.json",
            "section": "unique-fqdn-set",
            "about": """UniqueFQDNSet focus: new""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/unique-fqdn-set/new.json",
            "examples": [
                """curl """
                """--form 'domain_names=domain_names' """
                """{ADMIN_PREFIX}/unique-fqdn-set/new.json"""
            ],
            "form_fields": {
                "domain_names": "required; a comma separated list of domain names",
            },
        }
    )
    def new(self):
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/unique-fqdn-set/new.json")
        return render_to_response(
            "/admin/unique_fqdn_set-new.mako",
            {},
            self.request,
        )

    def _new__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_UniqueFQDNSet_new,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            # localize form values
            domain_names = formStash.results["domain_names"]

            # Pass 1- Validate Input
            try:
                # this function checks the domain names match a simple regex
                # domains will also be lowercase+strip
                domain_names = cert_utils.utils.domains_from_string(
                    domain_names,
                    allow_hostname=True,
                    allow_ipv4=True,
                    allow_ipv6=True,
                    ipv6_require_compressed=True,
                )
            except ValueError as exc:  # noqa: F841
                formStash.fatal_field(
                    field="domain_names",
                    error_field="invalid domain names detected",
                )

            # Pass 2- Aggregate Input
            # okay, and then again...
            if not domain_names:
                formStash.fatal_field(
                    field="domain_names",
                    error_field="no valid domain names submitted",
                )
            if len(domain_names) > 100:
                formStash.fatal_field(
                    field="domain_names",
                    error_field="more than 100 domain names submitted",
                )

            # okay, try to add it
            try:
                (
                    dbUniqueFQDNSet,
                    is_created,
                ) = lib_db.getcreate.getcreate__UniqueFQDNSet__by_domains(
                    self.request.api_context,
                    domain_names,
                    allow_blocklisted_domains=False,
                    discovery_type="upload",
                )
            except Exception as exc:  # noqa: F841
                raise

            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "new",
                    "is_created": is_created,
                    "UniqueFQDNSet": dbUniqueFQDNSet.as_json,
                }

            return HTTPSeeOther(
                "%s/unique-fqdn-set/%s?result=success&operation=new&is_created=%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbUniqueFQDNSet.id,
                    is_created,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)
