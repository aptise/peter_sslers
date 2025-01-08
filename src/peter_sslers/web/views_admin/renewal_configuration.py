# stdlib
from typing import Optional
from typing import TYPE_CHECKING

# from typing import Dict

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config

# local
from ..lib import form_utils as form_utils
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_RenewalConfig_new
from ..lib.forms import Form_RenewalConfig_new_configuration
from ..lib.forms import Form_RenewalConfig_new_order
from ..lib.forms import Form_RenewalConfiguration_mark
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils
from ...model.objects import AcmeOrder
from ...model.objects import RenewalConfiguration


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:renewal_configurations",
    )
    @view_config(
        route_name="admin:renewal_configurations|json",
    )
    def list_redirect(self):
        url_all = (
            "%s/renewal-configurations/active"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_all = "%s.json" % url_all
        return HTTPSeeOther(url_all)

    @view_config(
        route_name="admin:renewal_configurations:all",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:renewal_configurations:active",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:renewal_configurations:disabled",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:renewal_configurations:all_paginated",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:renewal_configurations:active_paginated",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:renewal_configurations:disabled_paginated",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(route_name="admin:renewal_configurations:all|json", renderer="json")
    @view_config(route_name="admin:renewal_configurations:active|json", renderer="json")
    @view_config(
        route_name="admin:renewal_configurations:disabled|json", renderer="json"
    )
    @view_config(
        route_name="admin:renewal_configurations:all_paginated|json", renderer="json"
    )
    @view_config(
        route_name="admin:renewal_configurations:active_paginated|json", renderer="json"
    )
    @view_config(
        route_name="admin:renewal_configurations:disabled_paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/renewal-configurations.json",
            "section": "renewal-configuration",
            "about": """list RenewalConfiguration(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/renewal-configurations.json",
        }
    )
    @docify(
        {
            "endpoint": "/renewal-configurations/{PAGE}.json",
            "section": "renewal-configuration",
            "example": "curl {ADMIN_PREFIX}/renewal-configurations/1.json",
            "variant_of": "/renewal-configurations.json",
        }
    )
    @docify(
        {
            "endpoint": "/renewal-configurations/all.json",
            "section": "renewal-configuration",
            "about": """list RenewalConfiguration(s) ALL""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/renewal-configurations/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/renewal-configurations/all/{PAGE}.json",
            "section": "renewal-configuration",
            "example": "curl {ADMIN_PREFIX}/renewal-configurations/all/1.json",
            "variant_of": "/renewal-configurations/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/renewal-configurations/active.json",
            "section": "renewal-configuration",
            "about": """list RenewalConfiguration(s) Active""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/renewal-configurations/active.json",
        }
    )
    @docify(
        {
            "endpoint": "/renewal-configurations/active/{PAGE}.json",
            "section": "renewal-configuration",
            "example": "curl {ADMIN_PREFIX}/renewal-configurations/active/1.json",
            "variant_of": "/renewal-configurations/active.json",
        }
    )
    @docify(
        {
            "endpoint": "/renewal-configurations/finished.json",
            "section": "renewal-configuration",
            "about": """list RenewalConfiguration(s) Finished""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/renewal-configurations/finished.json",
        }
    )
    @docify(
        {
            "endpoint": "/renewal-configurations/finished/{PAGE}.json",
            "section": "renewal-configuration",
            "example": "curl {ADMIN_PREFIX}/renewal-configurations/finished/1.json",
            "variant_of": "/renewal-configurations/finished.json",
        }
    )
    def list(self):
        sidenav_option: str = ""
        active_status: Optional[bool] = None
        if self.request.matched_route.name in (
            "admin:renewal_configurations:all",
            "admin:renewal_configurations:all_paginated",
            "admin:renewal_configurations:all|json",
            "admin:renewal_configurations:all_paginated|json",
        ):
            sidenav_option = "all"
            active_status = None
        elif self.request.matched_route.name in (
            "admin:renewal_configurations:active",
            "admin:renewal_configurations:active_paginated",
            "admin:renewal_configurations:active|json",
            "admin:renewal_configurations:active_paginated|json",
        ):
            sidenav_option = "active"
            active_status = True
        elif self.request.matched_route.name in (
            "admin:renewal_configurations:disabled",
            "admin:renewal_configurations:disabled_paginated",
            "admin:renewal_configurations:disabled|json",
            "admin:renewal_configurations:disabled_paginated|json",
        ):
            sidenav_option = "disabled"
            active_status = False

        url_template = "%s/renewal-configurations/%s/{0}" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            "sidenav_option",
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        items_count = lib_db.get.get__RenewalConfiguration__count(
            self.request.api_context, active_status=active_status
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__RenewalConfiguration__paginated(
            self.request.api_context,
            active_status=active_status,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            # admin_url = self.request.admin_url
            return {
                "RenewalConfigurations": [i.as_json for i in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "RenewalConfigurations_count": items_count,
            "RenewalConfigurations": items_paged,
            "pager": pager,
            "sidenav_option": sidenav_option,
        }


# ------------------------------------------------------------------------------


class View_Focus(Handler):
    dbRenewalConfiguration: Optional[RenewalConfiguration] = None
    _competing_dbAcmeOrder: Optional[AcmeOrder] = None

    def _focus(self) -> RenewalConfiguration:
        if self.dbRenewalConfiguration is None:
            dbRenewalConfiguration = lib_db.get.get__RenewalConfiguration__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbRenewalConfiguration:
                raise HTTPNotFound("the order was not found")
            self.dbRenewalConfiguration = dbRenewalConfiguration
            self._focus_url = "%s/renewal-configuration/%s" % (
                self.request.admin_url,
                self.dbRenewalConfiguration.id,
            )
        return self.dbRenewalConfiguration

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:renewal_configuration:focus",
        renderer="/admin/renewal_configuration-focus.mako",
    )
    @view_config(route_name="admin:renewal_configuration:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/renewal-configuration/{ID}.json",
            "section": "renewal-configuration",
            "about": """RenewalConfiguration focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/renewal-configuration/1.json",
        }
    )
    def focus(self):
        dbRenewalConfiguration = self._focus()
        if self.request.wants_json:
            return {
                "RenewalConfiguration": dbRenewalConfiguration.as_json,
            }
        return {
            "project": "peter_sslers",
            "RenewalConfiguration": dbRenewalConfiguration,
        }

    @view_config(
        route_name="admin:renewal_configuration:focus:acme_orders",
        renderer="/admin/renewal_configuration-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:renewal_configuration:focus:acme_orders_paginated",
        renderer="/admin/renewal_configuration-focus-acme_orders.mako",
    )
    @docify(
        {
            "endpoint": "/renewal-configuration/{ID}/acme-orders.json",
            "section": "renewal-configuration",
            "about": """RenewalConfiguration: Focus. list AcmeOrder(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/renewal-configuration/1/acme-orders.json",
        }
    )
    @docify(
        {
            "endpoint": "/renewal-configuration/{ID}/acme-orders/{PAGE}.json",
            "section": "renewal-configuration",
            "example": "curl {ADMIN_PREFIX}/renewal-configuration/1/acme-orders/1.json",
            "variant_of": "/renewal-configuration/{ID}/acme-orders.json",
        }
    )
    def related__AcmeOrders(self):
        dbRenewalConfiguration = self._focus()
        items_count = lib_db.get.get__AcmeOrder__by_RenewalConfigurationId__count(
            self.request.api_context, dbRenewalConfiguration.id
        )
        url_template = "%s/acme-orders/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeOrder__by_RenewalConfigurationId__paginated(
            self.request.api_context,
            dbRenewalConfiguration.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "RenewalConfiguration": dbRenewalConfiguration,
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:renewal_configuration:focus:certificate_signeds",
        renderer="/admin/renewal_configuration-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:renewal_configuration:focus:certificate_signeds_paginated",
        renderer="/admin/renewal_configuration-focus-certificate_signeds.mako",
    )
    def related__CertificateSigneds(self):
        dbRenewalConfiguration = self._focus()
        items_count = (
            lib_db.get.get__CertificateSigned__by_RenewalConfigurationId__count(
                self.request.api_context, dbRenewalConfiguration.id
            )
        )
        url_template = "%s/certificate-signeds/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__CertificateSigned__by_RenewalConfigurationId__paginated(
                self.request.api_context,
                dbRenewalConfiguration.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "RenewalConfiguration": dbRenewalConfiguration,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_Focus_Order(View_Focus):

    @view_config(
        route_name="admin:renewal_configuration:focus:new_order", renderer=None
    )
    @view_config(
        route_name="admin:renewal_configuration:focus:new_order|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/renewal-configuration/{ID}/new-order.json",
            "section": "renewal-configuration",
            "about": """AcmeOrder focus: Renew Quick""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/renewal-configuration/1/new-order.json",
            "form_fields": {
                "processing_strategy": "How should the order be processed?",
            },
            "valid_options": {
                "processing_strategy": model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL,
            },
            "instructions": [
                """curl --form 'processing_strategy=create_order' {ADMIN_PREFIX}/renewal-configuration/1/new-order.json""",
            ],
        }
    )
    def new_order(self):
        """
        This endpoint is for Immediately Renewing the AcmeOrder with this same Account .
        """
        dbRenewalConfiguration = self._focus()
        self._competing_dbAcmeOrder = (
            lib_db.associate.check_competing_orders_RenewalConfiguration(
                self.request.api_context,
                dbRenewalConfiguration,
            )
        )

        if self.request.method == "POST":
            return self._new_order__submit()
        return self._new_order__print()

    def _new_order__print(self):
        dbRenewalConfiguration = self._focus()
        if self.request.wants_json:
            return formatted_get_docs(
                self, "/renewal-configuration/{ID}/new-order.json"
            )

        return render_to_response(
            "/admin/renewal_configuration-focus-new_order.mako",
            {
                "RenewalConfiguration": dbRenewalConfiguration,
            },
            self.request,
        )

    def _new_order__submit(self):
        dbRenewalConfiguration = self._focus()
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_RenewalConfig_new_order,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            processing_strategy = formStash.results["processing_strategy"]
            try:
                dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__renewal_configuration(
                    self.request.api_context,
                    dbRenewalConfiguration=dbRenewalConfiguration,
                    processing_strategy=processing_strategy,
                    acme_order_type_id=model_utils.AcmeOrderType.RENEWAL_CONFIGURATION_REQUEST,
                )
            except errors.AcmeOrderCreatedError as exc:
                # unpack a `errors.AcmeOrderCreatedError` to local vars
                dbAcmeOrderNew = exc.acme_order
                exc = exc.original_exception
                if self.request.wants_json:
                    return {
                        "result": "error",
                        "error": str(exc),
                        "AcmeOrder": dbAcmeOrderNew.as_json,
                    }
                return HTTPSeeOther(
                    "%s/acme-order/%s?result=error&error=%s&operation=renewal+configuration"
                    % (self.request.admin_url, dbAcmeOrderNew.id, exc.as_querystring)
                )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeOrder": dbAcmeOrderNew.as_json,
                }
            return HTTPSeeOther(
                "%s/acme-order/%s?result=success&operation=renewal+configuration"
                % (self.request.admin_url, dbAcmeOrderNew.id)
            )
        except (
            errors.AcmeError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {"result": "error", "error": str(exc)}
            url_failure = "%s?result=error&error=%s&operation=renewal+configuration" % (
                self._focus_url,
                exc.as_querystring,
            )
            raise HTTPSeeOther(url_failure)
        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new_order__print)

    @view_config(
        route_name="admin:renewal_configuration:focus:new_configuration", renderer=None
    )
    @view_config(
        route_name="admin:renewal_configuration:focus:new_configuration|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/renewal-configuration/{ID}/new-configuration.json",
            "section": "renewal-configuration",
            "about": """AcmeOrder focus: Renew Quick""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/renewal-configuration/1/new-configuration.json",
            "form_fields": {
                "processing_strategy": "How should the order be processed?",
            },
            "valid_options": {
                "processing_strategy": model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL,
            },
            "instructions": [
                """curl --form 'processing_strategy=create_order' {ADMIN_PREFIX}/renewal-configuration/1/new-configuration.json""",
            ],
        }
    )
    def new_configuration(self):
        """
        This is basically forking the configuration
        """
        self._load_AcmeAccount_GlobalDefault()
        self._load_AcmeDnsServer_GlobalDefault()
        self._load_AcmeServers()
        if self.request.method == "POST":
            return self._new_configuration__submit()
        return self._new_configuration__print()

    def _new_configuration__print(self):
        dbRenewalConfiguration = self._focus()
        if self.request.wants_json:
            return formatted_get_docs(
                self, "/renewal-configuration/{ID}/new-configuration.json"
            )

        return render_to_response(
            "/admin/renewal_configuration-focus-new_configuration.mako",
            {
                "RenewalConfiguration": dbRenewalConfiguration,
                "AcmeAccount_GlobalDefault": self.dbAcmeAccount_GlobalDefault,
                "AcmeDnsServer_GlobalDefault": self.dbAcmeDnsServer_GlobalDefault,
                "AcmeServers": self.dbAcmeServers,
            },
            self.request,
        )

    def _new_configuration__submit(self):
        """
        much of this logic is shared with /api/domain-certificate-if-needed
        """
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_RenewalConfig_new_configuration,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            domains_challenged = form_utils.form_domains_challenge_typed(
                self.request,
                formStash,
                dbAcmeDnsServer_GlobalDefault=self.dbAcmeDnsServer_GlobalDefault,
            )

            acmeAccountSelection = form_utils.parse_AcmeAccountSelection(
                self.request,
                formStash,
                account_key_option=formStash.results["account_key_option"],
                require_contact=False,
            )
            assert acmeAccountSelection.AcmeAccount is not None
            private_key_cycle = formStash.results["private_key_cycle"]
            private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
                private_key_cycle
            )
            key_technology = formStash.results["key_technology"]
            key_technology_id = model_utils.KeyTechnology.from_string(key_technology)
            try:
                domains_all = []
                # check for blocklists here
                # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
                # this may raise errors.AcmeDomainsBlocklisted
                for challenge_, domains_ in domains_challenged.items():
                    if domains_:
                        lib_db.validate.validate_domain_names(
                            self.request.api_context, domains_
                        )
                        if challenge_ == "dns-01":
                            # check to ensure the domains are configured for dns-01
                            # this may raise errors.AcmeDomainsRequireConfigurationAcmeDNS
                            try:
                                lib_db.validate.ensure_domains_dns01(
                                    self.request.api_context, domains_
                                )
                            except errors.AcmeDomainsRequireConfigurationAcmeDNS as exc:
                                # in "experimental" mode, we may want to use specific
                                # acme-dns servers and not the global one
                                if (
                                    self.request.registry.settings["acme_dns_support"]
                                    == "experimental"
                                ):
                                    raise
                                # in "basic" mode we can just associate these to the global option
                                if not self.dbAcmeDnsServer_GlobalDefault:
                                    formStash.fatal_field(
                                        "domain_names_dns01",
                                        "No global acme-dns server configured.",
                                    )
                                if TYPE_CHECKING:
                                    assert (
                                        self.dbAcmeDnsServer_GlobalDefault is not None
                                    )
                                # exc.args[0] will be the listing of domains
                                (domainObjects, adnsAccountObjects) = (
                                    lib_db.associate.ensure_domain_names_to_acmeDnsServer(
                                        self.request.api_context,
                                        exc.args[0],
                                        self.dbAcmeDnsServer_GlobalDefault,
                                        discovery_type="via renewal_configuration.new",
                                    )
                                )
                        domains_all.extend(domains_)

                # create the configuration
                # this will create:
                # * model_utils.RenewableConfig
                # * model_utils.UniquelyChallengedFQDNSet2Domain
                # * model_utils.UniqueFQDNSet
                dbRenewalConfiguration = lib_db.create.create__RenewalConfiguration(
                    self.request.api_context,
                    dbAcmeAccount=acmeAccountSelection.AcmeAccount,
                    private_key_cycle_id=private_key_cycle_id,
                    key_technology_id=key_technology_id,
                    domains_challenged=domains_challenged,
                )

                if self.request.wants_json:
                    return {
                        "result": "success",
                        "RenewalConfiguration": dbRenewalConfiguration.as_json,
                    }

                return HTTPSeeOther(
                    "%s/renewal-configuration/%s"
                    % (
                        self.request.registry.settings["app_settings"]["admin_prefix"],
                        dbRenewalConfiguration.id,
                    )
                )

            except (
                errors.AcmeDomainsBlocklisted,
                errors.AcmeDomainsRequireConfigurationAcmeDNS,
            ) as exc:
                formStash.fatal_field(field="Error_Main", message=str(exc))

            except (errors.DuplicateRenewalConfiguration,) as exc:
                formStash.fatal_field(
                    field="Error_Main",
                    message="""This appears to be a duplicate of """
                    """RenewalConfiguration: %s.""" % exc.args[0].id,
                )

            except errors.AcmeDuplicateChallenges as exc:
                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}
                formStash.fatal_field(field="Error_Main", message=str(exc))

            except (
                errors.AcmeError,
                errors.InvalidRequest,
            ) as exc:
                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}

                return HTTPSeeOther(
                    "%s/renewal-configurations/all?result=error&error=%s&operation=new+freeform"
                    % (
                        self.request.registry.settings["app_settings"]["admin_prefix"],
                        exc.as_querystring,
                    )
                )
            except Exception as exc:  # noqa: F841
                raise
                # note: allow this on testing
                # raise
                if self.request.registry.settings["exception_redirect"]:
                    return HTTPSeeOther(
                        "%s/renewal-configurations/all?result=error&operation=new-freeform"
                        % self.request.registry.settings["app_settings"]["admin_prefix"]
                    )
                raise

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(
                self.request, self._new_configuration__print
            )


class View_Focus_Manipulate(View_Focus):

    @view_config(route_name="admin:renewal_configuration:focus:mark", renderer=None)
    @view_config(
        route_name="admin:renewal_configuration:focus:mark|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/renewal-configuration/{ID}/mark.json",
            "section": "renewal-configuration",
            "about": """RenewalConfiguration: Focus. Mark""",
            "POST": True,
            "GET": None,
            "example": "curl --form 'action=active' {ADMIN_PREFIX}/renewal-configuration/1/mark.json",
            "form_fields": {"action": "the intended action"},
            "valid_options": {"action": ["active", "inactive"]},
        }
    )
    def focus_mark(self):
        dbRenewalConfiguration = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._focus_mark__submit()
        return self._focus_mark__print()

    def _focus_mark__print(self):
        dbRenewalConfiguration = self._focus()  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(self, "/renewal-configuration/{ID}/mark.json")
        url_post_required = "%s?result=error&error=post+required&operation=mark" % (
            self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self):
        dbRenewalConfiguration = self._focus()  # noqa: F841
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_RenewalConfiguration_mark,
                validate_get=False,
                # validate_post=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string(
                "RenewalConfiguration__mark"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["renewal_configuration_id"] = dbRenewalConfiguration.id
            event_payload_dict["action"] = formStash.results["action"]

            event_status: Optional[str] = None

            try:
                if action == "active":
                    event_status = (
                        lib_db.update.update_RenewalConfiguration__set_active(
                            self.request.api_context, dbRenewalConfiguration
                        )
                    )

                elif action == "inactive":
                    event_status = (
                        lib_db.update.update_RenewalConfiguration__unset_active(
                            self.request.api_context, dbRenewalConfiguration
                        )
                    )

                else:
                    raise errors.InvalidTransition("Invalid option")

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

            if TYPE_CHECKING:
                assert event_status is not None

            self.request.api_context.dbSession.flush(objects=[dbRenewalConfiguration])

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
                dbRenewalConfiguration=dbRenewalConfiguration,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "RenewalConfiguration": dbRenewalConfiguration.as_json,
                }
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

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_New(Handler):
    @view_config(route_name="admin:renewal_configuration:new")
    @view_config(route_name="admin:renewal_configuration:new|json", renderer="json")
    @docify(
        {
            "endpoint": "/renewal-configuration/new/freeform.json",
            "section": "renewal-configuration",
            "about": """AcmeOrder: New Freeform""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/renewal-configuration/new/freeform.json",
            "form_fields": {
                "domain_names_http01": "required; a comma separated list of domain names to process",
                "domain_names_dns01": "required; a comma separated list of domain names to process",
                "processing_strategy": "How should the order be processed?",
                "account_key_option": "How is the AcmeAccount specified?",
                "account_key_reuse": "pem_md5 of the existing account key. Must/Only submit if `account_key_option==account_key_reuse`",
                "account_key_global_default": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option==account_key_global_default`",
                "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                "account_key_file_pem": "pem of the account key file. Must/Only submit if `account_key_option==account_key_file`",
                "acme_server_id": "account provider. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is used.",
                "account_key_file_le_meta": "LetsEncrypt Certbot file. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is not used",
                "account_key_file_le_pkey": "LetsEncrypt Certbot file",
                "account_key_file_le_reg": "LetsEncrypt Certbot file",
                "private_key_option": "How is the PrivateKey being specified?",
                "private_key_reuse": "pem_md5 of existing key",
                "private_key_existing": "pem_md5 of existing key",
                "private_key_file_pem": "pem to upload",
                "private_key_cycle": "how should the PrivateKey be cycled on renewals?",
            },
            "form_fields_related": [
                ["account_key_file_pem", "acme_server_id"],
                ["domain_names_http01", "domain_names_dns01"],
                [
                    "account_key_file_le_meta",
                    "account_key_file_le_pkey",
                    "account_key_file_le_reg",
                ],
            ],
            "valid_options": {
                "acme_server_id": "{RENDER_ON_REQUEST}",
                "account_key_option": model_utils.AcmeAccountKey_options_b,
                "processing_strategy": model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL,
                "private_key_option": model_utils.PrivateKey_options_b,
                "AcmeAccount_GlobalDefault": "{RENDER_ON_REQUEST}",
                "private_key_cycle": model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
            },
            "requirements": [
                "Submit corresponding field(s) to account_key_option. If `account_key_file` is your intent, submit either PEM+ProviderID or the three LetsEncrypt Certbot files.",
                "Submit at least one of `domain_names_http01` or `domain_names_dns01`",
            ],
            "instructions": [
                """curl --form 'account_key_option=account_key_reuse' --form 'account_key_reuse=ff00ff00ff00ff00' 'private_key_option=private_key_reuse' --form 'private_key_reuse=ff00ff00ff00ff00' {ADMIN_PREFIX}/renewal-configuration/new/freeform.json""",
            ],
        }
    )
    def new(self):
        self._load_AcmeAccount_GlobalDefault()
        self._load_AcmeDnsServer_GlobalDefault()
        self._load_AcmeServers()
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/renewal-configuration/new.json")
        return render_to_response(
            "/admin/renewal_configuration-new.mako",
            {
                "AcmeAccount_GlobalDefault": self.dbAcmeAccount_GlobalDefault,
                "AcmeDnsServer_GlobalDefault": self.dbAcmeDnsServer_GlobalDefault,
                "AcmeServers": self.dbAcmeServers,
                "domain_names_http01": self.request.params.get(
                    "domain_names_http01", ""
                ),
                "domain_names_dns01": self.request.params.get("domain_names_dns01", ""),
            },
            self.request,
        )

    def _new__submit(self):
        """
        much of this logic is shared with /api/domain-certificate-if-needed
        """
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_RenewalConfig_new,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            domains_challenged = form_utils.form_domains_challenge_typed(
                self.request,
                formStash,
                dbAcmeDnsServer_GlobalDefault=self.dbAcmeDnsServer_GlobalDefault,
            )

            acmeAccountSelection = form_utils.parse_AcmeAccountSelection(
                self.request,
                formStash,
                account_key_option=formStash.results["account_key_option"],
                require_contact=False,
            )
            assert acmeAccountSelection.AcmeAccount is not None
            private_key_cycle = formStash.results["private_key_cycle"]
            private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(
                private_key_cycle
            )
            key_technology = formStash.results["key_technology"]
            key_technology_id = model_utils.KeyTechnology.from_string(key_technology)
            try:
                domains_all = []
                # check for blocklists here
                # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
                # this may raise errors.AcmeDomainsBlocklisted
                for challenge_, domains_ in domains_challenged.items():
                    if domains_:
                        lib_db.validate.validate_domain_names(
                            self.request.api_context, domains_
                        )
                        if challenge_ == "dns-01":
                            # check to ensure the domains are configured for dns-01
                            # this may raise errors.AcmeDomainsRequireConfigurationAcmeDNS
                            try:
                                lib_db.validate.ensure_domains_dns01(
                                    self.request.api_context, domains_
                                )
                            except errors.AcmeDomainsRequireConfigurationAcmeDNS as exc:
                                # in "experimental" mode, we may want to use specific
                                # acme-dns servers and not the global one
                                if (
                                    self.request.registry.settings["acme_dns_support"]
                                    == "experimental"
                                ):
                                    raise
                                # in "basic" mode we can just associate these to the global option
                                if not self.dbAcmeDnsServer_GlobalDefault:
                                    formStash.fatal_field(
                                        "domain_names_dns01",
                                        "No global acme-dns server configured.",
                                    )
                                if TYPE_CHECKING:
                                    assert (
                                        self.dbAcmeDnsServer_GlobalDefault is not None
                                    )
                                # exc.args[0] will be the listing of domains
                                (domainObjects, adnsAccountObjects) = (
                                    lib_db.associate.ensure_domain_names_to_acmeDnsServer(
                                        self.request.api_context,
                                        exc.args[0],
                                        self.dbAcmeDnsServer_GlobalDefault,
                                        discovery_type="via renewal_configuration.new",
                                    )
                                )
                        domains_all.extend(domains_)

                # create the configuration
                # this will create:
                # * model_utils.RenewableConfig
                # * model_utils.UniquelyChallengedFQDNSet2Domain
                # * model_utils.UniqueFQDNSet
                dbRenewalConfiguration = lib_db.create.create__RenewalConfiguration(
                    self.request.api_context,
                    dbAcmeAccount=acmeAccountSelection.AcmeAccount,
                    private_key_cycle_id=private_key_cycle_id,
                    key_technology_id=key_technology_id,
                    domains_challenged=domains_challenged,
                )

                if self.request.wants_json:
                    return {
                        "result": "success",
                        "RenewalConfiguration": dbRenewalConfiguration.as_json,
                    }

                return HTTPSeeOther(
                    "%s/renewal-configuration/%s"
                    % (
                        self.request.registry.settings["app_settings"]["admin_prefix"],
                        dbRenewalConfiguration.id,
                    )
                )

            except (
                errors.AcmeDomainsBlocklisted,
                errors.AcmeDomainsRequireConfigurationAcmeDNS,
            ) as exc:
                formStash.fatal_field(field="Error_Main", message=str(exc))

            except (errors.DuplicateRenewalConfiguration,) as exc:
                formStash.fatal_field(
                    field="Error_Main",
                    message="""This appears to be a duplicate of """
                    """RenewalConfiguration: %s.""" % exc.args[0].id,
                )

            except errors.AcmeDuplicateChallenges as exc:
                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}
                formStash.fatal_field(field="Error_Main", message=str(exc))

            except (
                errors.AcmeError,
                errors.InvalidRequest,
            ) as exc:
                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}

                return HTTPSeeOther(
                    "%s/renewal-configurations/all?result=error&error=%s&operation=new+freeform"
                    % (
                        self.request.registry.settings["app_settings"]["admin_prefix"],
                        exc.as_querystring,
                    )
                )
            except Exception as exc:  # noqa: F841
                raise
                # note: allow this on testing
                # raise
                if self.request.registry.settings["exception_redirect"]:
                    return HTTPSeeOther(
                        "%s/renewal-configurations/all?result=error&operation=new-freeform"
                        % self.request.registry.settings["app_settings"]["admin_prefix"]
                    )
                raise

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)
