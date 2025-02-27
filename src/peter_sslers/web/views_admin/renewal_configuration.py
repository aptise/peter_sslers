# stdlib
from typing import List
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

if TYPE_CHECKING:
    from ...model.objects import CertificateSigned

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
            % self.request.api_context.application_settings["admin_prefix"]
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
        route_name="admin:renewal_configurations:all-paginated",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:renewal_configurations:active-paginated",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:renewal_configurations:disabled-paginated",
        renderer="/admin/renewal_configurations.mako",
    )
    @view_config(route_name="admin:renewal_configurations:all|json", renderer="json")
    @view_config(route_name="admin:renewal_configurations:active|json", renderer="json")
    @view_config(
        route_name="admin:renewal_configurations:disabled|json", renderer="json"
    )
    @view_config(
        route_name="admin:renewal_configurations:all-paginated|json", renderer="json"
    )
    @view_config(
        route_name="admin:renewal_configurations:active-paginated|json", renderer="json"
    )
    @view_config(
        route_name="admin:renewal_configurations:disabled-paginated|json",
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
            "admin:renewal_configurations:all-paginated",
            "admin:renewal_configurations:all|json",
            "admin:renewal_configurations:all-paginated|json",
        ):
            sidenav_option = "all"
            active_status = None
        elif self.request.matched_route.name in (
            "admin:renewal_configurations:active",
            "admin:renewal_configurations:active-paginated",
            "admin:renewal_configurations:active|json",
            "admin:renewal_configurations:active-paginated|json",
        ):
            sidenav_option = "active"
            active_status = True
        elif self.request.matched_route.name in (
            "admin:renewal_configurations:disabled",
            "admin:renewal_configurations:disabled-paginated",
            "admin:renewal_configurations:disabled|json",
            "admin:renewal_configurations:disabled-paginated|json",
        ):
            sidenav_option = "disabled"
            active_status = False

        url_template = "%s/renewal-configurations/%s/{0}" % (
            self.request.api_context.application_settings["admin_prefix"],
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
    _dbCertificateSigned_replaces_candidates__primary: Optional[
        List["CertificateSigned"]
    ] = None
    _dbCertificateSigned_replaces_candidates__backup: Optional[
        List["CertificateSigned"]
    ] = None

    @property
    def dbCertificateSigned_replaces_candidates__primary(
        self,
    ) -> List["CertificateSigned"]:
        assert self.dbRenewalConfiguration
        if self._dbCertificateSigned_replaces_candidates__primary is None:
            self._dbCertificateSigned_replaces_candidates__primary = (
                lib_db.get.get__CertificateSigned_replaces_candidates(
                    self.request.api_context,
                    dbRenewalConfiguration=self.dbRenewalConfiguration,
                    certificate_type=model_utils.CertificateType_Enum.MANAGED_PRIMARY,
                )
            )
        return self._dbCertificateSigned_replaces_candidates__primary

    @property
    def dbCertificateSigned_replaces_candidates__backup(
        self,
    ) -> List["CertificateSigned"]:
        assert self.dbRenewalConfiguration

        if self._dbCertificateSigned_replaces_candidates__backup is None:
            if not self.dbRenewalConfiguration.acme_account_id__backup:
                # don't bother with an impossible search
                self._dbCertificateSigned_replaces_candidates__backup = []
            else:
                self._dbCertificateSigned_replaces_candidates__backup = lib_db.get.get__CertificateSigned_replaces_candidates(
                    self.request.api_context,
                    dbRenewalConfiguration=self.dbRenewalConfiguration,
                    certificate_type=model_utils.CertificateType_Enum.MANAGED_BACKUP,
                )
        return self._dbCertificateSigned_replaces_candidates__backup

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
                "CertificateSigned_replaces_candidates__primary": [
                    i.as_json_replaces_candidate
                    for i in self.dbCertificateSigned_replaces_candidates__primary
                ],
                "CertificateSigned_replaces_candidates__backup": [
                    i.as_json_replaces_candidate
                    for i in self.dbCertificateSigned_replaces_candidates__backup
                ],
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
        route_name="admin:renewal_configuration:focus:acme_orders-paginated",
        renderer="/admin/renewal_configuration-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:renewal_configuration:focus:acme_orders|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:renewal_configuration:focus:acme_orders-paginated|json",
        renderer="json",
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
        if self.request.wants_json:
            _AcmeOrders = [k.as_json for k in items_paged]
            return {
                "AcmeOrders": _AcmeOrders,
                "pagination": json_pagination(items_count, pager),
            }
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
        route_name="admin:renewal_configuration:focus:certificate_signeds-paginated",
        renderer="/admin/renewal_configuration-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:renewal_configuration:focus:certificate_signeds|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:renewal_configuration:focus:certificate_signeds-paginated|json",
        renderer="json",
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
        if self.request.wants_json:
            _CertificateSigneds = [k.as_json for k in items_paged]
            return {
                "CertificateSigneds": _CertificateSigneds,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "RenewalConfiguration": dbRenewalConfiguration,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_Focus_New(View_Focus):

    replaces_CertificateSigned: Optional["CertificateSigned"] = None

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
            "instructions": "curl {ADMIN_PREFIX}/renewal-configuration/1/new-order.json",
            "form_fields": {
                "note": "A string to associate with the AcmeOrder.",
                "processing_strategy": "How should the order be processed?",
                "replaces": "ARI identifier of Certificate to replace. Eligible candidates are available from the focus endpoint. If omitted, a duplicate cert will be created.",
                "replaces_certificate_type": "Only submit if replacing an imported certificate, to instruct which ACME Account should be used",
            },
            "valid_options": {
                "processing_strategy": Form_RenewalConfig_new_order.fields[
                    "processing_strategy"
                ].list,
                "replaces_certificate_type": Form_RenewalConfig_new_order.fields[
                    "replaces_certificate_type"
                ].list,
            },
            "examples": [
                """curl """
                """--form 'processing_strategy=create_order' """
                """{ADMIN_PREFIX}/renewal-configuration/1/new-order.json""",
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
                "CertificateSigned_replaces_candidates__primary": self.dbCertificateSigned_replaces_candidates__primary,
                "CertificateSigned_replaces_candidates__backup": self.dbCertificateSigned_replaces_candidates__backup,
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

            note = formStash.results["note"]
            processing_strategy = formStash.results["processing_strategy"]

            # this will be validated in do__AcmeV2_AcmeOrder__new
            replaces = formStash.results["replaces"]
            # this defaults to "primary" if None
            replaces_certificate_type = formStash.results["replaces_certificate_type"]
            try:
                dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    self.request.api_context,
                    dbRenewalConfiguration=dbRenewalConfiguration,
                    processing_strategy=processing_strategy,
                    acme_order_type_id=model_utils.AcmeOrderType.RENEWAL_CONFIGURATION_REQUEST,
                    note=note,
                    replaces=replaces,
                    replaces_type=model_utils.ReplacesType_Enum.MANUAL,
                    replaces_certificate_type=replaces_certificate_type,
                )
            except errors.FieldError as exc:
                raise formStash.fatal_field(
                    field=exc.args[0],
                    message=exc.args[1],
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
            except Exception as exc:
                raise formStash.fatal_form(
                    message="%s" % exc,
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
            "instructions": "curl {ADMIN_PREFIX}/renewal-configuration/1/new-configuration.json",
            "form_fields": {
                # ALL certs
                "domain_names_http01": "required; a comma separated list of domain names to process",
                "domain_names_dns01": "required; a comma separated list of domain names to process",
                "note": "A string to associate with the RenewalConfiguration.",
                # primary cert
                "account_key_option": "How is the AcmeAccount specified?",
                "account_key_global_default": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option==account_key_global_default`",
                "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                "private_key_cycle__primary": "how should the PrivateKey be cycled on renewals?",
                "private_key_technology__primary": "what kind of keys to use?",
                "acme_profile__primary": "The name of an ACME Profile on the ACME Server",
                # backup cert
                "account_key_option_backup": "How is the AcmeAccount specified? [Backup Cert]",
                "account_key_global_backup": "pem_md5 of the Global Backup account key. Must/Only submit if `account_key_option_backup==account_key_global_backup` [Backup Cert]",
                "account_key_existing_backup": "pem_md5 of any key. Must/Only submit if `account_key_option_backup==account_key_existing_backup` [Backup Cert]",
                "private_key_cycle__backup": "how should the PrivateKey be cycled on renewals?",
                "private_key_technology__backup": "what kind of keys to use?",
                "acme_profile__backup": "The name of an ACME Profile on the ACME Server [Backup Cert]",
            },
            "form_fields_related": [
                ["domain_names_http01", "domain_names_dns01"],
                [
                    "account_key_option",
                    "account_key_global_default",
                    "account_key_existing",
                    "acme_profile__primary",
                ],
                [
                    "account_key_option_backup",
                    "account_key_global_backup",
                    "account_key_existing_backup",
                    "acme_profile__backup",
                ],
            ],
            "valid_options": {
                "EnrollmentPolicys": "{RENDER_ON_REQUEST}",
                "account_key_option": Form_RenewalConfig_new_configuration.fields[
                    "account_key_option"
                ].list,
                "account_key_option_backup": Form_RenewalConfig_new.fields[
                    "account_key_option_backup"
                ].list,
                "private_key_cycle__primary": Form_RenewalConfig_new_configuration.fields[
                    "private_key_cycle__primary"
                ].list,
                "private_key_technology__primary": Form_RenewalConfig_new_configuration.fields[
                    "private_key_technology__primary"
                ].list,
                "private_key_cycle__backup": Form_RenewalConfig_new_configuration.fields[
                    "private_key_cycle__backup"
                ].list,
                "private_key_technology__backup": Form_RenewalConfig_new_configuration.fields[
                    "private_key_technology__backup"
                ].list,
            },
            "examples": [
                """curl """
                """--form 'account_key_option=global_default' """
                """{ADMIN_PREFIX}/renewal-configuration/1/new-configuration.json""",
            ],
        }
    )
    def new_configuration(self):
        """
        This is basically forking the configuration
        """
        self.request.api_context._load_EnrollmentPolicy_global()
        self.request.api_context._load_AcmeDnsServer_GlobalDefault()
        self.request.api_context._load_AcmeServers()
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
                "EnrollmentPolicy_global": self.request.api_context.dbEnrollmentPolicy_global,
                "AcmeDnsServer_GlobalDefault": self.request.api_context.dbAcmeDnsServer_GlobalDefault,
                "AcmeServers": self.request.api_context.dbAcmeServers,
            },
            self.request,
        )

    def _new_configuration__submit(self):
        """ """
        dbRenewalConfiguration = self._focus()
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
                dbAcmeDnsServer_GlobalDefault=self.request.api_context.dbAcmeDnsServer_GlobalDefault,
            )

            acmeAccountSelection = form_utils.parse_AcmeAccountSelection(
                self.request,
                formStash,
                require_contact=False,
                support_upload=False,
            )
            assert acmeAccountSelection.AcmeAccount is not None

            acmeAccountSelection_backup = form_utils.parse_AcmeAccountSelection_backup(
                self.request,
                formStash,
            )

            # shared
            note = formStash.results["note"]

            # PRIMARY cert
            acme_profile__primary = formStash.results["acme_profile__primary"]
            private_key_technology__primary = formStash.results[
                "private_key_technology__primary"
            ]
            private_key_technology_id__primary = model_utils.KeyTechnology.from_string(
                private_key_technology__primary
            )
            private_key_cycle__primary = formStash.results["private_key_cycle__primary"]
            private_key_cycle_id__primary = model_utils.PrivateKeyCycle.from_string(
                private_key_cycle__primary
            )

            # BACKUP cert
            private_key_technology__backup = formStash.results[
                "private_key_technology__backup"
            ]
            private_key_technology_id__backup = None
            if private_key_technology__backup:
                private_key_technology_id__backup = (
                    model_utils.KeyTechnology.from_string(
                        private_key_technology__backup
                    )
                )
            private_key_cycle__backup = formStash.results["private_key_cycle__backup"]
            private_key_cycle_id__backup = None
            if private_key_cycle__backup:
                private_key_cycle_id__backup = model_utils.PrivateKeyCycle.from_string(
                    private_key_cycle__backup
                )
            acme_profile__backup = formStash.results["acme_profile__backup"]

            if not acmeAccountSelection_backup.AcmeAccount:
                private_key_cycle_id__backup = None
                private_key_technology_id__backup = None
                acme_profile__backup = None

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
                                    self.request.api_context.application_settings[
                                        "acme_dns_support"
                                    ]
                                    == "experimental"
                                ):
                                    raise
                                # in "basic" mode we can just associate these to the global option
                                if (
                                    not self.request.api_context.dbAcmeDnsServer_GlobalDefault
                                ):
                                    formStash.fatal_field(
                                        "domain_names_dns01",
                                        "No global acme-dns server configured.",
                                    )
                                if TYPE_CHECKING:
                                    assert (
                                        self.request.api_context.dbAcmeDnsServer_GlobalDefault
                                        is not None
                                    )
                                # exc.args[0] will be the listing of domains
                                (domainObjects, adnsAccountObjects) = (
                                    lib_db.associate.ensure_domain_names_to_acmeDnsServer(
                                        self.request.api_context,
                                        exc.args[0],
                                        self.request.api_context.dbAcmeDnsServer_GlobalDefault,
                                        discovery_type="via renewal_configuration.new",
                                    )
                                )
                        domains_all.extend(domains_)

                # create the configuration
                # this will create:
                # * model_utils.RenewableConfig
                # * model_utils.UniquelyChallengedFQDNSet2Domain
                # * model_utils.UniqueFQDNSet
                is_duplicate_renewal = None
                try:
                    dbRenewalConfiguration_new = lib_db.create.create__RenewalConfiguration(
                        self.request.api_context,
                        domains_challenged=domains_challenged,
                        # PRIMARY cert
                        dbAcmeAccount__primary=acmeAccountSelection.AcmeAccount,
                        private_key_cycle_id__primary=private_key_cycle_id__primary,
                        private_key_technology_id__primary=private_key_technology_id__primary,
                        acme_profile__primary=acme_profile__primary,
                        # BACKUP cert
                        dbAcmeAccount__backup=acmeAccountSelection_backup.AcmeAccount,
                        private_key_cycle_id__backup=private_key_cycle_id__backup,
                        private_key_technology_id__backup=private_key_technology_id__backup,
                        acme_profile__backup=acme_profile__backup,
                        # misc
                        note=note,
                    )
                    is_duplicate_renewal = False

                    # and turn the existing one off...
                    if dbRenewalConfiguration.is_active:
                        lib_db.update.update_RenewalConfiguration__unset_active(
                            self.request.api_context,
                            dbRenewalConfiguration,
                        )

                except errors.DuplicateRenewalConfiguration as exc:
                    is_duplicate_renewal = True
                    # we could raise exc to abort, but this is likely preferred
                    dbRenewalConfiguration_new = exc.args[0]

                if self.request.wants_json:
                    return {
                        "result": "success",
                        "RenewalConfiguration": dbRenewalConfiguration_new.as_json,
                        "is_duplicate_renewal": is_duplicate_renewal,
                    }

                return HTTPSeeOther(
                    "%s/renewal-configuration/%s%s"
                    % (
                        self.request.api_context.application_settings["admin_prefix"],
                        dbRenewalConfiguration_new.id,
                        "?is_duplicate_renewal=true" if is_duplicate_renewal else "",
                    )
                )

            except (
                errors.AcmeDomainsBlocklisted,
                errors.AcmeDomainsRequireConfigurationAcmeDNS,
            ) as exc:
                formStash.fatal_form(message=str(exc))

            except (errors.DuplicateRenewalConfiguration,) as exc:
                message = (
                    "This appears to be a duplicate of RenewalConfiguration: `%s`."
                    % exc.args[0].id
                )
                formStash.fatal_form(message=message)

            except errors.AcmeDuplicateChallenges as exc:
                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}
                formStash.fatal_form(message=str(exc))

            except errors.AcmeDnsServerError as exc:  # noqa: F841
                # raises a `FormInvalid`
                formStash.fatal_form(
                    message="Error communicating with the acme-dns server."
                )

            except (
                errors.AcmeError,
                errors.InvalidRequest,
            ) as exc:
                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}

                return HTTPSeeOther(
                    "%s/renewal-configurations/all?result=error&error=%s&operation=new+freeform"
                    % (
                        self.request.api_context.application_settings["admin_prefix"],
                        exc.as_querystring,
                    )
                )

            except errors.UnknownAcmeProfile_Local as exc:  # noqa: F841
                # raises a `FormInvalid`
                # exc.args: var(matches field), submitted, allowed
                formStash.fatal_field(
                    field=exc.args[0],
                    message="Unknown acme_profile (%s); not one of: %s."
                    % (exc.args[1], exc.args[2]),
                )

            except Exception as exc:  # noqa: F841
                raise
                # note: allow this on testing
                # raise
                if self.request.registry.settings["exception_redirect"]:
                    return HTTPSeeOther(
                        "%s/renewal-configurations/all?result=error&operation=new-freeform"
                        % self.request.api_context.application_settings["admin_prefix"]
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
            "instructions": "curl --form 'action=active' {ADMIN_PREFIX}/renewal-configuration/1/mark.json",
            "example": "curl "
            "--form 'action=active' "
            "{ADMIN_PREFIX}/renewal-configuration/1/mark.json",
            "form_fields": {
                "action": "the intended action",
            },
            "valid_options": {
                "action": ["active", "inactive"],
            },
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
                    "operation": "mark",
                    "action": action,
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
            "endpoint": "/renewal-configuration/new.json",
            "section": "renewal-configuration",
            "about": """AcmeOrder: New Freeform""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/renewal-configuration/new.json",
            "form_fields": {
                # ALL certs
                "domain_names_http01": "required; a comma separated list of domain names to process",
                "domain_names_dns01": "required; a comma separated list of domain names to process",
                "note": "A string to associate with the RenewalConfiguration.",
                # primary cert
                "account_key_option": "How is the AcmeAccount specified?",
                "account_key_global_default": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option==account_key_global_default`",
                "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                "private_key_cycle__primary": "how should the PrivateKey be cycled on renewals?",
                "private_key_technology__primary": "what kind of keys to use?",
                "acme_profile_primary": """The name of an ACME Profile on the ACME Server.
Leave this blank for no profile.
If you want to defer to the AcmeAccount, use the special name `@`.""",
                # backup cert
                "account_key_option_backup": "How is the AcmeAccount specified? [Backup Cert]",
                "account_key_global_backup": "pem_md5 of the Global Backup account key. Must/Only submit if `account_key_option_backup==account_key_global_backup` [Backup Cert]",
                "account_key_existing_backup": "pem_md5 of any key. Must/Only submit if `account_key_option_backup==account_key_existing_backup` [Backup Cert]",
                "private_key_cycle__backup": "how should the PrivateKey be cycled on renewals?",
                "private_key_technology__backup": "what kind of keys to use?",
                "acme_profile__backup": """The name of an ACME Profile on the ACME Server [Backup Cert].
Leave this blank for no profile.
If you want to defer to the AcmeAccount, use the special name `@`.""",
            },
            "form_fields_related": [
                ["domain_names_http01", "domain_names_dns01"],
                [
                    "account_key_option",
                    "account_key_global_default",
                    "account_key_existing",
                    "acme_profile_primary",
                ],
                [
                    "account_key_option_backup",
                    "account_key_global_backup",
                    "account_key_existing_backup",
                    "acme_profile_backup",
                ],
            ],
            "valid_options": {
                "EnrollmentPolicys": "{RENDER_ON_REQUEST}",
                "account_key_option": Form_RenewalConfig_new.fields[
                    "account_key_option"
                ].list,
                "account_key_option_backup": Form_RenewalConfig_new.fields[
                    "account_key_option_backup"
                ].list,
                "private_key_cycle__primary": Form_RenewalConfig_new.fields[
                    "private_key_cycle__primary"
                ].list,
                "private_key_technology__primary": Form_RenewalConfig_new.fields[
                    "private_key_technology__primary"
                ].list,
                "private_key_cycle__backup": Form_RenewalConfig_new.fields[
                    "private_key_cycle__backup"
                ].list,
                "private_key_technology__backup": Form_RenewalConfig_new.fields[
                    "private_key_technology__backup"
                ].list,
            },
            "requirements": [
                "Submit at least one of `domain_names_http01` or `domain_names_dns01`",
            ],
            "examples": [
                """curl """
                """--form 'account_key_option=account_key_existing' """
                """--form 'account_key_existing=ff00ff00ff00ff00' """
                """--form 'private_key_cycle=account_default' """
                """{ADMIN_PREFIX}/renewal-configuration/new.json""",
            ],
        }
    )
    def new(self):
        self.request.api_context._load_EnrollmentPolicy_global()
        self.request.api_context._load_AcmeDnsServer_GlobalDefault()
        self.request.api_context._load_AcmeServers()
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/renewal-configuration/new.json")
        return render_to_response(
            "/admin/renewal_configuration-new.mako",
            {
                "EnrollmentPolicy_global": self.request.api_context.dbEnrollmentPolicy_global,
                "AcmeDnsServer_GlobalDefault": self.request.api_context.dbAcmeDnsServer_GlobalDefault,
                "AcmeServers": self.request.api_context.dbAcmeServers,
                "domain_names_http01": self.request.params.get(
                    "domain_names_http01", ""
                ),
                "domain_names_dns01": self.request.params.get("domain_names_dns01", ""),
            },
            self.request,
        )

    def _new__submit(self):
        """ """
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
                dbAcmeDnsServer_GlobalDefault=self.request.api_context.dbAcmeDnsServer_GlobalDefault,
            )

            acmeAccountSelection = form_utils.parse_AcmeAccountSelection(
                self.request,
                formStash,
                require_contact=False,
                support_upload=False,
            )
            assert acmeAccountSelection.AcmeAccount is not None

            acmeAccountSelection_backup = form_utils.parse_AcmeAccountSelection_backup(
                self.request,
                formStash,
            )

            # shared
            note = formStash.results["note"]

            # PRIMARY cert
            private_key_technology__primary = formStash.results[
                "private_key_technology__primary"
            ]
            private_key_technology_id__primary = model_utils.KeyTechnology.from_string(
                private_key_technology__primary
            )
            private_key_cycle__primary = formStash.results["private_key_cycle__primary"]
            private_key_cycle_id__primary = model_utils.PrivateKeyCycle.from_string(
                private_key_cycle__primary
            )
            acme_profile__primary = formStash.results["acme_profile__primary"]

            # BACKUP cert
            private_key_technology__backup = formStash.results[
                "private_key_technology__backup"
            ]
            private_key_technology_id__backup = None
            if private_key_technology__backup:
                private_key_technology_id__backup = (
                    model_utils.KeyTechnology.from_string(
                        private_key_technology__backup
                    )
                )
            private_key_cycle__backup = formStash.results["private_key_cycle__backup"]
            private_key_cycle_id__backup = None
            if private_key_cycle__backup:
                private_key_cycle_id__backup = model_utils.PrivateKeyCycle.from_string(
                    private_key_cycle__backup
                )
            acme_profile__backup = formStash.results["acme_profile__backup"]

            if not acmeAccountSelection_backup.AcmeAccount:
                private_key_cycle_id__backup = None
                private_key_technology_id__backup = None
                acme_profile__backup = None

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
                                    self.request.api_context.application_settings[
                                        "acme_dns_support"
                                    ]
                                    == "experimental"
                                ):
                                    raise
                                # in "basic" mode we can just associate these to the global option
                                if (
                                    not self.request.api_context.dbAcmeDnsServer_GlobalDefault
                                ):
                                    formStash.fatal_field(
                                        "domain_names_dns01",
                                        "No global acme-dns server configured.",
                                    )
                                if TYPE_CHECKING:
                                    assert (
                                        self.request.api_context.dbAcmeDnsServer_GlobalDefault
                                        is not None
                                    )
                                # exc.args[0] will be the listing of domains
                                (domainObjects, adnsAccountObjects) = (
                                    lib_db.associate.ensure_domain_names_to_acmeDnsServer(
                                        self.request.api_context,
                                        exc.args[0],
                                        self.request.api_context.dbAcmeDnsServer_GlobalDefault,
                                        discovery_type="via renewal_configuration.new",
                                    )
                                )
                        domains_all.extend(domains_)

                # create the configuration
                # this will create:
                # * model_utils.RenewableConfig
                # * model_utils.UniquelyChallengedFQDNSet2Domain
                # * model_utils.UniqueFQDNSet
                is_duplicate_renewal = None
                try:
                    dbRenewalConfiguration = lib_db.create.create__RenewalConfiguration(
                        self.request.api_context,
                        domains_challenged=domains_challenged,
                        # PRIMARY cert
                        dbAcmeAccount__primary=acmeAccountSelection.AcmeAccount,
                        private_key_technology_id__primary=private_key_technology_id__primary,
                        private_key_cycle_id__primary=private_key_cycle_id__primary,
                        acme_profile__primary=acme_profile__primary,
                        # BACKUP cert
                        dbAcmeAccount__backup=acmeAccountSelection_backup.AcmeAccount,
                        private_key_technology_id__backup=private_key_technology_id__backup,
                        private_key_cycle_id__backup=private_key_cycle_id__backup,
                        acme_profile__backup=acme_profile__backup,
                        # misc
                        note=note,
                    )
                except errors.DuplicateRenewalConfiguration as exc:
                    is_duplicate_renewal = True
                    # we could raise exc to abort, but this is likely preferred
                    dbRenewalConfiguration = exc.args[0]

                if self.request.wants_json:
                    return {
                        "result": "success",
                        "RenewalConfiguration": dbRenewalConfiguration.as_json,
                        "is_duplicate_renewal": is_duplicate_renewal,
                    }

                return HTTPSeeOther(
                    "%s/renewal-configuration/%s%s"
                    % (
                        self.request.api_context.application_settings["admin_prefix"],
                        dbRenewalConfiguration.id,
                        "?is_duplicate_renewal=true" if is_duplicate_renewal else "",
                    )
                )

            except (
                errors.AcmeDomainsBlocklisted,
                errors.AcmeDomainsRequireConfigurationAcmeDNS,
            ) as exc:
                formStash.fatal_form(message=str(exc))

            except (errors.DuplicateRenewalConfiguration,) as exc:
                message = (
                    "This appears to be a duplicate of RenewalConfiguration: `%s`."
                    % exc.args[0].id
                )
                formStash.fatal_form(message=message)

            except errors.AcmeDuplicateChallenges as exc:
                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}
                formStash.fatal_form(message=str(exc))

            except errors.AcmeDnsServerError as exc:  # noqa: F841
                # raises a `FormInvalid`
                formStash.fatal_form(
                    message="Error communicating with the acme-dns server."
                )

            except (
                errors.AcmeError,
                errors.InvalidRequest,
            ) as exc:
                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}

                return HTTPSeeOther(
                    "%s/renewal-configurations/all?result=error&error=%s&operation=new+freeform"
                    % (
                        self.request.api_context.application_settings["admin_prefix"],
                        exc.as_querystring,
                    )
                )

            except errors.UnknownAcmeProfile_Local as exc:  # noqa: F841
                # raises a `FormInvalid`
                # exc.args: var(matches field), submitted, allowed
                formStash.fatal_field(
                    field=exc.args[0],
                    message="Unknown acme_profile (%s); not one of: %s."
                    % (exc.args[1], exc.args[2]),
                )

            except Exception as exc:  # noqa: F841
                raise
                # note: allow this on testing
                # raise
                if self.request.registry.settings["exception_redirect"]:
                    return HTTPSeeOther(
                        "%s/renewal-configurations/all?result=error&operation=new-freeform"
                        % self.request.api_context.application_settings["admin_prefix"]
                    )
                raise

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)
