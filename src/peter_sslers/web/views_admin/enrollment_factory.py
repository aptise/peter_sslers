# stdlib
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# from typing import Dict

# pypi
import cert_utils
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
from ..lib.forms import Form_EnrollmentFactory_edit_new
from ..lib.forms import Form_EnrollmentFactory_query
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...lib.utils import displayable_exception
from ...lib.utils import validate_domains_template
from ...lib.utils import validate_label_template
from ...model import utils as model_utils
from ...model.objects import EnrollmentFactory

if TYPE_CHECKING:
    from pyramid.request import Request
    from pyramid_formencode_classic import FormStash

    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeDnsServer
    from ...model.objects import RenewalConfiguration
    from ...model.objects import X509Certificate

# ==============================================================================


def validate_formstash_domain_templates(
    formStash: "FormStash",
    dbAcmeDnsServer_GlobalDefault: Optional["AcmeDnsServer"] = None,
) -> Tuple[str, str]:
    """will raise an exception if fails"""

    domain_template_http01 = formStash.results["domain_template_http01"]
    if domain_template_http01:
        domain_template_http01, _err = validate_domains_template(
            domain_template_http01, model_utils.AcmeChallengeType_Enum.HTTP_01
        )
        if not domain_template_http01:
            formStash.fatal_field(field="domain_template_http01", error_field=_err)
    domain_template_dns01 = formStash.results["domain_template_dns01"]
    if domain_template_dns01:
        domain_template_dns01, _err = validate_domains_template(
            domain_template_dns01, model_utils.AcmeChallengeType_Enum.DNS_01
        )
        if not domain_template_dns01:
            formStash.fatal_field(field="domain_template_dns01", error_field=_err)
    if not any((domain_template_http01, domain_template_dns01)):
        _error = "Domains HTTP-01 or DNS-01 MUST be specified"
        formStash.fatal_field(field="domain_template_http01", error_field=_error)
        formStash.fatal_field(field="domain_template_dns01", error_field=_error)

    # now we test these...
    domains_challenged = model_utils.DomainsChallenged()
    domain_names_all = []
    if domain_template_dns01:
        templated = domain_template_dns01.replace("{DOMAIN}", "example.com").replace(
            "{NIAMOD}", "com.example"
        )
        # domains will also be lowercase+strip
        #
        # IMPORTANT RFC 8738
        #       https://www.rfc-editor.org/rfc/rfc8738#section-7
        #       The existing "dns-01" challenge MUST NOT be used to validate IP identifiers.
        #
        domain_names = cert_utils.utils.domains_from_string(
            templated,
            allow_hostname=True,
            allow_ipv4=False,
            allow_ipv6=False,  # DNS-01 not allowed for IPs via RFC
        )
        if domain_names:
            domain_names_all.extend(domain_names)
            domains_challenged["dns-01"] = domain_names
    if domain_template_http01:
        templated = domain_template_http01.replace("{DOMAIN}", "example.com").replace(
            "{NIAMOD}", "com.example"
        )
        # domains will also be lowercase+strip
        domain_names = cert_utils.utils.domains_from_string(
            templated,
            allow_hostname=True,
            allow_ipv4=True,
            allow_ipv6=True,
            ipv6_require_compressed=True,
        )
        if domain_names:
            domain_names_all.extend(domain_names)
            domains_challenged["http-01"] = domain_names
    # 2: ensure there are domains
    if not domain_names_all:
        formStash.fatal_form(error_main="templates did not expand to domains")
    # 3: ensure there is no overlap
    domain_names_all_set = set(domain_names_all)
    if len(domain_names_all) != len(domain_names_all_set):
        formStash.fatal_form(
            error_main="a domain name can only be associated to one challenge type",
        )

    for chall, ds in domains_challenged.items():
        if chall == "dns-01":
            continue
        if ds:
            for d in ds:
                if d[0] == "*":
                    formStash.fatal_form(
                        error_main="wildcards (*) MUST use `dns-01`.",
                    )
    if domains_challenged["dns-01"]:
        if not dbAcmeDnsServer_GlobalDefault:
            formStash.fatal_field(
                field="domain_template_dns01",
                error_field="The global acme-dns server is not configured.",
            )

    return domain_template_http01, domain_template_dns01


def submit__new(
    request: "Request",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> EnrollmentFactory:
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    (result, formStash) = formhandling.form_validate(
        request,
        schema=Form_EnrollmentFactory_edit_new,
        validate_get=False,
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    try:
        dbAcmeAccount__primary: Optional["AcmeAccount"] = None
        dbAcmeAccount__backup: Optional["AcmeAccount"] = None

        # shared
        name = formStash.results["name"]
        name = utils.normalize_unique_text(name)
        if not utils.validate_label(name):
            formStash.fatal_field(
                field="name", error_field="the `name` is not compliant"
            )

        note = formStash.results["note"]
        private_key_cycle_id__backup: Optional[int]
        private_key_technology_id__backup: Optional[int]
        acme_profile__backup: Optional[str]
        is_export_filesystem = formStash.results["is_export_filesystem"]
        is_export_filesystem_id = model_utils.OptionsOnOff.from_string(
            is_export_filesystem
        )

        # these require some validation
        existingEnrollmentFactory = lib_db.get.get__EnrollmentFactory__by_name(
            request.api_context, name
        )
        if existingEnrollmentFactory:
            formStash.fatal_field(
                field="name",
                error_field="An EnrollmentFactory already exists with this name.",
            )

        (domain_template_http01, domain_template_dns01) = (
            validate_formstash_domain_templates(
                formStash,
                dbAcmeDnsServer_GlobalDefault=request.api_context.dbAcmeDnsServer_GlobalDefault,
            )
        )

        # PRIMARY config
        acme_account_id__primary = formStash.results["acme_account_id__primary"]
        dbAcmeAccount__primary = lib_db.get.get__AcmeAccount__by_id(
            request.api_context, acme_account_id__primary
        )
        if not dbAcmeAccount__primary:
            formStash.fatal_field(
                field="acme_account_id__primary", error_field="invalid"
            )
        if TYPE_CHECKING:
            assert dbAcmeAccount__primary

        private_key_cycle__primary = formStash.results["private_key_cycle__primary"]
        private_key_cycle_id__primary = model_utils.PrivateKeyCycle.from_string(
            private_key_cycle__primary
        )
        private_key_technology__primary = formStash.results[
            "private_key_technology__primary"
        ]
        private_key_technology_id__primary = model_utils.KeyTechnology.from_string(
            private_key_technology__primary
        )
        acme_profile__primary = formStash.results["acme_profile__primary"] or None

        # BACKUP config
        acme_account_id__backup = formStash.results["acme_account_id__backup"]
        if acme_account_id__backup:
            dbAcmeAccount__backup = lib_db.get.get__AcmeAccount__by_id(
                request.api_context, acme_account_id__backup
            )
            if not dbAcmeAccount__backup:
                formStash.fatal_field(
                    field="acme_account_id__backup",
                    error_field="invalid",
                )
        private_key_cycle__backup = formStash.results["private_key_cycle__backup"]
        if private_key_cycle__backup:
            private_key_cycle_id__backup = model_utils.PrivateKeyCycle.from_string(
                private_key_cycle__backup
            )
        private_key_technology__backup = formStash.results[
            "private_key_technology__backup"
        ]
        if private_key_cycle__backup:
            private_key_technology_id__backup = model_utils.KeyTechnology.from_string(
                private_key_technology__backup
            )

        acme_profile__backup = formStash.results["acme_profile__backup"] or None
        if dbAcmeAccount__backup:
            if (
                dbAcmeAccount__primary.acme_server_id
                == dbAcmeAccount__backup.acme_server_id
            ):
                formStash.fatal_form(
                    error_main="Primary and Backup must be on different ACME servers"
                )
        else:
            private_key_cycle_id__backup = None
            private_key_technology_id__backup = None
            acme_profile__backup = None

        label_template = formStash.results["label_template"]
        if label_template:
            _valid, _err = validate_label_template(label_template)
            if not _valid:
                formStash.fatal_field(field="label_template", error_field=_err)

        # make it

        dbEnrollmentFactory = lib_db.create.create__EnrollmentFactory(
            request.api_context,
            name=name,
            # Primary cert
            dbAcmeAccount__primary=dbAcmeAccount__primary,
            private_key_technology_id__primary=private_key_technology_id__primary,
            private_key_cycle_id__primary=private_key_cycle_id__primary,
            acme_profile__primary=acme_profile__primary,
            # Backup cert
            dbAcmeAccount__backup=dbAcmeAccount__backup,
            private_key_technology_id__backup=private_key_technology_id__backup,
            private_key_cycle_id__backup=private_key_cycle_id__backup,
            acme_profile__backup=acme_profile__backup,
            # misc
            note=note,
            domain_template_http01=domain_template_http01,
            domain_template_dns01=domain_template_dns01,
            label_template=label_template,
            is_export_filesystem_id=is_export_filesystem_id,
        )

        request.api_context.pyramid_transaction_commit()
        return dbEnrollmentFactory

    except formhandling.FormInvalid:
        raise

    except Exception as exc:
        formStash.fatal_form(error_main=displayable_exception(exc))


def submit__edit(
    request: "Request",
    dbEnrollmentFactory: EnrollmentFactory,
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> bool:
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    (result, formStash) = formhandling.form_validate(
        request,
        schema=Form_EnrollmentFactory_edit_new,
        validate_get=False,
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    # these require some validation
    # nest outside of the try to minimize Exception catching
    (domain_template_http01, domain_template_dns01) = (
        validate_formstash_domain_templates(
            formStash,
            dbAcmeDnsServer_GlobalDefault=request.api_context.dbAcmeDnsServer_GlobalDefault,
        )
    )
    label_template = formStash.results["label_template"]
    if label_template:
        _valid, _err = validate_label_template(label_template)
        if not _valid:
            formStash.fatal_field(field="label_template", error_field=_err)

    try:

        is_export_filesystem = formStash.results["is_export_filesystem"]
        is_export_filesystem_id = model_utils.OptionsOnOff.from_string(
            is_export_filesystem
        )

        result = lib_db.update.update_EnrollmentFactory(
            request.api_context,
            dbEnrollmentFactory,
            name=formStash.results["name"],
            # primary
            acme_account_id__primary=formStash.results["acme_account_id__primary"],
            private_key_cycle__primary=formStash.results["private_key_cycle__primary"],
            private_key_technology__primary=formStash.results[
                "private_key_technology__primary"
            ],
            acme_profile__primary=formStash.results["acme_profile__primary"],
            # backup
            acme_account_id__backup=formStash.results["acme_account_id__backup"],
            private_key_cycle__backup=formStash.results["private_key_cycle__backup"],
            private_key_technology__backup=formStash.results[
                "private_key_technology__backup"
            ],
            acme_profile__backup=formStash.results["acme_profile__backup"],
            is_export_filesystem_id=is_export_filesystem_id,
            # misc
            note=formStash.results["note"],
            label_template=label_template,
            domain_template_http01=domain_template_http01,
            domain_template_dns01=domain_template_dns01,
        )

        return result
    except Exception as exc:
        formStash.fatal_form(error_main=displayable_exception(exc))


def submit__query(
    request: "Request",
    dbEnrollmentFactory: EnrollmentFactory,
) -> Tuple["FormStash", Optional["RenewalConfiguration"], List["X509Certificate"]]:

    (result, formStash) = formhandling.form_validate(
        request,
        schema=Form_EnrollmentFactory_query,
        validate_get=False,
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    # note: step 1 - analyze the "submitted" domain
    # this ensures only one domain
    # we'll pretend it's http-01, though that is irreleveant
    domains_challenged = form_utils.form_single_domain_challenge_typed(
        request, formStash, challenge_type="http-01"
    )
    # this may raise: [errors.AcmeDomainsBlocklisted, errors.AcmeDomainsInvalid]
    for challenge_, domains_ in domains_challenged.items():
        if domains_:
            try:
                lib_db.validate.validate_domain_names(request.api_context, domains_)
            except errors.AcmeDomainsBlocklisted as exc:  # noqa: F841
                formStash.fatal_field(
                    field="domain_name",
                    error_field="This domain_name has been blocklisted",
                )
            except errors.AcmeDomainsInvalid as exc:  # noqa: F841
                formStash.fatal_field(
                    field="domain_name",
                    error_field="This domain_name is invalid",
                )

    domain_name = domains_challenged["http-01"][0]

    # does the domain exist?
    # we should check to see if it does and has certs
    dbDomain = lib_db.get.get__Domain__by_name(
        request.api_context,
        domain_name,
    )
    if not dbDomain:
        return (formStash, None, [])

    dbUniqueFQDNSet = lib_db.get.get__UniqueFQDNSet__by_DomainIds(
        request.api_context,
        [
            dbDomain.id,
        ],
    )
    if not dbUniqueFQDNSet:
        return (formStash, None, [])

    dbRenewalConfiguration = (
        lib_db.get.get__RenewalConfiguration__by_EnrollmentFactoryId_UniqueFqdnSetId(
            request.api_context,
            dbEnrollmentFactory.id,
            dbUniqueFQDNSet.id,
        )
    )
    dbX509Certificates = []
    if dbRenewalConfiguration:
        dbX509Certificates = (
            lib_db.get.get__X509Certificate__by_RenewalConfigurationId__paginated(
                request.api_context,
                dbRenewalConfiguration.id,
                limit=5,
                offset=0,
            )
        )
    return formStash, dbRenewalConfiguration, dbX509Certificates


class View_List(Handler):

    @view_config(
        route_name="admin:enrollment_factorys",
        renderer="/admin/enrollment_factorys.mako",
    )
    @view_config(
        route_name="admin:enrollment_factorys-paginated",
        renderer="/admin/enrollment_factorys.mako",
    )
    @view_config(
        route_name="admin:enrollment_factorys-paginated|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:enrollment_factorys|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/enrollment-factorys.json",
            "section": "enrollment-factorys",
            "about": """list EnrollmentFactory(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/enrollment-factorys.json",
        }
    )
    def list(self):
        url_template = "%s/enrollment-factorys" % (
            self.request.api_context.application_settings["admin_prefix"],
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        items_count = lib_db.get.get__EnrollmentFactory__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__EnrollmentFactory__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            # admin_url = self.request.admin_url
            return {
                "EnrollmentFactorys": [i.as_json for i in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "EnrollmentFactorys_count": items_count,
            "EnrollmentFactorys": items_paged,
            "pager": pager,
        }


# ------------------------------------------------------------------------------


class View_Focus(Handler):
    dbEnrollmentFactory: Optional[EnrollmentFactory] = None

    def _focus(self) -> EnrollmentFactory:
        if self.dbEnrollmentFactory is None:
            _identifier = self.request.matchdict["id"]
            dbEnrollmentFactory = lib_db.get.get__EnrollmentFactory__by_id(
                self.request.api_context,
                _identifier,
            )
            if not dbEnrollmentFactory:
                raise HTTPNotFound("the EnrollmentFactory was not found")
            self.dbEnrollmentFactory = dbEnrollmentFactory
            self._focus_url = "%s/enrollment-factory/%s" % (
                self.request.admin_url,
                self.dbEnrollmentFactory.id,
            )
        return self.dbEnrollmentFactory

    # ---------------

    @view_config(
        route_name="admin:enrollment_factory:focus",
        renderer="/admin/enrollment_factory-focus.mako",
    )
    @view_config(route_name="admin:enrollment_factory:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/enrollment-factory/{ID}.json",
            "section": "enrollment-factory",
            "about": """EnrollmentFactory focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/enrollment-factory/1.json",
        }
    )
    def focus(self):
        dbEnrollmentFactory = self._focus()
        if self.request.wants_json:
            return {
                "EnrollmentFactory": dbEnrollmentFactory.as_json,
            }
        return {
            "project": "peter_sslers",
            "EnrollmentFactory": dbEnrollmentFactory,
        }

    @view_config(
        route_name="admin:enrollment_factory:focus:edit",
        renderer="/admin/enrollment_factory-focus-edit.mako",
    )
    @view_config(route_name="admin:enrollment_factory:focus:edit|json", renderer="json")
    @docify(
        {
            "endpoint": "/enrollment-factory/{ID}/edit.json",
            "section": "enrollment-factory",
            "about": """EnrollmentFactory focus edit""",
            "POST": None,
            "GET": True,
            "instructions": "curl {ADMIN_PREFIX}/enrollment-factory/1/edit.json",
            "examples": [],
            "form_fields": {
                "acme_account_id__backup": "which provider",
                "acme_account_id__primary": "which provider",
                "acme_profile__backup": "server profile",
                "acme_profile__primary": "server profile",
                "private_key_technology__backup": "what is the key technology preference for this account?",
                "private_key_technology__primary": "what is the key technology preference for this account?",
                "private_key_cycle__backup": "what should orders default to?",
                "private_key_cycle__primary": "what should orders default to?",
                "note": "user note",
                "domain_template_http01": "template",
                "domain_template_dns01": "template",
                "name": "name. EDIT is not supported.",
                "is_export_filesystem": "export certs?",
            },
            "valid_options": {
                "AcmeAccounts": "{RENDER_ON_REQUEST::as_json_label}",
                "private_key_cycle__primary": Form_EnrollmentFactory_edit_new.fields[
                    "private_key_cycle__primary"
                ].list,
                "private_key_cycle__backup": Form_EnrollmentFactory_edit_new.fields[
                    "private_key_cycle__backup"
                ].list,
                "private_key_technology__primary": Form_EnrollmentFactory_edit_new.fields[
                    "private_key_technology__primary"
                ].list,
                "private_key_technology__backup": Form_EnrollmentFactory_edit_new.fields[
                    "private_key_technology__backup"
                ].list,
                "is_export_filesystem": Form_EnrollmentFactory_edit_new.fields[
                    "is_export_filesystem"
                ].list,
            },
        }
    )
    def edit(self):
        dbEnrollmentFactory = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._edit__submit()
        return self._edit__print()

    def _edit__print(self):
        assert self.dbEnrollmentFactory is not None
        # quick setup, we need a bunch of options for dropdowns...
        _required_ids = [
            i
            for i in [
                self.dbEnrollmentFactory.acme_account_id__primary,
                self.dbEnrollmentFactory.acme_account_id__backup,
            ]
            if i
        ]
        self.dbAcmeAccounts_all = lib_db.get.get__AcmeAccount__paginated(
            self.request.api_context,
            render_in_selects=True,
            render_in_selects_include=_required_ids,
        )
        if self.request.wants_json:
            return formatted_get_docs(self, "/enrollment-factory/{ID}/edit.json")
        return render_to_response(
            "/admin/enrollment_factory-focus-edit.mako",
            {
                "EnrollmentFactory": self.dbEnrollmentFactory,
                "AcmeAccounts": self.dbAcmeAccounts_all,
                "AcmeDnsServer_GlobalDefault": self.request.api_context.dbAcmeDnsServer_GlobalDefault,
            },
            self.request,
        )

    def _edit__submit(self):
        assert self.dbEnrollmentFactory is not None
        try:
            result = submit__edit(  # noqa: F841
                self.request,
                self.dbEnrollmentFactory,
                acknowledge_transaction_commits=True,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "EnrollmentFactory": self.dbEnrollmentFactory.as_json,
                }
            return HTTPSeeOther(
                "%s/enrollment-factory/%s?result=success&operation=edit"
                % (
                    self.request.admin_url,
                    self.dbEnrollmentFactory.id,
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": exc.formStash.errors}
            return formhandling.form_reprint(self.request, self._edit__print)

    @view_config(
        route_name="admin:enrollment_factory:focus:query",
        renderer="/admin/enrollment_factory-focus-query.mako",
    )
    @view_config(
        route_name="admin:enrollment_factory:focus:query|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/enrollment-factory/{ID}/query.json",
            "section": "enrollment-factory",
            "about": """EnrollmentFactory focus query""",
            "POST": None,
            "GET": True,
            "instructions": "curl {ADMIN_PREFIX}/enrollment-factory/1/query.json",
            "examples": [],
            "form_fields": {
                "domain_name": "string",
            },
        }
    )
    def query(self):
        dbEnrollmentFactory = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._query__submit()
        return self._query__print()

    def _query__print(self):
        assert self.dbEnrollmentFactory is not None
        if self.request.wants_json:
            return formatted_get_docs(self, "/enrollment-factory/{ID}/query.json")
        return render_to_response(
            "/admin/enrollment_factory-focus-query.mako",
            {
                "domain_name": None,
                "EnrollmentFactory": self.dbEnrollmentFactory,
            },
            self.request,
        )

    def _query__submit(self):
        assert self.dbEnrollmentFactory is not None
        try:
            (formStash, dbRenewalConfiguration, dbX509Certificates) = submit__query(
                self.request,
                self.dbEnrollmentFactory,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "domain_name": formStash.results["domain_name"],
                    "RenewalConfiguration": (
                        dbRenewalConfiguration.as_json
                        if dbRenewalConfiguration
                        else None
                    ),
                    "X509Certificates": [i.as_json for i in dbX509Certificates],
                }
            return render_to_response(
                "/admin/enrollment_factory-focus-query.mako",
                {
                    "domain_name": formStash.results["domain_name"],
                    "EnrollmentFactory": self.dbEnrollmentFactory,
                    "RenewalConfiguration": dbRenewalConfiguration,
                    "X509Certificates": dbX509Certificates,
                },
                self.request,
            )
        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": exc.formStash.errors}
            return formhandling.form_reprint(self.request, self._query__print)

    @view_config(
        route_name="admin:enrollment_factory:focus:renewal_configurations",
        renderer="/admin/enrollment_factory-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:enrollment_factory:focus:renewal_configurations-paginated",
        renderer="/admin/enrollment_factory-focus-renewal_configurations.mako",
    )
    @view_config(
        route_name="admin:enrollment_factory:focus:renewal_configurations|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:enrollment_factory:focus:renewal_configurations-paginated|json",
        renderer="json",
    )
    def related__RenewalConfigurations(self):
        dbEnrollmentFactory = self._focus()  # noqa: F841
        items_count = (
            lib_db.get.get__RenewalConfiguration__by_EnrollmentFactoryId__count(
                self.request.api_context, dbEnrollmentFactory.id
            )
        )
        url_template = "%s/renewal-configurations/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__RenewalConfiguration__by_EnrollmentFactoryId__paginated(
                self.request.api_context,
                dbEnrollmentFactory.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        if self.request.wants_json:
            _RenewalConfigurations = [k.as_json for k in items_paged]
            return {
                "RenewalConfigurations": _RenewalConfigurations,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "EnrollmentFactory": dbEnrollmentFactory,
            "RenewalConfigurations_count": items_count,
            "RenewalConfigurations": items_paged,
            "pager": pager,
        }

    @view_config(
        route_name="admin:enrollment_factory:focus:x509_certificates",
        renderer="/admin/enrollment_factory-focus-x509_certificates.mako",
    )
    @view_config(
        route_name="admin:enrollment_factory:focus:x509_certificates-paginated",
        renderer="/admin/enrollment_factory-focus-x509_certificates.mako",
    )
    @view_config(
        route_name="admin:enrollment_factory:focus:x509_certificates|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:enrollment_factory:focus:x509_certificates-paginated|json",
        renderer="json",
    )
    def related__X509Certificates(self):
        dbEnrollmentFactory = self._focus()  # noqa: F841
        items_count = lib_db.get.get__X509Certificate__by_EnrollmentFactoryId__count(
            self.request.api_context, dbEnrollmentFactory.id
        )
        url_template = "%s/x509-certificates/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__X509Certificate__by_EnrollmentFactoryId__paginated(
                self.request.api_context,
                dbEnrollmentFactory.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        if self.request.wants_json:
            _X509Certificates = [k.as_json for k in items_paged]
            return {
                "X509Certificates": _X509Certificates,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "EnrollmentFactory": dbEnrollmentFactory,
            "X509Certificates_count": items_count,
            "X509Certificates": items_paged,
            "pager": pager,
        }


class View_New(Handler):
    @view_config(route_name="admin:enrollment_factorys:new")
    @view_config(route_name="admin:enrollment_factorys:new|json", renderer="json")
    @docify(
        {
            "endpoint": "/enrollment-factorys/new.json",
            "section": "enrollment-factory",
            "about": """EnrollmentFactory: New""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/enrollment-factory/global/edit.json",
            "examples": [],
            "form_fields": {
                "name": "name",
                "note": "note",
                "label_template": "template used for RenewalConfiguration labels",
                "is_export_filesystem": "export certs?",
                "domain_template_http01": "template",
                "domain_template_dns01": "template",
                "acme_account_id__backup": "which provider",
                "acme_account_id__primary": "which provider",
                "acme_profile__backup": "server profile",
                "acme_profile__primary": "server profile",
                "private_key_technology__backup": "what is the key technology preference for this account?",
                "private_key_technology__primary": "what is the key technology preference for this account?",
                "private_key_cycle__backup": "what should orders default to?",
                "private_key_cycle__primary": "what should orders default to?",
            },
            "valid_options": {
                "AcmeAccounts": "{RENDER_ON_REQUEST::as_json_label}",
                "private_key_cycle__primary": Form_EnrollmentFactory_edit_new.fields[
                    "private_key_cycle__primary"
                ].list,
                "private_key_cycle__backup": Form_EnrollmentFactory_edit_new.fields[
                    "private_key_cycle__backup"
                ].list,
                "private_key_technology__primary": Form_EnrollmentFactory_edit_new.fields[
                    "private_key_technology__primary"
                ].list,
                "private_key_technology__backup": Form_EnrollmentFactory_edit_new.fields[
                    "private_key_technology__backup"
                ].list,
                "is_export_filesystem": Form_EnrollmentFactory_edit_new.fields[
                    "is_export_filesystem"
                ].list,
            },
        }
    )
    def new(self):
        # quick setup, we need a bunch of options for dropdowns...
        self.dbAcmeAccounts_all = lib_db.get.get__AcmeAccount__paginated(
            self.request.api_context,
            render_in_selects=True,
        )
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/enrollment-factorys/new.json")
        return render_to_response(
            "/admin/enrollment_factorys-new.mako",
            {
                "AcmeAccounts": self.dbAcmeAccounts_all,
                "AcmeDnsServer_GlobalDefault": self.request.api_context.dbAcmeDnsServer_GlobalDefault,
            },
            self.request,
        )

    def _new__submit(self):
        """ """
        try:

            dbEnrollmentFactory = submit__new(
                self.request, acknowledge_transaction_commits=True
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "EnrollmentFactory": dbEnrollmentFactory.as_json,
                }

            return HTTPSeeOther(
                "%s/enrollment-factory/%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbEnrollmentFactory.id,
                )
            )
        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": exc.formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)
