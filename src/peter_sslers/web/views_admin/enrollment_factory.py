# stdlib
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

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_EnrollmentFactory_edit_new
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model import utils as model_utils
from ...model.objects import EnrollmentFactory

if TYPE_CHECKING:
    from pyramid_formencode_classic import FormStash
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeDnsServer

# ==============================================================================


def validate_domains_template(template: str) -> Tuple[Optional[str], Optional[str]]:
    """
    validates and normalizes the template
    return value is a tuple:
        Optional[NormalizedTemplate], Optional[ErrorMessage]
    Success will return:
        [String, None]
    Failure will yield:
        [None, String]
    """
    if not template:
        return None, "Nothing submitted"
    # remove any spaces
    template = template.replace(" ", "")
    ds = template.split(",")
    ds = [i.strip() for i in ds]
    for i in ds:
        if "{DOMAIN}" not in i:
            return None, "Missing {DOMAIN} marker"
    ds2 = [i.replace("{DOMAIN}", "example.com") for i in ds]
    try:
        cert_utils.validate_domains(ds2)
    except Exception:
        return None, "Invalid Domain(s) Detected"
    normalized = ", ".join(ds)
    return normalized, None


def validate_formstash_domains(
    formStash: "FormStash",
    dbAcmeDnsServer_GlobalDefault: Optional["AcmeDnsServer"] = None,
) -> Tuple[str, str]:
    """will raise an exception if fails"""

    domain_template_http01 = formStash.results["domain_template_http01"]
    if domain_template_http01:
        domain_template_http01, _err = validate_domains_template(domain_template_http01)
        if not domain_template_http01:
            formStash.fatal_field(field="domain_template_http01", message=_err)
    domain_template_dns01 = formStash.results["domain_template_dns01"]
    if domain_template_dns01:
        domain_template_dns01, _err = validate_domains_template(domain_template_dns01)
        if not domain_template_dns01:
            formStash.fatal_field(field="domain_template_dns01", message=_err)
    if not any((domain_template_http01, domain_template_dns01)):
        _error = "Domains HTTP-01 or DNS-01 MUST be specified"
        formStash.fatal_field(field="domain_template_http01", message=_error)
        formStash.fatal_field(field="domain_template_dns01", message=_error)

    # now we test these...
    domains_challenged = model_utils.DomainsChallenged()
    domain_names_all = []
    if domain_template_dns01:
        domain_names = domain_template_dns01.replace("{DOMAIN}", "example.com")
        domain_names = cert_utils.utils.domains_from_string(domain_names)
        if domain_names:
            domain_names_all.extend(domain_names)
            domains_challenged["dns-01"] = domain_names
    if domain_template_http01:
        domain_names = domain_template_http01.replace("{DOMAIN}", "example.com")
        domain_names = cert_utils.utils.domains_from_string(domain_names)
        if domain_names:
            domain_names_all.extend(domain_names)
            domains_challenged["http-01"] = domain_names
    # 2: ensure there are domains
    if not domain_names_all:
        formStash.fatal_form(message="templates did not expand to domains")
    # 3: ensure there is no overlap
    domain_names_all_set = set(domain_names_all)
    if len(domain_names_all) != len(domain_names_all_set):
        formStash.fatal_form(
            message="a domain name can only be associated to one challenge type",
        )

    for chall, ds in domains_challenged.items():
        if chall == "dns-01":
            continue
        if ds:
            for d in ds:
                if d[0] == "*":
                    formStash.fatal_form(
                        message="wildcards (*) MUST use `dns-01`.",
                    )
    if domains_challenged["dns-01"]:
        if not dbAcmeDnsServer_GlobalDefault:
            formStash.fatal_field(
                field="domain_template_dns01",
                message="The global acme-dns server is not configured.",
            )

    return domain_template_http01, domain_template_dns01


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
            print(items_paged)
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
                "name": "name",
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
            },
        }
    )
    def edit(self):
        self.request.api_context._load_AcmeDnsServer_GlobalDefault()
        dbEnrollmentFactory = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._edit__submit()
        return self._edit__print()

    def _edit__print(self):
        assert self.dbEnrollmentFactory is not None
        # quick setup, we need a bunch of options for dropdowns...
        self.dbAcmeAccounts_all = lib_db.get.get__AcmeAccount__paginated(
            self.request.api_context,
            render_in_selects=True,
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
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_EnrollmentFactory_edit_new, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            # these require some validation
            # nest outside of the try to minimize Exception catching
            (domain_template_http01, domain_template_dns01) = (
                validate_formstash_domains(
                    formStash,
                    dbAcmeDnsServer_GlobalDefault=self.request.api_context.dbAcmeDnsServer_GlobalDefault,
                )
            )

            try:

                result = lib_db.update.update_EnrollmentFactory(
                    self.request.api_context,
                    self.dbEnrollmentFactory,
                    name=formStash.results["name"],
                    # primary
                    acme_account_id__primary=formStash.results[
                        "acme_account_id__primary"
                    ],
                    private_key_cycle__primary=formStash.results[
                        "private_key_cycle__primary"
                    ],
                    private_key_technology__primary=formStash.results[
                        "private_key_technology__primary"
                    ],
                    acme_profile__primary=formStash.results["acme_profile__primary"],
                    # backup
                    acme_account_id__backup=formStash.results[
                        "acme_account_id__backup"
                    ],
                    private_key_cycle__backup=formStash.results[
                        "private_key_cycle__backup"
                    ],
                    private_key_technology__backup=formStash.results[
                        "private_key_technology__backup"
                    ],
                    acme_profile__backup=formStash.results["acme_profile__backup"],
                    # misc
                    note=formStash.results["note"],
                    domain_template_http01=domain_template_http01,
                    domain_template_dns01=domain_template_dns01,
                )
            except Exception as exc:
                formStash.fatal_form(message=str(exc))

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

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._edit__print)


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
            },
        }
    )
    def new(self):
        self.request.api_context._load_AcmeDnsServer_GlobalDefault()
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
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_EnrollmentFactory_edit_new,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                dbAcmeAccount_primary: Optional["AcmeAccount"] = None
                dbAcmeAccount_backup: Optional["AcmeAccount"] = None

                # shared
                name = formStash.results["name"]
                note = formStash.results["note"]
                private_key_cycle_id__backup: Optional[int]
                private_key_technology_id__backup: Optional[int]
                acme_profile__backup: Optional[str]

                # these require some validation
                existingEnrollmentFactory = lib_db.get.get__EnrollmentFactory__by_name(
                    self.request.api_context, name
                )
                if existingEnrollmentFactory:
                    formStash.fatal_field(
                        field="name",
                        message="An EnrollmentFactory already exists with this name.",
                    )

                (domain_template_http01, domain_template_dns01) = (
                    validate_formstash_domains(
                        formStash,
                        dbAcmeDnsServer_GlobalDefault=self.request.api_context.dbAcmeDnsServer_GlobalDefault,
                    )
                )

                # PRIMARY config
                acme_account_id__primary = formStash.results["acme_account_id__primary"]
                dbAcmeAccount_primary = lib_db.get.get__AcmeAccount__by_id(
                    self.request.api_context, acme_account_id__primary
                )
                if not dbAcmeAccount_primary:
                    formStash.fatal_field(
                        field="acme_account_id__primary", message="invalid"
                    )
                if TYPE_CHECKING:
                    assert dbAcmeAccount_primary

                private_key_cycle__primary = formStash.results[
                    "private_key_cycle__primary"
                ]
                private_key_cycle_id__primary = model_utils.PrivateKeyCycle.from_string(
                    private_key_cycle__primary
                )
                private_key_technology__primary = formStash.results[
                    "private_key_technology__primary"
                ]
                private_key_technology_id__primary = (
                    model_utils.KeyTechnology.from_string(
                        private_key_technology__primary
                    )
                )
                acme_profile__primary = (
                    formStash.results["acme_profile__primary"] or None
                )

                # BACKUP config
                acme_account_id__backup = formStash.results["acme_account_id__backup"]
                if acme_account_id__backup:
                    dbAcmeAccount_backup = lib_db.get.get__AcmeAccount__by_id(
                        self.request.api_context, acme_account_id__backup
                    )
                    if not dbAcmeAccount_backup:
                        formStash.fatal_field(
                            field="acme_account_id__backup", message="invalid"
                        )
                private_key_cycle__backup = formStash.results[
                    "private_key_cycle__backup"
                ]
                private_key_cycle_id__backup = model_utils.PrivateKeyCycle.from_string(
                    private_key_cycle__backup
                )
                private_key_technology__backup = formStash.results[
                    "private_key_technology__backup"
                ]
                private_key_technology_id__backup = (
                    model_utils.KeyTechnology.from_string(
                        private_key_technology__backup
                    )
                )
                acme_profile__backup = formStash.results["acme_profile__backup"] or None

                if dbAcmeAccount_backup:
                    if (
                        dbAcmeAccount_primary.acme_server_id
                        == dbAcmeAccount_backup.acme_server_id
                    ):
                        formStash.fatal_form(
                            message="Primary and Backup must be on different ACME servers"
                        )
                else:
                    private_key_cycle_id__backup = None
                    private_key_technology_id__backup = None
                    acme_profile__backup = None

                # make it

                dbEnrollmentFactory = lib_db.create.create__EnrollmentFactory(
                    self.request.api_context,
                    name=name,
                    # Primary cert
                    dbAcmeAccount_primary=dbAcmeAccount_primary,
                    private_key_technology_id__primary=private_key_technology_id__primary,
                    private_key_cycle_id__primary=private_key_cycle_id__primary,
                    acme_profile__primary=acme_profile__primary,
                    # Backup cert
                    dbAcmeAccount_backup=dbAcmeAccount_backup,
                    private_key_technology_id__backup=private_key_technology_id__backup,
                    private_key_cycle_id__backup=private_key_cycle_id__backup,
                    acme_profile__backup=acme_profile__backup,
                    # misc
                    note=note,
                    domain_template_http01=domain_template_http01,
                    domain_template_dns01=domain_template_dns01,
                )
            except formhandling.FormInvalid as exc:  # noqa: F841
                raise

            except Exception as exc:
                formStash.fatal_form(message="%s" % exc)

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
        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)
