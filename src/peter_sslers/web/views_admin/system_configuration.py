# stdlib
from typing import Optional

# from typing import Dict

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_SystemConfiguration_edit
from ..lib.forms import Form_SystemConfiguration_Global_edit
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import SystemConfiguration

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:system_configurations",
        renderer="/admin/system_configurations.mako",
    )
    @view_config(
        route_name="admin:system_configurations|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/system-configurations.json",
            "section": "system-configurations",
            "about": """list SystemConfiguration(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/system-configurations.json",
        }
    )
    def list(self):
        url_template = "%s/system-configurations" % (
            self.request.api_context.application_settings["admin_prefix"],
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        items_count = lib_db.get.get__SystemConfiguration__count(
            self.request.api_context
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__SystemConfiguration__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            # admin_url = self.request.admin_url
            return {
                "SystemConfigurations": [i.as_json for i in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "SystemConfigurations_count": items_count,
            "SystemConfigurations": items_paged,
            "pager": pager,
        }


# ------------------------------------------------------------------------------


class View_Focus(Handler):
    dbSystemConfiguration: Optional[SystemConfiguration] = None

    def _focus(self) -> SystemConfiguration:
        if self.dbSystemConfiguration is None:
            _identifier = self.request.matchdict["websafe_or_id"]
            if _identifier.isnumeric():
                dbSystemConfiguration = lib_db.get.get__SystemConfiguration__by_id(
                    self.request.api_context,
                    _identifier,
                )
            else:
                dbSystemConfiguration = lib_db.get.get__SystemConfiguration__by_name(
                    self.request.api_context,
                    _identifier,
                )
            if not dbSystemConfiguration:
                raise HTTPNotFound("the SystemConfiguration was not found")
            self.dbSystemConfiguration = dbSystemConfiguration
            self._focus_url = "%s/system-configuration/%s" % (
                self.request.admin_url,
                self.dbSystemConfiguration.id,
            )
        return self.dbSystemConfiguration

    # ---------------

    @view_config(
        route_name="admin:system_configuration:focus",
        renderer="/admin/system_configuration-focus.mako",
    )
    @view_config(route_name="admin:system_configuration:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/system-configuration/{ID}.json",
            "section": "system-configuration",
            "about": """SystemConfiguration focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/system-configuration/1.json",
        }
    )
    def focus(self):
        dbSystemConfiguration = self._focus()
        if self.request.wants_json:
            return {
                "SystemConfiguration": dbSystemConfiguration.as_json,
            }
        return {
            "project": "peter_sslers",
            "SystemConfiguration": dbSystemConfiguration,
        }

    @view_config(
        route_name="admin:system_configuration:focus:edit",
        renderer="/admin/system_configuration-focus-edit.mako",
    )
    @view_config(
        route_name="admin:system_configuration:focus:edit|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/system-configuration/{ID}/edit.json",
            "section": "system-configuration",
            "about": """SystemConfiguration focus edit""",
            "POST": None,
            "GET": True,
            "instructions": "curl {ADMIN_PREFIX}/system-configuration/global/edit.json",
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
            },
            "valid_options": {
                "AcmeAccounts": "{RENDER_ON_REQUEST::as_json_label}",
                "private_key_cycle": Form_SystemConfiguration_edit.fields[
                    "private_key_cycle__primary"
                ].list,
                "private_key_cycle__backup": Form_SystemConfiguration_edit.fields[
                    "private_key_cycle__backup"
                ].list,
                "private_key_technology__primary": Form_SystemConfiguration_edit.fields[
                    "private_key_technology__primary"
                ].list,
                "private_key_technology__backup": Form_SystemConfiguration_edit.fields[
                    "private_key_technology__backup"
                ].list,
            },
            "note": "For `global` policy, only `acme_account_id__primary` and `acme_account_id__backup` allow changes. All fields must be submitted.",
        }
    )
    def edit(self):
        dbSystemConfiguration = self._focus()  # noqa: F841
        if self.request.method == "POST":
            if dbSystemConfiguration.name == "global":
                return self._edit__submit__global()
            return self._edit__submit()
        return self._edit__print()

    def _edit__print(self):
        assert self.dbSystemConfiguration is not None
        # quick setup, we need a bunch of options for dropdowns...
        self.dbAcmeAccounts_all = lib_db.get.get__AcmeAccount__paginated(
            self.request.api_context,
            render_in_selects=True,
        )
        if self.request.wants_json:
            return formatted_get_docs(self, "/system-configuration/{ID}/edit.json")
        return render_to_response(
            "/admin/system_configuration-focus-edit.mako",
            {
                "SystemConfiguration": self.dbSystemConfiguration,
                "AcmeAccounts": self.dbAcmeAccounts_all,
            },
            self.request,
        )

    def _edit__submit__global(self):
        assert self.dbSystemConfiguration is not None
        assert self.dbSystemConfiguration.name == "global"
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_SystemConfiguration_Global_edit,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                result = lib_db.update.update_SystemConfiguration(
                    self.request.api_context,
                    self.dbSystemConfiguration,
                    acme_account_id__primary=formStash.results[
                        "acme_account_id__primary"
                    ],
                    acme_account_id__backup=formStash.results[
                        "acme_account_id__backup"
                    ],
                    private_key_cycle__primary=self.dbSystemConfiguration.private_key_cycle__primary,
                    private_key_technology__primary=self.dbSystemConfiguration.private_key_technology__primary,
                    acme_profile__primary=self.dbSystemConfiguration.acme_profile__primary,
                    private_key_cycle__backup=self.dbSystemConfiguration.private_key_cycle__backup,
                    private_key_technology__backup=self.dbSystemConfiguration.private_key_technology__backup,
                    acme_profile__backup=self.dbSystemConfiguration.acme_profile__backup,
                    force_reconciliation=formStash.results[
                        "force_reconciliation"
                    ],  # undocumented
                )
            except Exception as exc:
                formStash.fatal_form(message=str(exc))

            if self.request.wants_json:
                return {
                    "result": "success",
                    "SystemConfiguration": self.dbSystemConfiguration.as_json,
                }
            return HTTPSeeOther(
                "%s/system-configuration/%s?result=success&operation=edit"
                % (
                    self.request.admin_url,
                    self.dbSystemConfiguration.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._edit__print)

    def _edit__submit(self):
        assert self.dbSystemConfiguration is not None
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_SystemConfiguration_edit, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                result = lib_db.update.update_SystemConfiguration(
                    self.request.api_context,
                    self.dbSystemConfiguration,
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
                    force_reconciliation=formStash.results[
                        "force_reconciliation"
                    ],  # undocumented
                )
            except Exception as exc:
                formStash.fatal_form(message=str(exc))

            if self.request.wants_json:
                return {
                    "result": "success",
                    "SystemConfiguration": self.dbSystemConfiguration.as_json,
                }
            return HTTPSeeOther(
                "%s/system-configuration/%s?result=success&operation=edit"
                % (
                    self.request.admin_url,
                    self.dbSystemConfiguration.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._edit__print)
