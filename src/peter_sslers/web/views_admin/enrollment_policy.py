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
from ..lib.forms import Form_EnrollmentPolicy_edit
from ..lib.forms import Form_EnrollmentPolicy_Global_edit
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import EnrollmentPolicy

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:enrollment_policys",
        renderer="/admin/enrollment_policys.mako",
    )
    @view_config(
        route_name="admin:enrollment_policys|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/enrollment-policys.json",
            "section": "enrollment-policys",
            "about": """list EnrollmentPolicy(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/enrollment-policys.json",
        }
    )
    def list(self):
        url_template = "%s/enrollment-policys" % (
            self.request.api_context.application_settings["admin_prefix"],
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        items_count = lib_db.get.get__EnrollmentPolicy__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__EnrollmentPolicy__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            # admin_url = self.request.admin_url
            return {
                "EnrollmentPolicys": [i.as_json for i in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "EnrollmentPolicys_count": items_count,
            "EnrollmentPolicys": items_paged,
            "pager": pager,
        }


# ------------------------------------------------------------------------------


class View_Focus(Handler):
    dbEnrollmentPolicy: Optional[EnrollmentPolicy] = None

    def _focus(self) -> EnrollmentPolicy:
        if self.dbEnrollmentPolicy is None:
            _identifier = self.request.matchdict["websafe_or_id"]
            if _identifier.isnumeric():
                dbEnrollmentPolicy = lib_db.get.get__EnrollmentPolicy__by_id(
                    self.request.api_context,
                    _identifier,
                )
            else:
                dbEnrollmentPolicy = lib_db.get.get__EnrollmentPolicy__by_name(
                    self.request.api_context,
                    _identifier,
                )
            if not dbEnrollmentPolicy:
                raise HTTPNotFound("the EnrollmentPolicy was not found")
            self.dbEnrollmentPolicy = dbEnrollmentPolicy
            self._focus_url = "%s/enrollment-policy/%s" % (
                self.request.admin_url,
                self.dbEnrollmentPolicy.id,
            )
        return self.dbEnrollmentPolicy

    # ---------------

    @view_config(
        route_name="admin:enrollment_policy:focus",
        renderer="/admin/enrollment_policy-focus.mako",
    )
    @view_config(route_name="admin:enrollment_policy:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/enrollment-policy/{ID}.json",
            "section": "enrollment-policy",
            "about": """EnrollmentPolicy focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/enrollment-policy/1.json",
        }
    )
    def focus(self):
        dbEnrollmentPolicy = self._focus()
        if self.request.wants_json:
            return {
                "EnrollmentPolicy": dbEnrollmentPolicy.as_json,
            }
        return {
            "project": "peter_sslers",
            "EnrollmentPolicy": dbEnrollmentPolicy,
        }

    @view_config(
        route_name="admin:enrollment_policy:focus:edit",
        renderer="/admin/enrollment_policy-focus-edit.mako",
    )
    @view_config(route_name="admin:enrollment_policy:focus:edit|json", renderer="json")
    @docify(
        {
            "endpoint": "/enrollment-policy/{ID}/edit.json",
            "section": "enrollment-policy",
            "about": """EnrollmentPolicy focus edit""",
            "POST": None,
            "GET": True,
            "instructions": "curl {ADMIN_PREFIX}/enrollment-policy/global/edit.json",
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
                "private_key_cycle": Form_EnrollmentPolicy_edit.fields[
                    "private_key_cycle__primary"
                ].list,
                "private_key_cycle__backup": Form_EnrollmentPolicy_edit.fields[
                    "private_key_cycle__backup"
                ].list,
                "private_key_technology__primary": Form_EnrollmentPolicy_edit.fields[
                    "private_key_technology__primary"
                ].list,
                "private_key_technology__backup": Form_EnrollmentPolicy_edit.fields[
                    "private_key_technology__backup"
                ].list,
            },
            "note": "For `global` policy, only `acme_account_id__primary` and `acme_account_id__backup` allow changes. All fields must be submitted.",
        }
    )
    def edit(self):
        dbEnrollmentPolicy = self._focus()  # noqa: F841
        if self.request.method == "POST":
            if dbEnrollmentPolicy.name == "global":
                return self._edit__submit__global()
            return self._edit__submit()
        return self._edit__print()

    def _edit__print(self):
        assert self.dbEnrollmentPolicy is not None
        # quick setup, we need a bunch of options for dropdowns...
        self.dbAcmeAccounts_all = lib_db.get.get__AcmeAccount__paginated(
            self.request.api_context,
            limit=None,
        )
        if self.request.wants_json:
            return formatted_get_docs(self, "/enrollment-policy/{ID}/edit.json")
        return render_to_response(
            "/admin/enrollment_policy-focus-edit.mako",
            {
                "EnrollmentPolicy": self.dbEnrollmentPolicy,
                "AcmeAccounts": self.dbAcmeAccounts_all,
            },
            self.request,
        )

    def _edit__submit__global(self):
        assert self.dbEnrollmentPolicy is not None
        assert self.dbEnrollmentPolicy.name == "global"
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_EnrollmentPolicy_Global_edit,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                result = lib_db.update.update_EnrollmentPolicy(
                    self.request.api_context,
                    self.dbEnrollmentPolicy,
                    acme_account_id__primary=formStash.results[
                        "acme_account_id__primary"
                    ],
                    acme_account_id__backup=formStash.results[
                        "acme_account_id__backup"
                    ],
                    private_key_cycle__primary=self.dbEnrollmentPolicy.private_key_cycle__primary,
                    private_key_technology__primary=self.dbEnrollmentPolicy.private_key_technology__primary,
                    acme_profile__primary=self.dbEnrollmentPolicy.acme_profile__primary,
                    private_key_cycle__backup=self.dbEnrollmentPolicy.private_key_cycle__backup,
                    private_key_technology__backup=self.dbEnrollmentPolicy.private_key_technology__backup,
                    acme_profile__backup=self.dbEnrollmentPolicy.acme_profile__backup,
                )
            except Exception as exc:
                formStash.fatal_form(message=str(exc))

            if self.request.wants_json:
                return {
                    "result": "success",
                    "EnrollmentPolicy": self.dbEnrollmentPolicy.as_json,
                }
            return HTTPSeeOther(
                "%s/enrollment-policy/%s?result=success&operation=edit"
                % (
                    self.request.admin_url,
                    self.dbEnrollmentPolicy.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._edit__print)

    def _edit__submit(self):
        assert self.dbEnrollmentPolicy is not None
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_EnrollmentPolicy_edit, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                result = lib_db.update.update_EnrollmentPolicy(
                    self.request.api_context,
                    self.dbEnrollmentPolicy,
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
                )
            except Exception as exc:
                formStash.fatal_form(message=str(exc))

            if self.request.wants_json:
                return {
                    "result": "success",
                    "EnrollmentPolicy": self.dbEnrollmentPolicy.as_json,
                }
            return HTTPSeeOther(
                "%s/enrollment-policy/%s?result=success&operation=edit"
                % (
                    self.request.admin_url,
                    self.dbEnrollmentPolicy.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._edit__print)
