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
from ..lib.forms import Form_EnrollmentPolicy_edit
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
            "example": "curl {ADMIN_PREFIX}/enrollment-policy/1/edit.json",
            "examples": [],
            "form_fields": {
                "acme_account_id": "which provider",
                "acme_profile": "server profile",
                "key_technology": "what is the key technology preference for this account?",
                "private_key_cycle": "what should orders default to?",
                "acme_account_id__backup": "which provider",
                "acme_profile__backup": "server profile",
                "key_technology__backup": "what is the key technology preference for this account?",
                "private_key_cycle__backup": "what should orders default to?",
            },
            "valid_options": {
                "private_key_cycle": Form_EnrollmentPolicy_edit.fields[
                    "private_key_cycle"
                ].list,
                "private_key_cycle__backup": Form_EnrollmentPolicy_edit.fields[
                    "private_key_cycle__backup"
                ].list,
                "key_technology": Form_EnrollmentPolicy_edit.fields[
                    "key_technology"
                ].list,
                "key_technology__backup": Form_EnrollmentPolicy_edit.fields[
                    "key_technology__backup"
                ].list,
            },
        }
    )
    def edit(self):
        dbEnrollmentPolicy = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._edit__submit()
        return self._edit__print()

    def _edit__print(self):
        assert self.dbEnrollmentPolicy is not None
        dbAcmeAccounts = lib_db.get.get__AcmeAccount__paginated(
            self.request.api_context,
            limit=None,
        )
        if self.request.wants_json:
            return {
                "EnrollmentPolicy": self.dbEnrollmentPolicy.as_json,
            }
        # quick setup, we need a bunch of options for dropdowns...
        return render_to_response(
            "/admin/enrollment_policy-focus-edit.mako",
            {
                "EnrollmentPolicy": self.dbEnrollmentPolicy,
                "AcmeAccounts": dbAcmeAccounts,
            },
            self.request,
        )

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
                    acme_account_id=formStash.results["acme_account_id"],
                    private_key_cycle=formStash.results["private_key_cycle"],
                    key_technology=formStash.results["key_technology"],
                    acme_profile=formStash.results["acme_profile"],
                    acme_account_id__backup=formStash.results[
                        "acme_account_id__backup"
                    ],
                    private_key_cycle__backup=formStash.results[
                        "private_key_cycle__backup"
                    ],
                    key_technology__backup=formStash.results["key_technology__backup"],
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
