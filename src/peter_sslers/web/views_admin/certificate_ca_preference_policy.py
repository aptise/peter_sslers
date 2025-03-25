# stdlib
from typing import Optional
from typing import TYPE_CHECKING

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_CertificateCAPreference__add
from ..lib.forms import Form_CertificateCAPreference__delete
from ..lib.forms import Form_CertificateCAPreference__prioritize
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...model.objects import CertificateCAPreferencePolicy

if TYPE_CHECKING:
    from pyramid_formencode_classic import FormStash
# ==============================================================================


class View_List(Handler):

    @view_config(
        route_name="admin:certificate_ca_preference_policys",
        renderer="/admin/certificate_ca_preference_policys.mako",
    )
    @view_config(
        route_name="admin:certificate_ca_preference_policys-paginated",
        renderer="/admin/certificate_ca_preference_policys.mako",
    )
    @view_config(
        route_name="admin:certificate_ca_preference_policys|json", renderer="json"
    )
    @view_config(
        route_name="admin:certificate_ca_preference_policys-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/certificate-ca-preference-policys.json",
            "section": "certificate-ca-preference-policys",
            "about": """list CertificateCAPreferencePolicy(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca-preference-policys.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca-preference-policys/{PAGE}.json",
            "section": "certificate-ca-preference-policys",
            "example": "curl {ADMIN_PREFIX}/certificate-ca-preference-policys/1.json",
            "variant_of": "/certificate-ca-preference-policys.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__CertificateCAPreferencePolicy__count(
            self.request.api_context
        )
        url_template = (
            "%s/certificate-ca-preference-policys/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateCAPreferencePolicy__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _items = {ca.id: ca.as_json for ca in items_paged}
            return {
                "CertificateCAPreferencePolicys": _items,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "CertificateCAPreferencePolicys_count": items_count,
            "CertificateCAPreferencePolicys": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbCertificateCAPreferencePolicy: Optional[CertificateCAPreferencePolicy] = None

    def _focus(self) -> CertificateCAPreferencePolicy:
        if self.dbCertificateCAPreferencePolicy is None:
            dbCertificateCAPreferencePolicy = (
                lib_db.get.get__CertificateCAPreferencePolicy__by_id(
                    self.request.api_context,
                    int(self.request.matchdict["id"]),
                    eagerload_preferences=True,
                )
            )
            if not dbCertificateCAPreferencePolicy:
                raise HTTPNotFound("the cert was not found")
            self.dbCertificateCAPreferencePolicy = dbCertificateCAPreferencePolicy
            self.focus_url = "%s/certificate-ca-preference-policy/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbCertificateCAPreferencePolicy.id,
            )
        return self.dbCertificateCAPreferencePolicy

    def _focus__print(self):
        if TYPE_CHECKING:
            assert self.dbCertificateCAPreferencePolicy is not None
        if self.request.wants_json:
            return {
                "CertificateCAPreferencePolicy": self.dbCertificateCAPreferencePolicy.as_json,
            }
        params = {
            "project": "peter_sslers",
            "CertificateCAPreferencePolicy": self.dbCertificateCAPreferencePolicy,
        }
        return render_to_response(
            "/admin/certificate_ca_preference_policy-focus.mako", params, self.request
        )

    @view_config(route_name="admin:certificate_ca_preference_policy:focus")
    @view_config(
        route_name="admin:certificate_ca_preference_policy:focus|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-ca-preference-policy/{id}.json",
            "section": "certificate-ca-preference-policy",
            "about": """view CertificateCAPreferencePolicy""",
            "POST": None,
            "GET": True,
        }
    )
    def focus(self):
        # just invoke the shared printing function
        self._focus()
        return self._focus__print()


class View_Preferred(View_Focus):
    def _get_active_selection(self, formStash: "FormStash"):
        """
        Queries the loaded preferences for a Fingerprint+Slot matching the
        the corresponding record indicated in the submitted ``formStash``.

        :param formStash: a formstash with at least the following result fields:
            * fingerprint_sha1
            * slot
        :returns: a two element tuple:
            0: the slot id
            1: instance of `model_utilsCertificateCAPreferences`
        """
        if TYPE_CHECKING:
            assert self.dbCertificateCAPreferencePolicy is not None

        cert_fingerprint = formStash.results["fingerprint_sha1"]
        cert_slot = formStash.results["slot"]

        dbPreference = None
        for _dbPref in self.dbCertificateCAPreferencePolicy.certificate_ca_preferences:
            if _dbPref.certificate_ca.fingerprint_sha1 == cert_fingerprint:
                dbPreference = _dbPref
                break

        if not dbPreference or (dbPreference.slot_id != cert_slot):
            # `formStash.fatal_form()` will raise `FormInvalid()`
            formStash.fatal_form("Can not operate on bad or stale data.")

        return dbPreference

    @view_config(route_name="admin:certificate_ca_preference_policy:focus:add")
    @view_config(
        route_name="admin:certificate_ca_preference_policy:focus:add|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/certificate-ca-preference-policy/{id}/add.json",
            "section": "certificate-ca-preference-policy",
            "about": """add preferred CertificateCA""",
            "POST": True,
            "GET": False,
            "instructions": "curl {ADMIN_PREFIX}/certificate-ca-preference-policy/{id}/add.json",
            # -----
            "examples": [
                """curl """
                """--form 'fingerprint_sha1=fingerprint_sha1' """
                """{ADMIN_PREFIX}/certificate-ca-preference-policy/{id}/add.json""",
            ],
            "form_fields": {
                "fingerprint_sha1": "the fingerprint_sha1 of the current record",
            },
        }
    )
    def add(self):
        self._focus()
        if TYPE_CHECKING:
            assert self.dbCertificateCAPreferencePolicy is not None
        try:
            if self.request.wants_json:
                if self.request.method != "POST":
                    return formatted_get_docs(
                        self, "/certificate-ca-preference-policy/{id}/add.json"
                    )
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CertificateCAPreference__add,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            # quick validation
            if (
                len(self.dbCertificateCAPreferencePolicy.certificate_ca_preferences)
                > 10
            ):
                raise ValueError("too many items in the preference queue")

            fingerprint_sha1 = formStash.results["fingerprint_sha1"]
            if len(fingerprint_sha1) == 8:
                matching_certs = (
                    lib_db.get.get__CertificateCAs__by_fingerprint_sha1_substring(
                        self.request.api_context,
                        fingerprint_sha1_substring=fingerprint_sha1,
                    )
                )
                if not len(matching_certs):
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="fingerprint_sha1",
                        message="No matching CertificateCAs.",
                    )
                elif len(matching_certs) > 1:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="fingerprint_sha1",
                        message="Too many matching CertificateCAs.",
                    )
                dbCertificateCA = matching_certs[0]
            else:
                dbCertificateCA = lib_db.get.get__CertificateCA__by_fingerprint_sha1(
                    self.request.api_context, fingerprint_sha1=fingerprint_sha1
                )
                if not dbCertificateCA:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="fingerprint_sha1",
                        message="No matching CertificateCA.",
                    )

            for (
                dbPref
            ) in self.dbCertificateCAPreferencePolicy.certificate_ca_preferences:
                if dbPref.certificate_ca_id == dbCertificateCA.id:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="fingerprint_sha1",
                        message="CertificateCA already in the list",
                    )

            dbPreferencePolicy = lib_db.get.get__CertificateCAPreferencePolicy__by_id(
                self.request.api_context,
                self.dbCertificateCAPreferencePolicy.id,
            )
            if not dbPreferencePolicy:
                formStash.fatal_form(message="could not load global policy")
            if TYPE_CHECKING:
                assert dbPreferencePolicy is not None

            # okay , add a new preference
            dbPreference = lib_db.create.create__CertificateCAPreference(  # noqa: F841
                self.request.api_context,
                dbCertificateCAPreferencePolicy=dbPreferencePolicy,
                dbCertificateCA=dbCertificateCA,
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "add",
                }
            return HTTPSeeOther(
                "%s/certificate-ca-preference-policy/%s?result=success&operation=add"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    self.dbCertificateCAPreferencePolicy.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus__print)

    @view_config(route_name="admin:certificate_ca_preference_policy:focus:delete")
    @view_config(
        route_name="admin:certificate_ca_preference_policy:focus:delete|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/certificate-ca-preference-policy/{id}/delete.json",
            "section": "certificate-ca-preference-policy",
            "about": """delete preferred CertificateCA""",
            "POST": True,
            "GET": False,
            "instructions": "curl {ADMIN_PREFIX}/certificate-ca-preference-policy/{id}/delete.json",
            # -----
            "examples": [
                """curl """
                """--form 'slot=slot' """
                """--form 'fingerprint_sha1=fingerprint_sha1' """
                """{ADMIN_PREFIX}/certificate-ca-preference-policy/{id}/delete.json""",
            ],
            "form_fields": {
                "fingerprint_sha1": "the fingerprint_sha1 of the current record",
                "slot": "the slot of the current record",
            },
        }
    )
    def delete(self):
        self._focus()
        if TYPE_CHECKING:
            assert self.dbCertificateCAPreferencePolicy is not None
        try:
            if self.request.wants_json:
                if self.request.method != "POST":
                    return formatted_get_docs(
                        self, "/certificate-ca-preference-policy/{id}/delete.json"
                    )
            # data_formencode_form = "delete"
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CertificateCAPreference__delete,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            dbPreference_active = self._get_active_selection(formStash)

            # okay, now iterate over the list...
            _removed = False
            for (
                dbPref
            ) in self.dbCertificateCAPreferencePolicy.certificate_ca_preferences:
                if dbPref == dbPreference_active:
                    self.request.api_context.dbSession.delete(dbPref)
                    self.request.api_context.dbSession.flush()
                    _removed = True
                else:
                    if _removed:
                        dbPref.id = dbPref.id - 1
                        self.request.api_context.dbSession.flush(objects=[dbPref])

            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "delete",
                }
            return HTTPSeeOther(
                "%s/certificate-ca-preference-policy/%s?result=success&operation=delete"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    self.dbCertificateCAPreferencePolicy.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus__print)

    @view_config(route_name="admin:certificate_ca_preference_policy:focus:prioritize")
    @view_config(
        route_name="admin:certificate_ca_preference_policy:focus:prioritize|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/certificate-ca-preference-policy/{id}/prioritize.json",
            "section": "certificate-ca-preference-policy",
            "about": """prioritize preferred CertificateCA""",
            "POST": True,
            "GET": False,
            "instructions": "curl {ADMIN_PREFIX}/certificate-ca-preference-policy/{id}/prioritize.json",
            # -----
            "examples": [
                """curl """
                """--form 'fingerprint_sha1=fingerprint_sha1' """
                """{ADMIN_PREFIX}/certificate-ca-preference-policy/{id}/prioritize.json""",
            ],
            "form_fields": {
                "fingerprint_sha1": "the fingerprint_sha1 of the current record",
                "slot": "the slot of the current record",
                "priority": "the new priority for the current record",
            },
            "valid_options": {
                "priority": Form_CertificateCAPreference__prioritize.fields[
                    "priority"
                ].list,
            },
        }
    )
    def prioritize(self):
        self._focus()
        if TYPE_CHECKING:
            assert self.dbCertificateCAPreferencePolicy is not None
        if self.request.wants_json:
            if self.request.method != "POST":
                return formatted_get_docs(
                    self, "/certificate-ca-preference-policy/{id}/prioritize.json"
                )
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CertificateCAPreference__prioritize,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            dbPreference_active = self._get_active_selection(formStash)

            try:
                lib_db.update.update_CertificateCAPreferencePolicy_reprioritize(
                    self.request.api_context,
                    self.dbCertificateCAPreferencePolicy,
                    dbPreference_active,
                    priority=formStash.results["priority"],
                )

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(exc.args[0])

            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "prioritize",
                }
            return HTTPSeeOther(
                "%s/certificate-ca-preference-policy/%s?result=success&operation=prioritize"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    self.dbCertificateCAPreferencePolicy.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus__print)
