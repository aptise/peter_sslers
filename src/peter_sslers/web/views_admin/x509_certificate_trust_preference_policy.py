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
from ..lib.forms import Form_X509CertificatePreferencePolicyItem__add
from ..lib.forms import Form_X509CertificatePreferencePolicyItem__delete
from ..lib.forms import Form_X509CertificatePreferencePolicyItem__prioritize
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...model.objects import X509CertificateTrustPreferencePolicy

if TYPE_CHECKING:
    from pyramid_formencode_classic import FormStash
# ==============================================================================


class View_List(Handler):

    @view_config(
        route_name="admin:x509_certificate_trust_preference_policys",
        renderer="/admin/x509_certificate_trust_preference_policys.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trust_preference_policys-paginated",
        renderer="/admin/x509_certificate_trust_preference_policys.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trust_preference_policys|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:x509_certificate_trust_preference_policys-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificate-trust-preference-policys.json",
            "section": "x509-certificate-trust-preference-policys",
            "about": """list X509CertificateTrustPreferencePolicy(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate-trust-preference-policys.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate-trust-preference-policys/{PAGE}.json",
            "section": "x509-certificate-trust-preference-policys",
            "example": "curl {ADMIN_PREFIX}/x509-certificate-trust-preference-policys/1.json",
            "variant_of": "/x509-certificate-trust-preference-policys.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__X509CertificateTrustPreferencePolicy__count(
            self.request.api_context
        )
        url_template = (
            "%s/x509-certificate-trust-preference-policys/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__X509CertificateTrustPreferencePolicy__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _items = {ca.id: ca.as_json for ca in items_paged}
            return {
                "X509CertificateTrustPreferencePolicys": _items,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "X509CertificateTrustPreferencePolicys_count": items_count,
            "X509CertificateTrustPreferencePolicys": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbX509CertificateTrustPreferencePolicy: Optional[
        X509CertificateTrustPreferencePolicy
    ] = None

    def _focus(self) -> X509CertificateTrustPreferencePolicy:
        if self.dbX509CertificateTrustPreferencePolicy is None:
            dbX509CertificateTrustPreferencePolicy = (
                lib_db.get.get__X509CertificateTrustPreferencePolicy__by_id(
                    self.request.api_context,
                    int(self.request.matchdict["id"]),
                    eagerload_preferences=True,
                )
            )
            if not dbX509CertificateTrustPreferencePolicy:
                raise HTTPNotFound("the cert was not found")
            self.dbX509CertificateTrustPreferencePolicy = (
                dbX509CertificateTrustPreferencePolicy
            )
            self.focus_url = "%s/x509-certificate-trust-preference-policy/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbX509CertificateTrustPreferencePolicy.id,
            )
        return self.dbX509CertificateTrustPreferencePolicy

    def _focus__print(self):
        if TYPE_CHECKING:
            assert self.dbX509CertificateTrustPreferencePolicy is not None
        if self.request.wants_json:
            return {
                "X509CertificateTrustPreferencePolicy": self.dbX509CertificateTrustPreferencePolicy.as_json,
            }
        params = {
            "project": "peter_sslers",
            "X509CertificateTrustPreferencePolicy": self.dbX509CertificateTrustPreferencePolicy,
        }
        return render_to_response(
            "/admin/x509_certificate_trust_preference_policy-focus.mako",
            params,
            self.request,
        )

    @view_config(route_name="admin:x509_certificate_trust_preference_policy:focus")
    @view_config(
        route_name="admin:x509_certificate_trust_preference_policy:focus|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificate-trust-preference-policy/{id}.json",
            "section": "x509-certificate-trust-preference-policy",
            "about": """view X509CertificateTrustPreferencePolicy""",
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
            1: instance of `model_utilsX509CertificatePreferencePolicyItems`
        """
        if TYPE_CHECKING:
            assert self.dbX509CertificateTrustPreferencePolicy is not None

        cert_fingerprint = formStash.results["fingerprint_sha1"]
        cert_slot = formStash.results["slot"]

        dbPreference = None
        for (
            _dbPref
        ) in (
            self.dbX509CertificateTrustPreferencePolicy.x509_certificate_trust_preference_policy_items
        ):
            if _dbPref.x509_certificate_trusted.fingerprint_sha1 == cert_fingerprint:
                dbPreference = _dbPref
                break

        if not dbPreference or (dbPreference.slot_id != cert_slot):
            formStash.fatal_form("Can not operate on bad or stale data.")

        return dbPreference

    @view_config(route_name="admin:x509_certificate_trust_preference_policy:focus:add")
    @view_config(
        route_name="admin:x509_certificate_trust_preference_policy:focus:add|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificate-trust-preference-policy/{id}/add.json",
            "section": "x509-certificate-trust-preference-policy",
            "about": """add preferred X509CertificateTrusted""",
            "POST": True,
            "GET": False,
            "instructions": "curl {ADMIN_PREFIX}/x509-certificate-trust-preference-policy/{id}/add.json",
            # -----
            "examples": [
                """curl """
                """--form 'fingerprint_sha1=fingerprint_sha1' """
                """{ADMIN_PREFIX}/x509-certificate-trust-preference-policy/{id}/add.json""",
            ],
            "form_fields": {
                "fingerprint_sha1": "the fingerprint_sha1 of the current record",
            },
        }
    )
    def add(self):
        self._focus()
        if TYPE_CHECKING:
            assert self.dbX509CertificateTrustPreferencePolicy is not None
        try:
            if self.request.wants_json:
                if self.request.method != "POST":
                    return formatted_get_docs(
                        self, "/x509-certificate-trust-preference-policy/{id}/add.json"
                    )
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_X509CertificatePreferencePolicyItem__add,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            # quick validation
            if (
                len(
                    self.dbX509CertificateTrustPreferencePolicy.x509_certificate_trust_preference_policy_items
                )
                > 10
            ):
                raise ValueError("too many items in the preference queue")

            fingerprint_sha1 = formStash.results["fingerprint_sha1"]
            if len(fingerprint_sha1) == 8:
                matching_certs = lib_db.get.get__X509CertificateTrusteds__by_fingerprint_sha1_substring(
                    self.request.api_context,
                    fingerprint_sha1_substring=fingerprint_sha1,
                )
                if not len(matching_certs):
                    formStash.fatal_field(
                        field="fingerprint_sha1",
                        error_field="No matching X509CertificateTrusteds.",
                    )
                elif len(matching_certs) > 1:
                    formStash.fatal_field(
                        field="fingerprint_sha1",
                        error_field="Too many matching X509CertificateTrusteds.",
                    )
                dbX509CertificateTrusted = matching_certs[0]
            else:
                dbX509CertificateTrusted = (
                    lib_db.get.get__X509CertificateTrusted__by_fingerprint_sha1(
                        self.request.api_context, fingerprint_sha1=fingerprint_sha1
                    )
                )
                if not dbX509CertificateTrusted:
                    formStash.fatal_field(
                        field="fingerprint_sha1",
                        error_field="No matching X509CertificateTrusted.",
                    )

            for (
                dbPref
            ) in (
                self.dbX509CertificateTrustPreferencePolicy.x509_certificate_trust_preference_policy_items
            ):
                if dbPref.x509_certificate_trusted_id == dbX509CertificateTrusted.id:
                    formStash.fatal_field(
                        field="fingerprint_sha1",
                        error_field="X509CertificateTrusted already in the list",
                    )

            dbPreferencePolicy = (
                lib_db.get.get__X509CertificateTrustPreferencePolicy__by_id(
                    self.request.api_context,
                    self.dbX509CertificateTrustPreferencePolicy.id,
                )
            )
            if not dbPreferencePolicy:
                formStash.fatal_form(error_main="could not load global policy")
            if TYPE_CHECKING:
                assert dbPreferencePolicy is not None

            # okay , add a new preference
            dbPreference = (  # noqa: F841
                lib_db.create.create__X509CertificatePreferencePolicyItem(
                    self.request.api_context,
                    dbX509CertificateTrustPreferencePolicy=dbPreferencePolicy,
                    dbX509CertificateTrusted=dbX509CertificateTrusted,
                )
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "add",
                }
            return HTTPSeeOther(
                "%s/x509-certificate-trust-preference-policy/%s?result=success&operation=add"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    self.dbX509CertificateTrustPreferencePolicy.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus__print)

    @view_config(
        route_name="admin:x509_certificate_trust_preference_policy:focus:delete"
    )
    @view_config(
        route_name="admin:x509_certificate_trust_preference_policy:focus:delete|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificate-trust-preference-policy/{id}/delete.json",
            "section": "x509-certificate-trust-preference-policy",
            "about": """delete preferred X509CertificateTrusted""",
            "POST": True,
            "GET": False,
            "instructions": "curl {ADMIN_PREFIX}/x509-certificate-trust-preference-policy/{id}/delete.json",
            # -----
            "examples": [
                """curl """
                """--form 'slot=slot' """
                """--form 'fingerprint_sha1=fingerprint_sha1' """
                """{ADMIN_PREFIX}/x509-certificate-trust-preference-policy/{id}/delete.json""",
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
            assert self.dbX509CertificateTrustPreferencePolicy is not None
        try:
            if self.request.wants_json:
                if self.request.method != "POST":
                    return formatted_get_docs(
                        self,
                        "/x509-certificate-trust-preference-policy/{id}/delete.json",
                    )
            # data_formencode_form = "delete"
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_X509CertificatePreferencePolicyItem__delete,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            dbPreference_active = self._get_active_selection(formStash)

            # okay, now iterate over the list...
            _removed = False
            for (
                dbPref
            ) in (
                self.dbX509CertificateTrustPreferencePolicy.x509_certificate_trust_preference_policy_items
            ):
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
                "%s/x509-certificate-trust-preference-policy/%s?result=success&operation=delete"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    self.dbX509CertificateTrustPreferencePolicy.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus__print)

    @view_config(
        route_name="admin:x509_certificate_trust_preference_policy:focus:prioritize"
    )
    @view_config(
        route_name="admin:x509_certificate_trust_preference_policy:focus:prioritize|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificate-trust-preference-policy/{id}/prioritize.json",
            "section": "x509-certificate-trust-preference-policy",
            "about": """prioritize preferred X509CertificateTrusted""",
            "POST": True,
            "GET": False,
            "instructions": "curl {ADMIN_PREFIX}/x509-certificate-trust-preference-policy/{id}/prioritize.json",
            # -----
            "examples": [
                """curl """
                """--form 'fingerprint_sha1=fingerprint_sha1' """
                """{ADMIN_PREFIX}/x509-certificate-trust-preference-policy/{id}/prioritize.json""",
            ],
            "form_fields": {
                "fingerprint_sha1": "the fingerprint_sha1 of the current record",
                "slot": "the slot of the current record",
                "priority": "the new priority for the current record",
            },
            "valid_options": {
                "priority": Form_X509CertificatePreferencePolicyItem__prioritize.fields[
                    "priority"
                ].list,
            },
        }
    )
    def prioritize(self):
        self._focus()
        if TYPE_CHECKING:
            assert self.dbX509CertificateTrustPreferencePolicy is not None
        if self.request.wants_json:
            if self.request.method != "POST":
                return formatted_get_docs(
                    self,
                    "/x509-certificate-trust-preference-policy/{id}/prioritize.json",
                )
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_X509CertificatePreferencePolicyItem__prioritize,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            dbPreference_active = self._get_active_selection(formStash)

            try:
                lib_db.update.update_X509CertificateTrustPreferencePolicy_reprioritize(
                    self.request.api_context,
                    self.dbX509CertificateTrustPreferencePolicy,
                    dbPreference_active,
                    priority=formStash.results["priority"],
                )

            except errors.InvalidTransition as exc:
                formStash.fatal_form(exc.args[0])

            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "prioritize",
                }
            return HTTPSeeOther(
                "%s/x509-certificate-trust-preference-policy/%s?result=success&operation=prioritize"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    self.dbX509CertificateTrustPreferencePolicy.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus__print)
