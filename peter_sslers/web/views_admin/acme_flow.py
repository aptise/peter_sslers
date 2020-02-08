# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import sqlalchemy

# localapp
from .. import lib
from ..lib import form_utils as form_utils
from ..lib import formhandling
from ..lib import text as lib_text
from ..lib.forms import Form_CertificateRequest_AcmeFlow_manage_domain
from ..lib.forms import Form_CertificateRequest_new_AcmeFlow
from ..lib.handler import Handler, items_per_page
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils
from ...model import objects as model_objects


# ==============================================================================


class ViewAdmin_New(Handler):

    @view_config(route_name="admin:acme_flow:new")
    def new_AcmeFlow(self):
        raise ValueError("ACME-FLOW is being redone")

        if not self.request.registry.settings["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")

        if self.request.method == "POST":
            return self._new_AcmeFlow__submit()
        return self._new_AcmeFlow__print()

    def _new_AcmeFlow__print(self):
        self._load_AccountKeyDefault()
        return render_to_response(
            "/admin/acme_flow-new.mako",
            {"AcmeAccountKey_Default": self.dbAcmeAccountKeyDefault},
            self.request,
        )

    def _new_AcmeFlow__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CertificateRequest_new_AcmeFlow,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = utils.domains_from_string(formStash.results["domain_names"])
            if not domain_names:
                raise ValueError("missing valid domain names")
            dbCertificateRequest = lib_db.create.create__CertificateRequest(
                self.request.api_context,
                csr_pem=None,
                certificate_request_source_id=model_utils.CertificateRequestSource.ACME_FLOW,
                domain_names=domain_names,
            )

            return HTTPSeeOther(
                "%s/acme-flow/manage/%s"
                % (
                    self.request.registry.settings["admin_prefix"],
                    dbCertificateRequest.id,
                )
            )

        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(self.request, self._new_AcmeFlow__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_flow:focus:deactivate")
    @view_config(
        route_name="admin:acme_flow:focus:deactivate|json", renderer="json",
    )
    def deactivate(self):
        # todo: post only?
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        dbCertificateRequest = self._focus()
        if not dbCertificateRequest.certificate_request_source_is("acme flow"):
            if wants_json:
                return {"result": "error", "error": "Only availble for Acme Flow"}
            raise HTTPNotFound("Only availble for Acme Flow")
        dbCertificateRequest.is_active = False
        self.request.api_context.dbSession.flush(objects=[dbCertificateRequest])
        if wants_json:
            return {
                "result": "success",
                "CertificateRequest": dbCertificateRequest.as_json,
            }
        return HTTPSeeOther("%s?result=success" % self._focus_url)


class ViewAdmin_Focus(Handler):
    @view_config(
        route_name="admin:acme_flow:focus", renderer="/admin/acme_flow-focus.mako",
    )
    def manage_AcmeFlow(self):
        raise ValueError("this system is being redone")

        if not self.request.registry.settings["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")
        dbCertificateRequest = self._focus()
        if not dbCertificateRequest.certificate_request_source_is("acme flow"):
            raise HTTPNotFound("Only availble for Acme Flow")
        return {
            "project": "peter_sslers",
            "CertificateRequest": dbCertificateRequest,
            "CertificateRequest2Domain": None,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_flow:focus:domain")
    def manage_AcmeFlow_domain(self):
        raise ValueError("this system is being redone")

        if not self.request.registry.settings["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")

        dbCertificateRequest = self._focus()
        if not dbCertificateRequest.certificate_request_source_is("acme flow"):
            raise HTTPNotFound("Only availble for Acme Flow")
        dbCertificateRequest2Domain = None

        domain_identifier = self.request.matchdict["domain_identifier"].strip()
        if domain_identifier.isdigit():
            dbDomain = lib_db.get.get__Domain__by_id(
                self.request.api_context,
                domain_identifier,
                preload=False,
                eagerload_web=False,
            )
        else:
            dbDomain = lib_db.get.get__Domain__by_name(
                self.request.api_context,
                domain_identifier,
                preload=False,
                eagerload_web=False,
            )
        if not dbDomain:
            raise HTTPNotFound("invalid domain")

        for to_domain in dbCertificateRequest.unique_fqdn_set.to_domains:
            if to_domain.domain_id == dbDomain.id:
                dbCertificateRequest2Domain = to_domain
                break
        if dbCertificateRequest2Domain is None:
            raise HTTPNotFound("invalid domain for certificate request")

        self.db_CertificateRequest = dbCertificateRequest
        self.db_CertificateRequest2Domain = dbCertificateRequest2Domain

        if self.request.method == "POST":
            return self._manage_AcmeFlow_domain__submit()
        return self._manage_AcmeFlow_domain__print()

    def _manage_AcmeFlow_domain__print(self):
        return render_to_response(
            "/admin/acme_flow-manage.mako",
            {
                "CertificateRequest": self.db_CertificateRequest,
                "CertificateRequest2Domain": self.db_CertificateRequest2Domain,
            },
            self.request,
        )

    def _manage_AcmeFlow_domain__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CertificateRequest_AcmeFlow_manage_domain,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            if self.db_CertificateRequest2Domain.timestamp_verified:
                raise ValueError("You can not edit the challenge of a verified item")

            changed = False
            for attribute in ("challenge_key", "challenge_text"):
                submitted_value = formStash.results[attribute]
                if submitted_value != getattr(
                    self.db_CertificateRequest2Domain, attribute
                ):
                    setattr(
                        self.db_CertificateRequest2Domain, attribute, submitted_value,
                    )
                    changed = True

            if not changed:
                raise ValueError("No changes!")

            self.request.api_context.dbSession.flush(
                objects=[self.db_CertificateRequest2Domain]
            )

            return HTTPSeeOther(
                "%s/acme-flow/manage/domain/%s?result=success"
                % (self._focus_url, self.db_CertificateRequest2Domain.domain_id,)
            )

        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(
                self.request, self._manage_AcmeFlow_domain__print
            )
