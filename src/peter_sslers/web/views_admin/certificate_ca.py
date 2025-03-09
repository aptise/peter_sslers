# stdlib
from typing import Optional

# pypi
import cert_utils
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.response import Response
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_CertificateCA_Upload_Cert__file
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import CertificateCA

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:certificate_cas", renderer="/admin/certificate_cas.mako"
    )
    @view_config(
        route_name="admin:certificate_cas-paginated",
        renderer="/admin/certificate_cas.mako",
    )
    @view_config(route_name="admin:certificate_cas|json", renderer="json")
    @view_config(route_name="admin:certificate_cas-paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/certificate-cas.json",
            "section": "certificate-ca",
            "about": """list CertificateCA(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-cas.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-cas/{PAGE}.json",
            "section": "certificate-ca",
            "example": "curl {ADMIN_PREFIX}/certificate-cas/1.json",
            "variant_of": "/certificate-cas.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__CertificateCA__count(self.request.api_context)
        url_template = (
            "%s/certificate-cas/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateCA__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _certs = {c.id: c.as_json for c in items_paged}
            return {
                "CertificateCAs": _certs,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "CertificateCAs_count": items_count,
            "CertificateCAs": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbCertificateCA: Optional[CertificateCA] = None

    def _focus(self) -> CertificateCA:
        if self.dbCertificateCA is None:
            dbCertificateCA = lib_db.get.get__CertificateCA__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbCertificateCA:
                raise HTTPNotFound("the cert was not found")
            self.dbCertificateCA = dbCertificateCA
            self.focus_item = dbCertificateCA
            self.focus_url = "%s/certificate-ca/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbCertificateCA.id,
            )
        return self.dbCertificateCA

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_ca:focus",
        renderer="/admin/certificate_ca-focus.mako",
    )
    @view_config(route_name="admin:certificate_ca:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}.json",
            "section": "certificate-ca",
            "about": """CertificateCA focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1.json",
        }
    )
    def focus(self):
        dbCertificateCA = self._focus()
        items_count = (
            lib_db.get.get__CertificateSigned__by_CertificateCAId__primary__count(
                self.request.api_context, dbCertificateCA.id
            )
        )
        items_paged = (
            lib_db.get.get__CertificateSigned__by_CertificateCAId__primary__paginated(
                self.request.api_context, dbCertificateCA.id, limit=10, offset=0
            )
        )
        items_paged_alt = (
            lib_db.get.get__CertificateSigned__by_CertificateCAId__alt__paginated(
                self.request.api_context, dbCertificateCA.id, limit=10, offset=0
            )
        )
        chains_0 = lib_db.get.get__CertificateCAChain__by_CertificateCAId0__paginated(
            self.request.api_context, dbCertificateCA.id, limit=10, offset=0
        )
        chains_n = lib_db.get.get__CertificateCAChain__by_CertificateCAIdN__paginated(
            self.request.api_context, dbCertificateCA.id, limit=10, offset=0
        )
        if self.request.wants_json:
            return {
                "CertificateCA": dbCertificateCA.as_json,
            }
        return {
            "project": "peter_sslers",
            "CertificateCA": dbCertificateCA,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "CertificateSigneds_Alt": items_paged_alt,
            "CertificateCAChains0": chains_0,
            "CertificateCAChainsN": chains_n,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_ca:focus:raw", renderer="string")
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.pem",
            "section": "certificate-ca",
            "about": """CertificateCA focus: cert.pem""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.pem.txt",
            "section": "certificate-ca",
            "about": """CertificateCA focus: cert.pem.txt""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.cer",
            "section": "certificate-ca",
            "about": """CertificateCA focus: cert.cer""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.cer",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.crt",
            "section": "certificate-ca",
            "about": """CertificateCA focus: cert.crt""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.crt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.der",
            "section": "certificate-ca",
            "about": """CertificateCA focus: cert.der""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.der",
        }
    )
    def focus_raw(self):
        """
        for extensions, see `cert_utils.EXTENSION_TO_MIME`
        """
        dbCertificateCA = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateCA.cert_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateCA.cert_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(pem_data=dbCertificateCA.cert_pem)
            response = Response()
            if self.request.matchdict["format"] in ("crt", "der"):
                response.content_type = "application/x-x509-ca-cert"
            elif self.request.matchdict["format"] in ("cer",):
                response.content_type = "application/pkix-cert"
            response.body = as_der
            return response
        return "UNSUPPORTED FORMAT"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_ca:focus:parse|json", renderer="json")
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/parse.json",
            "section": "certificate-ca",
            "about": """CertificateCA focus: parse""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/parse.json",
        }
    )
    def focus_parse_json(self):
        dbCertificateCA = self._focus()
        return {
            "CertificateCA": {
                "id": dbCertificateCA.id,
                "parsed": cert_utils.parse_cert(cert_pem=dbCertificateCA.cert_pem),
            }
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_ca:focus:certificate_signeds",
        renderer="/admin/certificate_ca-focus-certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:certificate_ca:focus:certificate_signeds-paginated",
        renderer="/admin/certificate_ca-focus-certificate_signeds.mako",
    )
    def related__CertificateSigneds(self):
        dbCertificateCA = self._focus()
        items_count = (
            lib_db.get.get__CertificateSigned__by_CertificateCAId__primary__count(
                self.request.api_context, dbCertificateCA.id
            )
        )
        url_template = "%s/certificate-signeds/{0}" % self.focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__CertificateSigned__by_CertificateCAId__primary__paginated(
                self.request.api_context,
                dbCertificateCA.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "CertificateCA": dbCertificateCA,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_ca:focus:certificate_signeds_alt",
        renderer="/admin/certificate_ca-focus-certificate_signeds_alt.mako",
    )
    @view_config(
        route_name="admin:certificate_ca:focus:certificate_signeds_alt-paginated",
        renderer="/admin/certificate_ca-focus-certificate_signeds_alt.mako",
    )
    def related__CertificateSignedsAlt(self):
        dbCertificateCA = self._focus()
        items_count = lib_db.get.get__CertificateSigned__by_CertificateCAId__alt__count(
            self.request.api_context, dbCertificateCA.id
        )
        url_template = "%s/certificate-signeds-alt/{0}" % self.focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__CertificateSigned__by_CertificateCAId__alt__paginated(
                self.request.api_context,
                dbCertificateCA.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "CertificateCA": dbCertificateCA,
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_ca:focus:certificate_ca_chains_0",
        renderer="/admin/certificate_ca-focus-certificate_ca_chains.mako",
    )
    @view_config(
        route_name="admin:certificate_ca:focus:certificate_ca_chains_0-paginated",
        renderer="/admin/certificate_ca-focus-certificate_ca_chains.mako",
    )
    @view_config(
        route_name="admin:certificate_ca:focus:certificate_ca_chains_n",
        renderer="/admin/certificate_ca-focus-certificate_ca_chains.mako",
    )
    @view_config(
        route_name="admin:certificate_ca:focus:certificate_ca_chains_n-paginated",
        renderer="/admin/certificate_ca-focus-certificate_ca_chains.mako",
    )
    def related__CertificateCAChains(self):
        dbCertificateCA = self._focus()

        accessor = None
        if self.request.matched_route.name in (
            "admin:certificate_ca:focus:certificate_ca_chains_0",
            "admin:certificate_ca:focus:certificate_ca_chains_0-paginated",
        ):
            url_template = "%s/certificate-ca-chains-0/{0}" % self.focus_url
            func_count = lib_db.get.get__CertificateCAChain__by_CertificateCAId0__count
            func_paginated = (
                lib_db.get.get__CertificateCAChain__by_CertificateCAId0__paginated
            )
            accessor = "0"
        else:
            url_template = "%s/certificate-ca-chains-n/{0}" % self.focus_url
            func_count = lib_db.get.get__CertificateCAChain__by_CertificateCAIdN__count
            func_paginated = (
                lib_db.get.get__CertificateCAChain__by_CertificateCAIdN__paginated
            )
            accessor = "n"

        items_count = func_count(self.request.api_context, dbCertificateCA.id)
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = func_paginated(
            self.request.api_context,
            dbCertificateCA.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "CertificateCA": dbCertificateCA,
            "CertificateCAChains_count": items_count,
            "CertificateCAChains": items_paged,
            "accessor": accessor,
            "pager": pager,
        }


class View_New(Handler):
    @view_config(route_name="admin:certificate_ca:upload_cert")
    @view_config(route_name="admin:certificate_ca:upload_cert|json", renderer="json")
    @docify(
        {
            "endpoint": "/certificate-ca/upload-cert.json",
            "section": "certificate-ca",
            "about": """CertificateCA upload certificate""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.der",
            # -----
            "instructions": [
                """curl """
                """--form 'cert_file=@chain1.pem' """
                """{ADMIN_PREFIX}/certificate-ca/upload-cert.json""",
            ],
            "form_fields": {
                "cert_file": "required",
            },
        }
    )
    def upload_cert(self):
        if self.request.method == "POST":
            return self._upload_cert__submit()
        return self._upload_cert__print()

    def _upload_cert__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/certificate-ca/upload-cert.json")
        return render_to_response(
            "/admin/certificate_ca-upload_cert.mako", {}, self.request
        )

    def _upload_cert__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CertificateCA_Upload_Cert__file,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            cert_pem = formhandling.slurp_file_field(formStash, "cert_file")
            if not isinstance(cert_pem, str):
                cert_pem = cert_pem.decode("utf8")

            cert_file_name = formStash.results["cert_file_name"] or "manual upload"
            (
                dbCertificateCA,
                _is_created,
            ) = lib_db.getcreate.getcreate__CertificateCA__by_pem_text(
                self.request.api_context,
                cert_pem,
                display_name=cert_file_name,
                discovery_type="upload",
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "CertificateCA": {
                        "created": _is_created,
                        "id": dbCertificateCA.id,
                    },
                }
            return HTTPSeeOther(
                "%s/certificate-ca/%s?result=success&is_created=%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbCertificateCA.id,
                    (1 if _is_created else 0),
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload_cert__submit)
