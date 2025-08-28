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
from ..lib.forms import Form_X509CertificateTrusted_Upload_Cert__file
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import X509CertificateTrusted

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:x509_certificate_trusteds",
        renderer="/admin/x509_certificate_trusteds.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trusteds-paginated",
        renderer="/admin/x509_certificate_trusteds.mako",
    )
    @view_config(route_name="admin:x509_certificate_trusteds|json", renderer="json")
    @view_config(
        route_name="admin:x509_certificate_trusteds-paginated|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-cas.json",
            "section": "certificate-ca",
            "about": """list X509CertificateTrusted(s)""",
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
        items_count = lib_db.get.get__X509CertificateTrusted__count(
            self.request.api_context
        )
        url_template = (
            "%s/certificate-cas/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__X509CertificateTrusted__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _certs = {c.id: c.as_json for c in items_paged}
            return {
                "X509CertificateTrusteds": _certs,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "X509CertificateTrusteds_count": items_count,
            "X509CertificateTrusteds": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbX509CertificateTrusted: Optional[X509CertificateTrusted] = None

    def _focus(self) -> X509CertificateTrusted:
        if self.dbX509CertificateTrusted is None:
            dbX509CertificateTrusted = lib_db.get.get__X509CertificateTrusted__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbX509CertificateTrusted:
                raise HTTPNotFound("the cert was not found")
            self.dbX509CertificateTrusted = dbX509CertificateTrusted
            self.focus_item = dbX509CertificateTrusted
            self.focus_url = "%s/certificate-ca/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbX509CertificateTrusted.id,
            )
        return self.dbX509CertificateTrusted

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_trusted:focus",
        renderer="/admin/x509_certificate_trusted-focus.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trusted:focus|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}.json",
            "section": "certificate-ca",
            "about": """X509CertificateTrusted focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1.json",
        }
    )
    def focus(self):
        dbX509CertificateTrusted = self._focus()
        items_count = lib_db.get.get__X509Certificate__by_X509CertificateTrustedId__primary__count(
            self.request.api_context, dbX509CertificateTrusted.id
        )
        items_paged = lib_db.get.get__X509Certificate__by_X509CertificateTrustedId__primary__paginated(
            self.request.api_context, dbX509CertificateTrusted.id, limit=10, offset=0
        )
        items_paged_alt = lib_db.get.get__X509Certificate__by_X509CertificateTrustedId__alt__paginated(
            self.request.api_context, dbX509CertificateTrusted.id, limit=10, offset=0
        )
        chains_0 = lib_db.get.get__X509CertificateTrustChain__by_X509CertificateTrustedId0__paginated(
            self.request.api_context, dbX509CertificateTrusted.id, limit=10, offset=0
        )
        chains_n = lib_db.get.get__X509CertificateTrustChain__by_X509CertificateTrustedIdN__paginated(
            self.request.api_context, dbX509CertificateTrusted.id, limit=10, offset=0
        )
        if self.request.wants_json:
            return {
                "X509CertificateTrusted": dbX509CertificateTrusted.as_json,
            }
        return {
            "project": "peter_sslers",
            "X509CertificateTrusted": dbX509CertificateTrusted,
            "X509Certificates_count": items_count,
            "X509Certificates": items_paged,
            "X509Certificates_Alt": items_paged_alt,
            "X509CertificateTrustChains0": chains_0,
            "X509CertificateTrustChainsN": chains_n,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_trusted:focus:raw", renderer="string"
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.pem",
            "section": "certificate-ca",
            "about": """X509CertificateTrusted focus: cert.pem""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.pem.txt",
            "section": "certificate-ca",
            "about": """X509CertificateTrusted focus: cert.pem.txt""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.cer",
            "section": "certificate-ca",
            "about": """X509CertificateTrusted focus: cert.cer""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.cer",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.crt",
            "section": "certificate-ca",
            "about": """X509CertificateTrusted focus: cert.crt""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.crt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/cert.der",
            "section": "certificate-ca",
            "about": """X509CertificateTrusted focus: cert.der""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/cert.der",
        }
    )
    def focus_raw(self):
        """
        for extensions, see `cert_utils.EXTENSION_TO_MIME`
        """
        dbX509CertificateTrusted = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbX509CertificateTrusted.cert_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbX509CertificateTrusted.cert_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbX509CertificateTrusted.cert_pem
            )
            response = Response()
            if self.request.matchdict["format"] in ("crt", "der"):
                response.content_type = "application/x-x509-ca-cert"
            elif self.request.matchdict["format"] in ("cer",):
                response.content_type = "application/pkix-cert"
            response.body = as_der
            return response
        return "UNSUPPORTED FORMAT"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_trusted:focus:parse|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-ca/{ID}/parse.json",
            "section": "certificate-ca",
            "about": """X509CertificateTrusted focus: parse""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca/1/parse.json",
        }
    )
    def focus_parse_json(self):
        dbX509CertificateTrusted = self._focus()
        return {
            "X509CertificateTrusted": {
                "id": dbX509CertificateTrusted.id,
                "parsed": cert_utils.parse_cert(
                    cert_pem=dbX509CertificateTrusted.cert_pem
                ),
            }
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_trusted:focus:x509_certificates",
        renderer="/admin/x509_certificate_trusted-focus-x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trusted:focus:x509_certificates-paginated",
        renderer="/admin/x509_certificate_trusted-focus-x509_certificates.mako",
    )
    def related__X509Certificates(self):
        dbX509CertificateTrusted = self._focus()
        items_count = lib_db.get.get__X509Certificate__by_X509CertificateTrustedId__primary__count(
            self.request.api_context, dbX509CertificateTrusted.id
        )
        url_template = "%s/x509-certificates/{0}" % self.focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__X509Certificate__by_X509CertificateTrustedId__primary__paginated(
            self.request.api_context,
            dbX509CertificateTrusted.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "X509CertificateTrusted": dbX509CertificateTrusted,
            "X509Certificates_count": items_count,
            "X509Certificates": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_trusted:focus:x509_certificates_alt",
        renderer="/admin/x509_certificate_trusted-focus-x509_certificates_alt.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trusted:focus:x509_certificates_alt-paginated",
        renderer="/admin/x509_certificate_trusted-focus-x509_certificates_alt.mako",
    )
    def related__X509CertificatesAlt(self):
        dbX509CertificateTrusted = self._focus()
        items_count = (
            lib_db.get.get__X509Certificate__by_X509CertificateTrustedId__alt__count(
                self.request.api_context, dbX509CertificateTrusted.id
            )
        )
        url_template = "%s/x509-certificates-alt/{0}" % self.focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__X509Certificate__by_X509CertificateTrustedId__alt__paginated(
            self.request.api_context,
            dbX509CertificateTrusted.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "X509CertificateTrusted": dbX509CertificateTrusted,
            "X509Certificates_count": items_count,
            "X509Certificates": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_trusted:focus:x509_certificate_trust_chains_0",
        renderer="/admin/x509_certificate_trusted-focus-x509_certificate_trust_chains.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trusted:focus:x509_certificate_trust_chains_0-paginated",
        renderer="/admin/x509_certificate_trusted-focus-x509_certificate_trust_chains.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trusted:focus:x509_certificate_trust_chains_n",
        renderer="/admin/x509_certificate_trusted-focus-x509_certificate_trust_chains.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trusted:focus:x509_certificate_trust_chains_n-paginated",
        renderer="/admin/x509_certificate_trusted-focus-x509_certificate_trust_chains.mako",
    )
    def related__X509CertificateTrustChains(self):
        dbX509CertificateTrusted = self._focus()

        accessor = None
        if self.request.matched_route.name in (
            "admin:x509_certificate_trusted:focus:x509_certificate_trust_chains_0",
            "admin:x509_certificate_trusted:focus:x509_certificate_trust_chains_0-paginated",
        ):
            url_template = "%s/x509-certificate-trust-chain-0/{0}" % self.focus_url
            func_count = (
                lib_db.get.get__X509CertificateTrustChain__by_X509CertificateTrustedId0__count
            )
            func_paginated = (
                lib_db.get.get__X509CertificateTrustChain__by_X509CertificateTrustedId0__paginated
            )
            accessor = "0"
        else:
            url_template = "%s/x509-certificate-trust-chain-n/{0}" % self.focus_url
            func_count = (
                lib_db.get.get__X509CertificateTrustChain__by_X509CertificateTrustedIdN__count
            )
            func_paginated = (
                lib_db.get.get__X509CertificateTrustChain__by_X509CertificateTrustedIdN__paginated
            )
            accessor = "n"

        items_count = func_count(self.request.api_context, dbX509CertificateTrusted.id)
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = func_paginated(
            self.request.api_context,
            dbX509CertificateTrusted.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "X509CertificateTrusted": dbX509CertificateTrusted,
            "X509CertificateTrustChains_count": items_count,
            "X509CertificateTrustChains": items_paged,
            "accessor": accessor,
            "pager": pager,
        }


class View_New(Handler):
    @view_config(route_name="admin:x509_certificate_trusted:upload_cert")
    @view_config(
        route_name="admin:x509_certificate_trusted:upload_cert|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-ca/upload-cert.json",
            "section": "certificate-ca",
            "about": """X509CertificateTrusted upload certificate""",
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
            "/admin/x509_certificate_trusted-upload_cert.mako", {}, self.request
        )

    def _upload_cert__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_X509CertificateTrusted_Upload_Cert__file,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            cert_pem = formhandling.slurp_file_field(formStash, "cert_file")
            if not isinstance(cert_pem, str):
                cert_pem = cert_pem.decode("utf8")

            cert_file_name = formStash.results["cert_file_name"] or "manual upload"
            (
                dbX509CertificateTrusted,
                _is_created,
            ) = lib_db.getcreate.getcreate__X509CertificateTrusted__by_pem_text(
                self.request.api_context,
                cert_pem,
                display_name=cert_file_name,
                discovery_type="upload",
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "X509CertificateTrusted": {
                        "created": _is_created,
                        "id": dbX509CertificateTrusted.id,
                    },
                }
            return HTTPSeeOther(
                "%s/certificate-ca/%s?result=success&is_created=%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbX509CertificateTrusted.id,
                    (1 if _is_created else 0),
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload_cert__submit)
