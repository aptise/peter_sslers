# stdlib
from typing import Optional

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_CertificateCAChain_Upload__file
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import CertificateCAChain


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:certificate_ca_chains",
        renderer="/admin/certificate_ca_chains.mako",
    )
    @view_config(
        route_name="admin:certificate_ca_chains-paginated",
        renderer="/admin/certificate_ca_chains.mako",
    )
    @view_config(route_name="admin:certificate_ca_chains|json", renderer="json")
    @view_config(
        route_name="admin:certificate_ca_chains-paginated|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-ca-chains.json",
            "section": "certificate-ca-chain",
            "about": """list CertificateCAChain(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca-chains.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca-chains/{PAGE}.json",
            "section": "certificate-ca-chain",
            "example": "curl {ADMIN_PREFIX}/certificate-ca-chains/1.json",
            "variant_of": "/certificate-ca-chains.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__CertificateCAChain__count(
            self.request.api_context
        )
        url_template = (
            "%s/certificate-ca-chains/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateCAChain__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _chains = {c.id: c.as_json for c in items_paged}
            return {
                "CertificateCAChains": _chains,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "CertificateCAChains_count": items_count,
            "CertificateCAChains": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbCertificateCAChain: Optional[CertificateCAChain] = None

    def _focus(self) -> CertificateCAChain:
        if self.dbCertificateCAChain is None:
            dbCertificateCAChain = lib_db.get.get__CertificateCAChain__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbCertificateCAChain:
                raise HTTPNotFound("the chain was not found")
            self.dbCertificateCAChain = dbCertificateCAChain
            self.focus_item = dbCertificateCAChain
            self.focus_url = "%s/certificate-ca-chain/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbCertificateCAChain.id,
            )
        return self.dbCertificateCAChain

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_ca_chain:focus",
        renderer="/admin/certificate_ca_chain-focus.mako",
    )
    @view_config(route_name="admin:certificate_ca_chain:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/certificate-ca-chain/{ID}.json",
            "section": "certificate-ca-chain",
            "about": """CertificateCAChain focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca-chain/1.json",
        }
    )
    def focus(self):
        dbCertificateCAChain = self._focus()
        if self.request.wants_json:
            return {
                "CertificateCAChain": dbCertificateCAChain.as_json,
            }
        return {
            "project": "peter_sslers",
            "CertificateCAChain": dbCertificateCAChain,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_ca_chain:focus:raw", renderer="string")
    @docify(
        {
            "endpoint": "/certificate-ca-chain/{ID}/chain.pem",
            "section": "certificate-ca-chain",
            "about": """CertificateCAChain focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca-chain/1/chain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-ca-chain/{ID}/chain.pem.txt",
            "section": "certificate-ca-chain",
            "about": """CertificateCAChain focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-ca-chain/1/chain.pem.txt",
        }
    )
    def focus_raw(self):
        """
        for extensions, see `cert_utils.EXTENSION_TO_MIME`
        """
        # TODO - support cer format
        # only able to read, not write, with cryptography right now
        dbCertificateCAChain = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateCAChain.chain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateCAChain.chain_pem
        return "UNSUPPORTED FORMAT"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_New(Handler):
    @view_config(route_name="admin:certificate_ca_chain:upload_chain")
    @view_config(
        route_name="admin:certificate_ca_chain:upload_chain|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-ca-chain/upload.json",
            "section": "certificate-ca-chain",
            "about": """upload a CertificateCAChain""",
            "POST": True,
            "GET": None,
            "instructions": """curl {ADMIN_PREFIX}/certificate-ca-chain/upload-chain.json""",
            "example": """curl """
            """--form 'chain_file=@chain1.pem' """
            """{ADMIN_PREFIX}/certificate-ca-chain/upload-chain.json""",
            "form_fields": {
                "chain_file": "required",
            },
        }
    )
    def upload_chain(self):
        if self.request.method == "POST":
            return self._upload_chain__submit()
        return self._upload_chain__print()

    def _upload_chain__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/certificate-ca-chain/upload.json")
        return render_to_response(
            "/admin/certificate_ca_chain-upload_chain.mako", {}, self.request
        )

    def _upload_chain__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CertificateCAChain_Upload__file,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            chain_pem = formhandling.slurp_file_field(formStash, "chain_file")
            if not isinstance(chain_pem, str):
                chain_pem = chain_pem.decode("utf8")

            chain_file_name = formStash.results["chain_file_name"]
            (
                dbCertificateCAChain,
                _is_created,
            ) = lib_db.getcreate.getcreate__CertificateCAChain__by_pem_text(
                self.request.api_context,
                chain_pem,
                display_name=chain_file_name,
                discovery_type="upload",
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "CertificateCAChain": {
                        "created": _is_created,
                        "id": dbCertificateCAChain.id,
                    },
                }
            return HTTPSeeOther(
                "%s/certificate-ca-chain/%s?result=success&is_created=%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbCertificateCAChain.id,
                    (1 if _is_created else 0),
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload_chain__submit)
