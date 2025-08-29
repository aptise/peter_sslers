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
from ..lib.forms import Form_X509CertificateTrustChain_Upload__file
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import X509CertificateTrustChain


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:x509_certificate_trust_chains",
        renderer="/admin/x509_certificate_trust_chains.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trust_chains-paginated",
        renderer="/admin/x509_certificate_trust_chains.mako",
    )
    @view_config(route_name="admin:x509_certificate_trust_chains|json", renderer="json")
    @view_config(
        route_name="admin:x509_certificate_trust_chains-paginated|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/x509-certificate-trust-chain.json",
            "section": "certificate-trust-chain",
            "about": """list X509CertificateTrustChain(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate-trust-chain.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate-trust-chain/{PAGE}.json",
            "section": "certificate-trust-chain",
            "example": "curl {ADMIN_PREFIX}/x509-certificate-trust-chain/1.json",
            "variant_of": "/x509-certificate-trust-chain.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__X509CertificateTrustChain__count(
            self.request.api_context
        )
        url_template = (
            "%s/x509-certificate-trust-chain/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__X509CertificateTrustChain__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _chains = {c.id: c.as_json for c in items_paged}
            return {
                "X509CertificateTrustChains": _chains,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "X509CertificateTrustChains_count": items_count,
            "X509CertificateTrustChains": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbX509CertificateTrustChain: Optional[X509CertificateTrustChain] = None

    def _focus(self) -> X509CertificateTrustChain:
        if self.dbX509CertificateTrustChain is None:
            dbX509CertificateTrustChain = (
                lib_db.get.get__X509CertificateTrustChain__by_id(
                    self.request.api_context, self.request.matchdict["id"]
                )
            )
            if not dbX509CertificateTrustChain:
                raise HTTPNotFound("the chain was not found")
            self.dbX509CertificateTrustChain = dbX509CertificateTrustChain
            self.focus_item = dbX509CertificateTrustChain
            self.focus_url = "%s/certificate-trust-chain/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbX509CertificateTrustChain.id,
            )
        return self.dbX509CertificateTrustChain

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_trust_chain:focus",
        renderer="/admin/x509_certificate_trust_chain-focus.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_trust_chain:focus|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-trust-chain/{ID}.json",
            "section": "certificate-trust-chain",
            "about": """X509CertificateTrustChain focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-trust-chain/1.json",
        }
    )
    def focus(self):
        dbX509CertificateTrustChain = self._focus()
        if self.request.wants_json:
            return {
                "X509CertificateTrustChain": dbX509CertificateTrustChain.as_json,
            }
        return {
            "project": "peter_sslers",
            "X509CertificateTrustChain": dbX509CertificateTrustChain,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_trust_chain:focus:raw", renderer="string"
    )
    @docify(
        {
            "endpoint": "/certificate-trust-chain/{ID}/chain.pem",
            "section": "certificate-trust-chain",
            "about": """X509CertificateTrustChain focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-trust-chain/1/chain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-trust-chain/{ID}/chain.pem.txt",
            "section": "certificate-trust-chain",
            "about": """X509CertificateTrustChain focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-trust-chain/1/chain.pem.txt",
        }
    )
    def focus_raw(self):
        """
        for extensions, see `cert_utils.EXTENSION_TO_MIME`
        """
        # TODO - support cer format
        # only able to read, not write, with cryptography right now
        dbX509CertificateTrustChain = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbX509CertificateTrustChain.chain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbX509CertificateTrustChain.chain_pem
        return "UNSUPPORTED FORMAT"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_New(Handler):
    @view_config(route_name="admin:x509_certificate_trust_chain:upload_chain")
    @view_config(
        route_name="admin:x509_certificate_trust_chain:upload_chain|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/certificate-trust-chain/upload.json",
            "section": "certificate-trust-chain",
            "about": """upload a X509CertificateTrustChain""",
            "POST": True,
            "GET": None,
            "instructions": """curl {ADMIN_PREFIX}/certificate-trust-chain/upload-chain.json""",
            "example": """curl """
            """--form 'chain_file=@chain1.pem' """
            """{ADMIN_PREFIX}/certificate-trust-chain/upload-chain.json""",
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
            return formatted_get_docs(self, "/certificate-trust-chain/upload.json")
        return render_to_response(
            "/admin/x509_certificate_trust_chain-upload_chain.mako", {}, self.request
        )

    def _upload_chain__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_X509CertificateTrustChain_Upload__file,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            chain_pem = formhandling.slurp_file_field(formStash, "chain_file")
            if not isinstance(chain_pem, str):
                chain_pem = chain_pem.decode("utf8")

            chain_file_name = formStash.results["chain_file_name"]
            (
                dbX509CertificateTrustChain,
                _is_created,
            ) = lib_db.getcreate.getcreate__X509CertificateTrustChain__by_pem_text(
                self.request.api_context,
                chain_pem,
                display_name=chain_file_name,
                discovery_type="upload",
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "X509CertificateTrustChain": {
                        "created": _is_created,
                        "id": dbX509CertificateTrustChain.id,
                    },
                }
            return HTTPSeeOther(
                "%s/certificate-trust-chain/%s?result=success&is_created=%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbX509CertificateTrustChain.id,
                    (1 if _is_created else 0),
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload_chain__submit)
