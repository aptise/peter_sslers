# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import six
import sqlalchemy

# localapp
from .. import lib
from ..lib import formhandling
from ..lib.forms import Form_CertificateCAChain_Upload__file
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import errors
from ...lib import letsencrypt_info


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:certificate_ca_chains",
        renderer="/admin/certificate_ca_chains.mako",
    )
    @view_config(
        route_name="admin:certificate_ca_chains_paginated",
        renderer="/admin/certificate_ca_chains.mako",
    )
    @view_config(route_name="admin:certificate_ca_chains|json", renderer="json")
    @view_config(
        route_name="admin:certificate_ca_chains_paginated|json", renderer="json"
    )
    def list(self):
        items_count = lib_db.get.get__CertificateCAChain__count(
            self.request.api_context
        )
        url_template = (
            "%s/certificate-ca-chains/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
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
    def _focus(self):
        dbCertificateCAChain = lib_db.get.get__CertificateCAChain__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbCertificateCAChain:
            raise HTTPNotFound("the chain was not found")
        self.focus_item = dbCertificateCAChain
        self.focus_url = "%s/certificate-ca-chain/%s" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            self.focus_item.id,
        )
        return dbCertificateCAChain

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_ca_chain:focus",
        renderer="/admin/certificate_ca_chain-focus.mako",
    )
    @view_config(route_name="admin:certificate_ca_chain:focus|json", renderer="json")
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
    def focus_raw(self):
        dbCertificateCAChain = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateCAChain.chain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateCAChain.chain_pem
        return "chain.?"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class View_New(Handler):
    @view_config(route_name="admin:certificate_ca_chain:upload_chain")
    @view_config(
        route_name="admin:certificate_ca_chain:upload_chain|json", renderer="json"
    )
    def upload_chain(self):
        if self.request.method == "POST":
            return self._upload_chain__submit()
        return self._upload_chain__print()

    def _upload_chain__print(self):
        if self.request.wants_json:
            return {
                "instructions": """curl --form 'chain_file=@chain1.pem' --form %s/certificate-ca-chain/upload-chain.json"""
                % self.request.admin_url,
                "form_fields": {"chain_file": "required"},
            }
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
                raise formhandling.FormInvalid()

            chain_pem = formhandling.slurp_file_field(formStash, "chain_file")
            if six.PY3:
                if not isinstance(chain_pem, str):
                    chain_pem = chain_pem.decode("utf8")

            chain_file_name = formStash.results["chain_file_name"] or "manual upload"
            (
                dbCertificateCAChain,
                _is_created,
            ) = lib_db.getcreate.getcreate__CertificateCAChain__by_pem_text(
                self.request.api_context, chain_pem, display_name=chain_file_name
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
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbCertificateCAChain.id,
                    (1 if _is_created else 0),
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload_chain__submit)
