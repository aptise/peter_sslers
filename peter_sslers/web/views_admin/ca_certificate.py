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
from ..lib.forms import Form_CACertificate_Upload__file
from ..lib.forms import Form_CACertificate_UploadBundle__file
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import letsencrypt_info


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:ca_certificates", renderer="/admin/ca_certificates.mako"
    )
    @view_config(
        route_name="admin:ca_certificates_paginated",
        renderer="/admin/ca_certificates.mako",
    )
    @view_config(route_name="admin:ca_certificates|json", renderer="json")
    @view_config(route_name="admin:ca_certificates_paginated|json", renderer="json")
    def list(self):
        items_count = lib_db.get.get__CACertificate__count(self.request.api_context)
        url_template = (
            "%s/ca-certificates/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CACertificate__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _certs = {c.id: c.as_json for c in items_paged}
            return {
                "CACertificates": _certs,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "CACertificates_count": items_count,
            "CACertificates": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    def _focus(self):
        dbCACertificate = lib_db.get.get__CACertificate__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbCACertificate:
            raise HTTPNotFound("the cert was not found")
        self.focus_item = dbCACertificate
        self.focus_url = "%s/ca-certificate/%s" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            self.focus_item.id,
        )
        return dbCACertificate

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:ca_certificate:focus",
        renderer="/admin/ca_certificate-focus.mako",
    )
    @view_config(route_name="admin:ca_certificate:focus|json", renderer="json")
    def focus(self):
        dbCACertificate = self._focus()
        items_count = lib_db.get.get__ServerCertificate__by_CACertificateId__count(
            self.request.api_context, dbCACertificate.id
        )
        items_paged = lib_db.get.get__ServerCertificate__by_CACertificateId__paginated(
            self.request.api_context, dbCACertificate.id, limit=10, offset=0
        )
        items_paged_alt = (
            lib_db.get.get__ServerCertificate__by_CACertificateId__alt__paginated(
                self.request.api_context, dbCACertificate.id, limit=10, offset=0
            )
        )
        if self.request.wants_json:
            return {
                "CACertificate": dbCACertificate.as_json,
            }
        return {
            "project": "peter_sslers",
            "CACertificate": dbCACertificate,
            "ServerCertificates_count": items_count,
            "ServerCertificates": items_paged,
            "ServerCertificates_Alt": items_paged_alt,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:ca_certificate:focus:raw", renderer="string")
    def focus_raw(self):
        dbCACertificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCACertificate.cert_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCACertificate.cert_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(pem_data=dbCACertificate.cert_pem)
            response = Response()
            if self.request.matchdict["format"] in ("crt", "der"):
                response.content_type = "application/x-x509-ca-cert"
            elif self.request.matchdict["format"] in ("cer",):
                response.content_type = "application/pkix-cert"
            response.body = as_der
            return response
        return "chain.?"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:ca_certificate:focus:parse|json", renderer="json")
    def focus_parse_json(self):
        dbCACertificate = self._focus()
        return {
            "CACertificate": {
                "id": dbCACertificate.id,
                "parsed": cert_utils.parse_cert(cert_pem=dbCACertificate.cert_pem),
            }
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:ca_certificate:focus:server_certificates",
        renderer="/admin/ca_certificate-focus-server_certificates.mako",
    )
    @view_config(
        route_name="admin:ca_certificate:focus:server_certificates_paginated",
        renderer="/admin/ca_certificate-focus-server_certificates.mako",
    )
    def related__ServerCertificates(self):
        dbCACertificate = self._focus()
        items_count = lib_db.get.get__ServerCertificate__by_CACertificateId__count(
            self.request.api_context, dbCACertificate.id
        )
        url_template = "%s/server-certificates/{0}" % self.focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__ServerCertificate__by_CACertificateId__paginated(
            self.request.api_context,
            dbCACertificate.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "CACertificate": dbCACertificate,
            "ServerCertificates_count": items_count,
            "ServerCertificates": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:ca_certificate:focus:server_certificates_alt",
        renderer="/admin/ca_certificate-focus-server_certificates_alt.mako",
    )
    @view_config(
        route_name="admin:ca_certificate:focus:server_certificates_alt_paginated",
        renderer="/admin/ca_certificate-focus-server_certificates_alt.mako",
    )
    def related__ServerCertificatesAlt(self):
        dbCACertificate = self._focus()
        items_count = lib_db.get.get__ServerCertificate__by_CACertificateId__alt__count(
            self.request.api_context, dbCACertificate.id
        )
        url_template = "%s/server-certificates-alt/{0}" % self.focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = (
            lib_db.get.get__ServerCertificate__by_CACertificateId__alt__paginated(
                self.request.api_context,
                dbCACertificate.id,
                limit=items_per_page,
                offset=offset,
            )
        )
        return {
            "project": "peter_sslers",
            "CACertificate": dbCACertificate,
            "ServerCertificates_count": items_count,
            "ServerCertificates": items_paged,
            "pager": pager,
        }


class View_New(Handler):
    @view_config(route_name="admin:ca_certificate:upload")
    @view_config(route_name="admin:ca_certificate:upload|json", renderer="json")
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        if self.request.wants_json:
            return {
                "instructions": """curl --form 'chain_file=@chain1.pem' --form %s/ca-certificate/upload.json"""
                % self.request.admin_url,
                "form_fields": {"chain_file": "required"},
            }
        return render_to_response("/admin/ca_certificate-upload.mako", {}, self.request)

    def _upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_CACertificate_Upload__file, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            ca_chain_pem = formhandling.slurp_file_field(formStash, "chain_file")
            if six.PY3:
                if not isinstance(ca_chain_pem, str):
                    ca_chain_pem = ca_chain_pem.decode("utf8")

            chain_file_name = formStash.results["chain_file_name"] or "manual upload"
            (
                dbCACertificate,
                cacert_is_created,
            ) = lib_db.getcreate.getcreate__CACertificate__by_pem_text(
                self.request.api_context, ca_chain_pem, ca_chain_name=chain_file_name
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "CACertificate": {
                        "created": cacert_is_created,
                        "id": dbCACertificate.id,
                    },
                }
            return HTTPSeeOther(
                "%s/ca-certificate/%s?result=success&is_created=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbCACertificate.id,
                    (1 if cacert_is_created else 0),
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:ca_certificate:upload_bundle")
    @view_config(route_name="admin:ca_certificate:upload_bundle|json", renderer="json")
    def upload_bundle(self):
        if self.request.method == "POST":
            return self._upload_bundle__submit()
        return self._upload_bundle__print()

    def _upload_bundle__print(self):
        if self.request.wants_json:
            _instructions = ["curl --form 'isrgrootx1_file=@isrgrootx1.pem'"]
            _form_fields = {"isrgrootx1_file": "optional"}
            for xi in letsencrypt_info.CA_CROSS_SIGNED_X:
                _instructions.append(
                    """--form 'le_%s_cross_signed_file=@lets-encrypt-%s-cross-signed.pem'"""
                    % (xi, xi)
                )
                _form_fields["le_%s_cross_signed_file" % xi] = "optional"
            for xi in letsencrypt_info.CA_AUTH_X:
                _instructions.append(
                    """--form 'le_%s_auth_file=@letsencryptauthority%s'""" % (xi, xi)
                )
                _form_fields["le_%s_auth_file" % xi] = "optional"
            # and the post
            _instructions.append(
                """%s/ca-certificate/upload-bundle.json""" % self.request.admin_url
            )

            return {
                "instructions": " ".join(_instructions),
                "form_fields": _form_fields,
            }
        return render_to_response(
            "/admin/ca_certificate-new_bundle.mako",
            {
                "CA_CROSS_SIGNED_X": letsencrypt_info.CA_CROSS_SIGNED_X,
                "CA_AUTH_X": letsencrypt_info.CA_AUTH_X,
            },
            self.request,
        )

    def _upload_bundle__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CACertificate_UploadBundle__file,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()
            has_uploads = [i for i in formStash.results.values() if i is not None]
            if not has_uploads:
                # `formStash.fatal_form()` will raise `FormInvalid()`
                formStash.fatal_form("Nothing uploaded!")

            bundle_data = {"isrgrootx1_pem": None}
            if formStash.results["isrgrootx1_file"] is not None:
                bundle_data["isrgrootx1_pem"] = formhandling.slurp_file_field(
                    formStash, "isrgrootx1_file"
                )
                if six.PY3:
                    if not isinstance(bundle_data["isrgrootx1_pem"], str):
                        bundle_data["isrgrootx1_pem"] = bundle_data[
                            "isrgrootx1_pem"
                        ].decode("utf8")

            for xi in letsencrypt_info.CA_CROSS_SIGNED_X:
                _bd_key = "le_%s_cross_signed_pem" % xi
                bundle_data[_bd_key] = None
                if formStash.results["le_%s_cross_signed_file" % xi] is not None:
                    bundle_data[_bd_key] = formhandling.slurp_file_field(
                        formStash, "le_%s_cross_signed_file" % xi
                    )
                    if six.PY3:
                        if not isinstance(bundle_data[_bd_key], str):
                            bundle_data[_bd_key] = bundle_data[_bd_key].decode("utf8")

            for xi in letsencrypt_info.CA_AUTH_X:
                _bd_key = "le_%s_auth_pem" % xi
                bundle_data[_bd_key] = None
                if formStash.results["le_%s_auth_file" % xi] is not None:
                    bundle_data[_bd_key] = formhandling.slurp_file_field(
                        formStash, "le_%s_auth_file" % xi
                    )
                    if six.PY3:
                        if not isinstance(bundle_data[_bd_key], str):
                            bundle_data[_bd_key] = bundle_data[_bd_key].decode("utf8")

            bundle_data = dict([i for i in bundle_data.items() if i[1]])

            dbResults = lib_db.actions.upload__CACertificateBundle__by_pem_text(
                self.request.api_context, bundle_data
            )

            if self.request.wants_json:
                rval = {"result": "success"}
                for (cert_type, cert_result) in dbResults.items():
                    rval[cert_type] = {
                        "created": cert_result[1],
                        "id": cert_result[0].id,
                    }
                return rval
            return HTTPSeeOther(
                "%s/ca-certificates?uploaded=1"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload_bundle__print)
