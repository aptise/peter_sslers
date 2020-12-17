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
from ..lib.forms import Form_CertificateCA_Upload__file
from ..lib.forms import Form_CertificateCA_UploadBundle__file
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import letsencrypt_info


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:certificate_cas", renderer="/admin/certificate_cas.mako"
    )
    @view_config(
        route_name="admin:certificate_cas_paginated",
        renderer="/admin/certificate_cas.mako",
    )
    @view_config(route_name="admin:certificate_cas|json", renderer="json")
    @view_config(route_name="admin:certificate_cas_paginated|json", renderer="json")
    def list(self):
        items_count = lib_db.get.get__CertificateCA__count(self.request.api_context)
        url_template = (
            "%s/certificate-cas/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
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
    def _focus(self):
        dbCertificateCA = lib_db.get.get__CertificateCA__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbCertificateCA:
            raise HTTPNotFound("the cert was not found")
        self.focus_item = dbCertificateCA
        self.focus_url = "%s/certificate-ca/%s" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            self.focus_item.id,
        )
        return dbCertificateCA

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_ca:focus",
        renderer="/admin/certificate_ca-focus.mako",
    )
    @view_config(route_name="admin:certificate_ca:focus|json", renderer="json")
    def focus(self):
        dbCertificateCA = self._focus()
        items_count = lib_db.get.get__CertificateSigned__by_CertificateCAId__count(
            self.request.api_context, dbCertificateCA.id
        )
        items_paged = lib_db.get.get__CertificateSigned__by_CertificateCAId__paginated(
            self.request.api_context, dbCertificateCA.id, limit=10, offset=0
        )
        items_paged_alt = (
            lib_db.get.get__CertificateSigned__by_CertificateCAId__alt__paginated(
                self.request.api_context, dbCertificateCA.id, limit=10, offset=0
            )
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
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_ca:focus:raw", renderer="string")
    def focus_raw(self):
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
        return "chain.?"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_ca:focus:parse|json", renderer="json")
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
        route_name="admin:certificate_ca:focus:certificate_signeds_paginated",
        renderer="/admin/certificate_ca-focus-certificate_signeds.mako",
    )
    def related__CertificateSigneds(self):
        dbCertificateCA = self._focus()
        items_count = lib_db.get.get__CertificateSigned__by_CertificateCAId__count(
            self.request.api_context, dbCertificateCA.id
        )
        url_template = "%s/certificate-signeds/{0}" % self.focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateSigned__by_CertificateCAId__paginated(
            self.request.api_context,
            dbCertificateCA.id,
            limit=items_per_page,
            offset=offset,
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
        route_name="admin:certificate_ca:focus:certificate_signeds_alt_paginated",
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


class View_New(Handler):
    @view_config(route_name="admin:certificate_ca:upload")
    @view_config(route_name="admin:certificate_ca:upload|json", renderer="json")
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        if self.request.wants_json:
            return {
                "instructions": """curl --form 'chain_file=@chain1.pem' --form %s/certificate-ca/upload.json"""
                % self.request.admin_url,
                "form_fields": {"chain_file": "required"},
            }
        return render_to_response("/admin/certificate_ca-upload.mako", {}, self.request)

    def _upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_CertificateCA_Upload__file, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            ca_chain_pem = formhandling.slurp_file_field(formStash, "chain_file")
            if six.PY3:
                if not isinstance(ca_chain_pem, str):
                    ca_chain_pem = ca_chain_pem.decode("utf8")

            chain_file_name = formStash.results["chain_file_name"] or "manual upload"
            (
                dbCertificateCA,
                cacert_is_created,
            ) = lib_db.getcreate.getcreate__CertificateCA__by_pem_text(
                self.request.api_context, ca_chain_pem, ca_chain_name=chain_file_name
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "CertificateCA": {
                        "created": cacert_is_created,
                        "id": dbCertificateCA.id,
                    },
                }
            return HTTPSeeOther(
                "%s/certificate-ca/%s?result=success&is_created=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbCertificateCA.id,
                    (1 if cacert_is_created else 0),
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_ca:upload_bundle")
    @view_config(route_name="admin:certificate_ca:upload_bundle|json", renderer="json")
    def upload_bundle(self):
        if self.request.method == "POST":
            return self._upload_bundle__submit()
        return self._upload_bundle__print()

    def _upload_bundle__print(self):
        if self.request.wants_json:
            _instructions = ["curl --form 'isrgrootx1_file=@isrgrootx1.pem'"]
            _form_fields = {"isrgrootx1_file": "optional"}
            for xi in letsencrypt_info.CA_LE_INTERMEDIATES_CROSSED:
                _instructions.append(
                    """--form 'le_%s_cross_file=@lets-encrypt-%s-cross-signed.pem'"""
                    % (xi, xi)
                )
                _form_fields["le_%s_cross_file" % xi] = "optional"
            for xi in letsencrypt_info.CA_LE_INTERMEDIATES:
                _instructions.append(
                    """--form 'le_int_%s_file=@letsencryptauthority%s'""" % (xi, xi)
                )
                _form_fields["le_int_%_file" % xi] = "optional"
            # and the post
            _instructions.append(
                """%s/certificate-ca/upload-bundle.json""" % self.request.admin_url
            )

            return {
                "instructions": " ".join(_instructions),
                "form_fields": _form_fields,
            }
        return render_to_response(
            "/admin/certificate_ca-new_bundle.mako",
            {
                "CA_LE_INTERMEDIATES_CROSSED": letsencrypt_info.CA_LE_INTERMEDIATES_CROSSED,
                "CA_LE_INTERMEDIATES": letsencrypt_info.CA_LE_INTERMEDIATES,
            },
            self.request,
        )

    def _upload_bundle__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CertificateCA_UploadBundle__file,
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

            for xi in letsencrypt_info.CA_LE_INTERMEDIATES_CROSSED:
                _bd_key = "le_%s_cross_signed_pem" % xi
                bundle_data[_bd_key] = None
                if formStash.results["le_%s_cross_file" % xi] is not None:
                    bundle_data[_bd_key] = formhandling.slurp_file_field(
                        formStash, "le_%s_cross_file" % xi
                    )
                    if six.PY3:
                        if not isinstance(bundle_data[_bd_key], str):
                            bundle_data[_bd_key] = bundle_data[_bd_key].decode("utf8")

            for xi in letsencrypt_info.CA_LE_INTERMEDIATES:
                _bd_key = "le_int_%s_pem" % xi
                bundle_data[_bd_key] = None
                if formStash.results["le_int_%s_file" % xi] is not None:
                    bundle_data[_bd_key] = formhandling.slurp_file_field(
                        formStash, "le_int_%s_file" % xi
                    )
                    if six.PY3:
                        if not isinstance(bundle_data[_bd_key], str):
                            bundle_data[_bd_key] = bundle_data[_bd_key].decode("utf8")

            bundle_data = dict([i for i in bundle_data.items() if i[1]])

            dbResults = lib_db.actions.upload__CertificateCABundle__by_pem_text(
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
                "%s/certificate-cas?uploaded=1"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload_bundle__print)
