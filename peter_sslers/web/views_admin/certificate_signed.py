# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime
import tempfile
import time
import zipfile

# pypi
import six
import sqlalchemy

# localapp
from .. import lib
from ..lib import form_utils as form_utils
from ..lib import formhandling
from ..lib.forms import Form_CertificateSigned_mark
from ..lib.forms import Form_Certificate_Upload__file
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import errors
from ...lib import events
from ...lib import db as lib_db
from ...lib import cert_utils
from ...lib import letsencrypt_info
from ...lib import utils
from ...lib import utils_nginx
from ...model import utils as model_utils


# ==============================================================================


def archive_zipfile(dbCertificateSigned, ca_cert_id=None):
    if ca_cert_id is None:
        ca_cert_id = dbCertificateSigned.certificate_ca_id__preferred

    now = time.localtime(time.time())[:6]
    tmpfile = tempfile.SpooledTemporaryFile()
    with zipfile.ZipFile(tmpfile, "w") as archive:
        # `cert1.pem`
        info = zipfile.ZipInfo("cert%s.pem" % dbCertificateSigned.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, dbCertificateSigned.cert_pem)

        # `chain1.pem`
        info = zipfile.ZipInfo("chain%s.pem" % dbCertificateSigned.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(
            info, dbCertificateSigned.valid_cert_chain_pem(ca_cert_id=ca_cert_id)
        )
        # `fullchain1.pem`
        info = zipfile.ZipInfo("fullchain%s.pem" % dbCertificateSigned.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(
            info, dbCertificateSigned.valid_cert_fullchain_pem(ca_cert_id=ca_cert_id)
        )
        # `privkey1.pem`
        info = zipfile.ZipInfo("privkey%s.pem" % dbCertificateSigned.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, dbCertificateSigned.private_key.key_pem)
    tmpfile.seek(0)
    return tmpfile


class View_List(Handler):
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signeds",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(route_name="admin:certificate_signeds|json", renderer="json")
    def list_redirect(self):
        url_redirect = (
            "%s/certificate-signeds/active"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_redirect = "%s.json" % url_redirect
        return HTTPSeeOther(url_redirect)

    @view_config(
        route_name="admin:certificate_signeds:all",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:certificate_signeds:all_paginated",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:certificate_signeds:active",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:certificate_signeds:active_paginated",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:certificate_signeds:expiring",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:certificate_signeds:expiring_paginated",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:certificate_signeds:inactive",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(
        route_name="admin:certificate_signeds:inactive_paginated",
        renderer="/admin/certificate_signeds.mako",
    )
    @view_config(route_name="admin:certificate_signeds:all|json", renderer="json")
    @view_config(
        route_name="admin:certificate_signeds:all_paginated|json", renderer="json"
    )
    @view_config(route_name="admin:certificate_signeds:active|json", renderer="json")
    @view_config(
        route_name="admin:certificate_signeds:active_paginated|json", renderer="json"
    )
    @view_config(route_name="admin:certificate_signeds:expiring|json", renderer="json")
    @view_config(
        route_name="admin:certificate_signeds:expiring_paginated|json", renderer="json"
    )
    @view_config(route_name="admin:certificate_signeds:inactive|json", renderer="json")
    @view_config(
        route_name="admin:certificate_signeds:inactive_paginated|json", renderer="json"
    )
    def list(self):
        expiring_days = self.request.registry.settings["app_settings"]["expiring_days"]
        if self.request.matched_route.name in (
            "admin:certificate_signeds:expiring",
            "admin:certificate_signeds:expiring_paginated",
            "admin:certificate_signeds:expiring|json",
            "admin:certificate_signeds:expiring_paginated|json",
        ):
            sidenav_option = "expiring"
            url_template = (
                "%s/certificate-signeds/expiring/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__CertificateSigned__count(
                self.request.api_context, expiring_days=expiring_days
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__CertificateSigned__paginated(
                self.request.api_context,
                expiring_days=expiring_days,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:certificate_signeds:active",
            "admin:certificate_signeds:active_paginated",
            "admin:certificate_signeds:active|json",
            "admin:certificate_signeds:active_paginated|json",
        ):
            sidenav_option = "active"
            url_template = (
                "%s/certificate-signeds/active/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__CertificateSigned__count(
                self.request.api_context, is_active=True
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__CertificateSigned__paginated(
                self.request.api_context,
                is_active=True,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:certificate_signeds:inactive",
            "admin:certificate_signeds:inactive_paginated",
            "admin:certificate_signeds:inactive|json",
            "admin:certificate_signeds:inactive_paginated|json",
        ):
            sidenav_option = "inactive"
            url_template = (
                "%s/certificate-signeds/active/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__CertificateSigned__count(
                self.request.api_context, is_active=False
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__CertificateSigned__paginated(
                self.request.api_context,
                is_active=False,
                limit=items_per_page,
                offset=offset,
            )
        else:
            sidenav_option = "all"
            url_template = (
                "%s/certificate-signeds/all/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__CertificateSigned__count(
                self.request.api_context
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__CertificateSigned__paginated(
                self.request.api_context,
                limit=items_per_page,
                offset=offset,
                eagerload_web=True,
            )
        if self.request.matched_route.name.endswith("|json"):
            _certificates = {c.id: c.as_json for c in items_paged}
            return {
                "CertificateSigneds": _certificates,
                "pagination": json_pagination(items_count, pager),
            }

        return {
            "project": "peter_sslers",
            "CertificateSigneds_count": items_count,
            "CertificateSigneds": items_paged,
            "sidenav_option": sidenav_option,
            "expiring_days": expiring_days,
            "pager": pager,
        }


class View_New(Handler):
    @view_config(route_name="admin:certificate_signed:upload")
    @view_config(route_name="admin:certificate_signed:upload|json", renderer="json")
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        if self.request.wants_json:
            return {
                "instructions": """curl --form 'private_key_file_pem=@privkey1.pem' --form 'certificate_file=@cert1.pem' --form 'chain_file=@chain1.pem' %s/certificate-signed/upload.json"""
                % self.request.admin_url,
                "form_fields": {
                    "private_key_file_pem": "required",
                    "chain_file": "required",
                    "certificate_file": "required",
                },
            }
        return render_to_response(
            "/admin/certificate_signed-upload.mako", {}, self.request
        )

    def _upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Certificate_Upload__file, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            private_key_pem = formhandling.slurp_file_field(
                formStash, "private_key_file_pem"
            )
            if six.PY3:
                if not isinstance(private_key_pem, str):
                    private_key_pem = private_key_pem.decode("utf8")
            (
                dbPrivateKey,
                pkey_is_created,
            ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                self.request.api_context,
                private_key_pem,
                private_key_source_id=model_utils.PrivateKeySource.from_string(
                    "imported"
                ),
                private_key_type_id=model_utils.PrivateKeyType.from_string("standard"),
            )
            ca_chain_pem = formhandling.slurp_file_field(formStash, "chain_file")
            if six.PY3:
                if not isinstance(ca_chain_pem, str):
                    ca_chain_pem = ca_chain_pem.decode("utf8")
            (
                dbCertificateCA,
                cacert_is_created,
            ) = lib_db.getcreate.getcreate__CertificateCA__by_pem_text(
                self.request.api_context, ca_chain_pem, display_name="manual upload"
            )

            certificate_pem = formhandling.slurp_file_field(
                formStash, "certificate_file"
            )
            if six.PY3:
                if not isinstance(certificate_pem, str):
                    certificate_pem = certificate_pem.decode("utf8")

            _tmpfileCert = None
            try:
                _tmpfileCert = cert_utils.new_pem_tempfile(certificate_pem)
                _certificate_domain_names = cert_utils.parse_cert__domains(
                    cert_pem=certificate_pem,
                    cert_pem_filepath=_tmpfileCert.name,
                )
                if not _certificate_domain_names:
                    raise ValueError(
                        "could not find any domain names in the certificate"
                    )
                (
                    dbUniqueFQDNSet,
                    is_created_fqdn,
                ) = lib_db.getcreate.getcreate__UniqueFQDNSet__by_domains(
                    self.request.api_context, _certificate_domain_names
                )
            except Exception as exc:
                raise
            finally:
                if _tmpfileCert:
                    _tmpfileCert.close()

            (
                dbCertificateSigned,
                cert_is_created,
            ) = lib_db.getcreate.getcreate__CertificateSigned(
                self.request.api_context,
                certificate_pem,
                cert_domains_expected=_certificate_domain_names,
                dbCertificateCA=dbCertificateCA,
                dbUniqueFQDNSet=dbUniqueFQDNSet,
                dbPrivateKey=dbPrivateKey,
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "CertificateSigned": {
                        "created": cert_is_created,
                        "id": dbCertificateSigned.id,
                        "url": "%s/certificate-signed/%s"
                        % (
                            self.request.registry.settings["app_settings"][
                                "admin_prefix"
                            ],
                            dbCertificateSigned.id,
                        ),
                    },
                    "CertificateCA": {
                        "created": cacert_is_created,
                        "id": dbCertificateCA.id,
                    },
                    "PrivateKey": {"created": pkey_is_created, "id": dbPrivateKey.id},
                }
            return HTTPSeeOther(
                "%s/certificate-signed/%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbCertificateSigned.id,
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)


class View_Focus(Handler):
    def _focus(self):
        dbCertificateSigned = lib_db.get.get__CertificateSigned__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbCertificateSigned:
            raise HTTPNotFound("invalid CertificateSigned")
        self._focus_item = dbCertificateSigned
        self._focus_url = "%s/certificate-signed/%s" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            dbCertificateSigned.id,
        )
        return dbCertificateSigned

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus",
        renderer="/admin/certificate_signed-focus.mako",
    )
    @view_config(route_name="admin:certificate_signed:focus|json", renderer="json")
    def focus(self):
        dbCertificateSigned = self._focus()
        if self.request.wants_json:
            return {"CertificateSigned": dbCertificateSigned.as_json}
        # x-x509-server-cert
        return {"project": "peter_sslers", "CertificateSigned": dbCertificateSigned}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:parse|json", renderer="json"
    )
    def parse_json(self):
        dbCertificateSigned = self._focus()
        return {
            "CertificateSigned": {
                "id": dbCertificateSigned.id,
                "parsed": cert_utils.parse_cert(cert_pem=dbCertificateSigned.cert_pem),
            }
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:chain:raw", renderer="string"
    )
    def chain(self):
        dbCertificateSigned = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateSigned.cert_chain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateSigned.cert_chain_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbCertificateSigned.cert_chain_pem
            )
            response = Response()
            if self.request.matchdict["format"] in ("crt", "der"):
                response.content_type = "application/x-x509-ca-cert"
            elif self.request.matchdict["format"] in ("cer",):
                response.content_type = "application/pkix-cert"
            response.body = as_der
            return response
        return "chain.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:fullchain:raw", renderer="string"
    )
    def fullchain(self):
        dbCertificateSigned = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateSigned.cert_fullchain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateSigned.cert_fullchain_pem
        return "fullchain.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:privatekey:raw", renderer="string"
    )
    def privatekey(self):
        dbCertificateSigned = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateSigned.private_key.key_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateSigned.private_key.key_pem
        elif self.request.matchdict["format"] == "key":
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbCertificateSigned.private_key.key_pem
            )
            response = Response()
            response.content_type = "application/pkcs8"
            response.body = as_der
            return response
        return "privatekey.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:cert:raw", renderer="string"
    )
    def cert(self):
        dbCertificateSigned = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateSigned.cert_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateSigned.cert_pem
        elif self.request.matchdict["format"] == "crt":
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbCertificateSigned.cert_pem
            )
            response = Response()
            response.content_type = "application/x-x509-server-cert"
            response.body = as_der
            return response
        return "cert.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:config|json", renderer="json"
    )
    def config_json(self):
        dbCertificateSigned = self._focus()
        if self.request.params.get("idonly", None):
            rval = dbCertificateSigned.config_payload_idonly
        else:
            rval = dbCertificateSigned.config_payload
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_signed:focus:config|zip")
    def config_zip(self):
        """
        generates a certbot style configuration
        note: there is no renderer, because we generate a `Response`
        """
        dbCertificateSigned = self._focus()
        try:
            tmpfile = archive_zipfile(dbCertificateSigned)
            response = Response(
                content_type="application/zip", body_file=tmpfile, status=200
            )
            response.headers["Content-Disposition"] = (
                "attachment; filename= cert%s.zip" % dbCertificateSigned.id
            )
            return response

        except Exception as exc:
            return HTTPSeeOther(
                "%s?result=error&error=could+not+generate+zipfile" % self._focus_url
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:queue_certificates",
        renderer="/admin/certificate_signed-focus-queue_certificates.mako",
    )
    @view_config(
        route_name="admin:certificate_signed:focus:queue_certificates_paginated",
        renderer="/admin/certificate_signed-focus-queue_certificates.mako",
    )
    def related__QueueCertificates(self):
        dbCertificateSigned = self._focus()
        items_count = lib_db.get.get__QueueCertificate__by_UniqueFQDNSetId__count(
            self.request.api_context, dbCertificateSigned.unique_fqdn_set_id
        )
        url_template = "%s/queue-certificates/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__QueueCertificate__by_UniqueFQDNSetId__paginated(
            self.request.api_context,
            dbCertificateSigned.unique_fqdn_set_id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "CertificateSigned": dbCertificateSigned,
            "QueueCertificates_count": items_count,
            "QueueCertificates": items_paged,
            "pager": pager,
        }


class View_Focus_via_CaCert(View_Focus):
    def _focus_via_CaCert(self):
        dbCertificateSigned = self._focus()
        id_cacert = int(self.request.matchdict["id_cacert"])
        if id_cacert not in dbCertificateSigned.valid_certificate_upchain_ids:
            raise HTTPNotFound("invalid CaCertificate")
        return (dbCertificateSigned, id_cacert)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:via_ca_cert:config|json",
        renderer="json",
    )
    def config_json(self):
        (dbCertificateSigned, id_cacert) = self._focus_via_CaCert()
        if self.request.params.get("idonly", None):
            rval = dbCertificateSigned.custom_config_payload(
                ca_cert_id=id_cacert, id_only=True
            )
        else:
            rval = dbCertificateSigned.custom_config_payload(
                ca_cert_id=id_cacert, id_only=False
            )
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_signed:focus:via_ca_cert:config|zip")
    def config_zip(self):
        (dbCertificateSigned, id_cacert) = self._focus_via_CaCert()
        try:
            tmpfile = archive_zipfile(dbCertificateSigned, ca_cert_id=id_cacert)
            response = Response(
                content_type="application/zip", body_file=tmpfile, status=200
            )
            response.headers[
                "Content-Disposition"
            ] = "attachment; filename= cert%s-chain%s.zip" % (
                dbCertificateSigned.id,
                id_cacert,
            )
            return response

        except Exception as exc:
            return HTTPSeeOther(
                "%s?result=error&error=could+not+generate+zipfile" % self._focus_url
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:via_ca_cert:chain:raw",
        renderer="string",
    )
    def chain(self):
        (dbCertificateSigned, id_cacert) = self._focus_via_CaCert()
        cert_chain_pem = dbCertificateSigned.valid_cert_chain_pem(id_cacert)
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return cert_chain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return cert_chain_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(pem_data=cert_chain_pem)
            response = Response()
            if self.request.matchdict["format"] in ("crt", "der"):
                response.content_type = "application/x-x509-ca-cert"
            elif self.request.matchdict["format"] in ("cer",):
                response.content_type = "application/pkix-cert"
            response.body = as_der
            return response
        return "chain.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:via_ca_cert:fullchain:raw",
        renderer="string",
    )
    def fullchain(self):
        (dbCertificateSigned, id_cacert) = self._focus_via_CaCert()
        cert_fullchain_pem = dbCertificateSigned.valid_cert_fullchain_pem(id_cacert)
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return cert_fullchain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return cert_fullchain_pem
        return "fullchain.pem"


class View_Focus_Manipulate(View_Focus):
    @view_config(
        route_name="admin:certificate_signed:focus:nginx_cache_expire", renderer=None
    )
    @view_config(
        route_name="admin:certificate_signed:focus:nginx_cache_expire|json",
        renderer="json",
    )
    def nginx_expire(self):
        dbCertificateSigned = self._focus()
        if not self.request.registry.settings["app_settings"]["enable_nginx"]:
            raise HTTPSeeOther("%s?result=error&error=no+nginx" % self._focus_url)
        dbDomains = [
            c2d.domain for c2d in dbCertificateSigned.unique_fqdn_set.to_domains
        ]

        # this will generate it's own log__OperationsEvent
        success, dbEvent = utils_nginx.nginx_expire_cache(
            self.request, self.request.api_context, dbDomains=dbDomains
        )
        if self.request.wants_json:
            return {"result": "success", "operations_event": {"id": dbEvent.id}}
        return HTTPSeeOther(
            "%s?result=success&operation=nginx+cache+expire&event.id=%s"
            % (self._focus_url, dbEvent.id)
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_signed:focus:mark", renderer=None)
    @view_config(route_name="admin:certificate_signed:focus:mark|json", renderer="json")
    def mark(self):
        dbCertificateSigned = self._focus()
        if self.request.method == "POST":
            return self._mark__submit(dbCertificateSigned)
        return self._mark__print(dbCertificateSigned)

    def _mark__print(self, dbCertificateSigned):
        if self.request.wants_json:
            return {
                "instructions": [
                    """HTTP POST required""",
                    """curl --form 'action=active' %s/certificate-signed/1/mark.json"""
                    % self.request.admin_url,
                ],
                "form_fields": {"action": "the intended action"},
                "valid_options": {
                    "action": [
                        "active",
                        "inactive",
                        "revoked",
                        # "renew_manual",
                        # "renew_auto",
                        "unrevoke",
                    ]
                },
            }
        url_post_required = (
            "%s?result=error&error=post+required&operation=mark" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _mark__submit(self, dbCertificateSigned):
        action = None
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_CertificateSigned_mark, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["certificate_signed.id"] = dbCertificateSigned.id
            event_payload_dict["action"] = action
            event_type = model_utils.OperationsEventType.from_string(
                "CertificateSigned__mark"
            )

            update_recents = False
            unactivated = False
            activated = False
            event_status = False

            try:

                if action == "active":
                    event_status = lib_db.update.update_CertificateSigned__set_active(
                        self.request.api_context, dbCertificateSigned
                    )
                    update_recents = True
                    activated = True

                elif action == "inactive":
                    event_status = lib_db.update.update_CertificateSigned__unset_active(
                        self.request.api_context, dbCertificateSigned
                    )
                    update_recents = True
                    unactivated = True

                elif action == "revoked":
                    event_status = lib_db.update.update_CertificateSigned__set_revoked(
                        self.request.api_context, dbCertificateSigned
                    )
                    update_recents = True
                    unactivated = True
                    event_type = "CertificateSigned__revoke"

                # elif action == "renew_manual":
                #    event_status = lib_db.update.update_CertificateSigned__set_renew_manual(
                #        self.request.api_context, dbCertificateSigned
                #    )

                # elif action == "renew_auto":
                #    event_status = lib_db.update.update_CertificateSigned__set_renew_auto(
                #        self.request.api_context, dbCertificateSigned
                #    )

                elif action == "unrevoke":
                    raise errors.InvalidTransition("Invalid option: `unrevoke`")
                    """
                    event_status = lib_db.update.update_CertificateSigned__unset_revoked(
                        self.request.api_context, dbCertificateSigned
                    )
                    update_recents = True
                    activated = None
                    """

                else:
                    raise errors.InvalidTransition("Invalid option")

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

            self.request.api_context.dbSession.flush(objects=[dbCertificateSigned])

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type, event_payload_dict
            )
            lib_db.logger._log_object_event(
                self.request.api_context,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    event_status
                ),
                dbCertificateSigned=dbCertificateSigned,
            )

            if update_recents:
                event_update = lib_db.actions.operations_update_recents__global(
                    self.request.api_context
                )
                event_update.operations_event_id__child_of = dbOperationsEvent.id
                self.request.api_context.dbSession.flush(objects=[event_update])

            if unactivated:
                # this will handle requeuing
                events.Certificate_unactivated(
                    self.request.api_context, dbCertificateSigned
                )

            if activated:
                # nothing to do?
                pass

            if self.request.wants_json:
                return {
                    "result": "success",
                    "CertificateSigned": dbCertificateSigned.as_json,
                }
            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?&result=error&error=%s&operation=mark" % (
                self._focus_url,
                formStash.errors["Error_Main"].replace("\n", "+").replace(" ", "+"),
            )
            if action:
                url_failure = "%s&action=%s" % (url_failure, action)
            raise HTTPSeeOther(url_failure)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
