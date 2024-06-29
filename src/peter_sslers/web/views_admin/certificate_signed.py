# stdlib
import tempfile
import time
from typing import Optional
from typing import TYPE_CHECKING
import zipfile

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
from ..lib.forms import Form_Certificate_Upload__file
from ..lib.forms import Form_CertificateSigned_mark
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import events
from ...lib import utils
from ...lib import utils_nginx
from ...model import utils as model_utils
from ...model.objects import CertificateSigned


# ==============================================================================


def archive_zipfile(dbCertificateSigned, certificate_ca_chain_id=None):
    if certificate_ca_chain_id is None:
        certificate_ca_chain_id = dbCertificateSigned.certificate_ca_chain_id__preferred

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
            info,
            dbCertificateSigned.valid_cert_chain_pem(
                certificate_ca_chain_id=certificate_ca_chain_id
            ),
        )
        # `fullchain1.pem`
        info = zipfile.ZipInfo("fullchain%s.pem" % dbCertificateSigned.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(
            info,
            dbCertificateSigned.valid_cert_fullchain_pem(
                certificate_ca_chain_id=certificate_ca_chain_id
            ),
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
    @docify(
        {
            "endpoint": "/certificate-signeds/all.json",
            "section": "certificate-signed",
            "about": """list CertificateSigned(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signeds/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signeds/all/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/certificate-signeds/all/1.json",
            "variant_of": "/certificate-signeds/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signeds/active.json",
            "section": "certificate-signed",
            "about": """list CertificateSigned(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signeds/active.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signeds/active/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/certificate-signeds/active/1.json",
            "variant_of": "/certificate-signeds/active.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signeds/expiring.json",
            "section": "certificate-signed",
            "about": """list CertificateSigned(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signeds/expiring.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signeds/expiring/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/certificate-signeds/expiring/1.json",
            "variant_of": "/certificate-signeds/expiring.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signeds/inactive.json",
            "section": "certificate-signed",
            "about": """list CertificateSigned(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signeds/inactive.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signeds/inactive/{PAGE}.json",
            "section": "certificate-signed",
            "example": "curl {ADMIN_PREFIX}/certificate-signeds/inactive/1.json",
            "variant_of": "/certificate-signeds/expiring.json",
        }
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
    @docify(
        {
            "endpoint": "/certificate-signed/upload.json",
            "section": "certificate-signed",
            "about": """upload a CertificateSigned""",
            "POST": True,
            "GET": None,
            "instructions": """curl --form 'private_key_file_pem=@privkey1.pem' --form 'certificate_file=@cert1.pem' --form 'chain_file=@chain1.pem' {ADMIN_PREFIX}/certificate-signed/upload.json""",
            "form_fields": {
                "private_key_file_pem": "required",
                "chain_file": "required",
                "certificate_file": "required",
            },
        }
    )
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/certificate-signed/upload.json")
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
                discovery_type="via upload certificate_signed",
            )
            ca_chain_pem = formhandling.slurp_file_field(formStash, "chain_file")
            if not isinstance(ca_chain_pem, str):
                ca_chain_pem = ca_chain_pem.decode("utf8")
            (
                dbCertificateCAChain,
                chain_is_created,
            ) = lib_db.getcreate.getcreate__CertificateCAChain__by_pem_text(
                self.request.api_context,
                ca_chain_pem,
                discovery_type="upload",
            )

            certificate_pem = formhandling.slurp_file_field(
                formStash, "certificate_file"
            )
            if not isinstance(certificate_pem, str):
                certificate_pem = certificate_pem.decode("utf8")

            _tmpfileCert = None
            try:
                if cert_utils.NEEDS_TEMPFILES:
                    _tmpfileCert = cert_utils.new_pem_tempfile(certificate_pem)
                _certificate_domain_names = cert_utils.parse_cert__domains(
                    cert_pem=certificate_pem,
                    cert_pem_filepath=_tmpfileCert.name if _tmpfileCert else None,
                )
                if not _certificate_domain_names:
                    raise ValueError(
                        "could not find any domain names in the certificate"
                    )
                (
                    dbUniqueFQDNSet,
                    is_created_fqdn,
                ) = lib_db.getcreate.getcreate__UniqueFQDNSet__by_domains(
                    self.request.api_context,
                    _certificate_domain_names,
                    discovery_type="via upload certificate_signed",
                )
            except Exception as exc:  # noqa: F841
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
                dbCertificateCAChain=dbCertificateCAChain,
                # optionals
                dbUniqueFQDNSet=dbUniqueFQDNSet,
                dbPrivateKey=dbPrivateKey,
                discovery_type="via upload certificate_signed",
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
                    "CertificateCAChain": {
                        "created": chain_is_created,
                        "id": dbCertificateCAChain.id,
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

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)


class View_Focus(Handler):
    dbCertificateSigned: Optional[CertificateSigned] = None

    def _focus(self) -> CertificateSigned:
        if self.dbCertificateSigned is None:
            dbCertificateSigned = lib_db.get.get__CertificateSigned__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbCertificateSigned:
                raise HTTPNotFound("invalid CertificateSigned")
            self.dbCertificateSigned = dbCertificateSigned
            self._focus_item = dbCertificateSigned
            self._focus_url = "%s/certificate-signed/%s" % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                self.dbCertificateSigned.id,
            )
        return self.dbCertificateSigned

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus",
        renderer="/admin/certificate_signed-focus.mako",
    )
    @view_config(route_name="admin:certificate_signed:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}.json",
            "section": "certificate-signed",
            "about": """CertificateSigned focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1.json",
        }
    )
    def focus(self):
        dbCertificateSigned = self._focus()
        if self.request.wants_json:
            return {"CertificateSigned": dbCertificateSigned.as_json}
        # x-x509-server-cert
        return {"project": "peter_sslers", "CertificateSigned": dbCertificateSigned}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:cert:raw", renderer="string"
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/cert.pem",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/cert.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/cert.pem.txt",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/cert.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/cert.cer",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. as DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/cert.cer",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/cert.crt",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. as DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/cert.crt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/cert.der",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. as DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/cert.der",
        }
    )
    def focus_raw(self):
        """
        for extensions, see `cert_utils.EXTENSION_TO_MIME`
        """
        dbCertificateSigned = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateSigned.cert_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateSigned.cert_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbCertificateSigned.cert_pem
            )
            response = Response()
            if self.request.matchdict["format"] in ("crt", "der"):
                response.content_type = "application/x-x509-server-cert"
            elif self.request.matchdict["format"] in ("cer",):
                response.content_type = "application/pkix-cert"
            response.body = as_der
            return response
        return "UNSUPPORTED FORMAT"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:parse|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/parse.json",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. parsed""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/parse.json",
        }
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
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/chain.pem",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. Chain PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/chain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/chain.pem.txt",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. chain PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/chain.pem.txt",
        }
    )
    def chain(self):
        dbCertificateSigned = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateSigned.cert_chain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateSigned.cert_chain_pem
        return "chain.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:fullchain:raw", renderer="string"
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/fullchain.pem",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. FullChain PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/fullchain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/fullchain.pem.txt",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. FullChain PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/fullchain.pem.txt",
        }
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
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/privkey.pem",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. PrivateKey PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/privkey.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/privkey.pem.txt",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. PrivateKey PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/privkey.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/privkey.key",
            "section": "certificate-signed",
            "about": """CertificateSigned focus. PrivateKey DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/privkey.key",
        }
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
        route_name="admin:certificate_signed:focus:config|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/config.json",
            "section": "certificate-signed",
            "about": """CertificateSigned Config""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/config.json",
        }
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
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/config.zip",
            "section": "certificate-signed",
            "about": """CertificateSigned Config.zip""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/config.zip",
        }
    )
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

        except Exception as exc:  # noqa: F841
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


class View_Focus_via_CertificateCAChain(View_Focus):
    def _focus_via_CertificateCAChain(self):
        dbCertificateSigned = self._focus()
        certificate_ca_chain_id = int(self.request.matchdict["id_cachain"])
        if certificate_ca_chain_id not in dbCertificateSigned.certificate_ca_chain_ids:
            raise HTTPNotFound("invalid CertificateCAChain")
        return (dbCertificateSigned, certificate_ca_chain_id)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:via_certificate_ca_chain:config|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/config.json",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain Config.json""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/config.json",
        }
    )
    def config_json(self):
        (
            dbCertificateSigned,
            certificate_ca_chain_id,
        ) = self._focus_via_CertificateCAChain()
        if self.request.params.get("idonly", None):
            rval = dbCertificateSigned.custom_config_payload(
                certificate_ca_chain_id=certificate_ca_chain_id, id_only=True
            )
        else:
            rval = dbCertificateSigned.custom_config_payload(
                certificate_ca_chain_id=certificate_ca_chain_id, id_only=False
            )
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:via_certificate_ca_chain:config|zip"
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/config.zip",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain Config.zip""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/config.zip",
        }
    )
    def config_zip(self):
        (
            dbCertificateSigned,
            certificate_ca_chain_id,
        ) = self._focus_via_CertificateCAChain()
        try:
            tmpfile = archive_zipfile(
                dbCertificateSigned, certificate_ca_chain_id=certificate_ca_chain_id
            )
            response = Response(
                content_type="application/zip", body_file=tmpfile, status=200
            )
            response.headers[
                "Content-Disposition"
            ] = "attachment; filename= cert%s-chain%s.zip" % (
                dbCertificateSigned.id,
                certificate_ca_chain_id,
            )
            return response

        except Exception as exc:  # noqa: F841
            return HTTPSeeOther(
                "%s?result=error&error=could+not+generate+zipfile" % self._focus_url
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_signed:focus:via_certificate_ca_chain:chain:raw",
        renderer="string",
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.pem",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain Chain-PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/chain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.pem.txt",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain Chain-PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/chain.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.cer",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain Chain-DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/chain.cer",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.crt",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain Chain-DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/chain.crt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.der",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain Chain-DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/chain.der",
        }
    )
    def chain(self):
        (
            dbCertificateSigned,
            certificate_ca_chain_id,
        ) = self._focus_via_CertificateCAChain()
        cert_chain_pem = dbCertificateSigned.valid_cert_chain_pem(
            certificate_ca_chain_id
        )
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
        route_name="admin:certificate_signed:focus:via_certificate_ca_chain:fullchain:raw",
        renderer="string",
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/fullchain.pem",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain FullChain-PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/fullchain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/fullchain.pem.txt",
            "section": "certificate-signed",
            "about": """CertificateSigned via CertificateCAChain FullChain-PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/via-certificate-ca-chain/2/fullchain.pem.txt",
        }
    )
    def fullchain(self):
        (
            dbCertificateSigned,
            certificate_ca_chain_id,
        ) = self._focus_via_CertificateCAChain()
        cert_fullchain_pem = dbCertificateSigned.valid_cert_fullchain_pem(
            certificate_ca_chain_id
        )
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
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/nginx-cache-expire.json",
            "section": "certificate-signed",
            "about": """Flushes the Nginx cache. This will make background requests to configured Nginx servers, instructing them to flush their cache. """,
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/certificate-signed/1/nginx-cache-expire.json",
        }
    )
    def nginx_expire(self):
        dbCertificateSigned = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self, "/certificate-signed/{ID}/nginx-cache-expire.json"
                )
            raise HTTPSeeOther(
                "%s?result=error&operation=nginx-cache-expire&message=POST+required"
                % self._focus_url
            )
        try:
            # could raise `InvalidRequest("nginx is not enabled")`
            self._ensure_nginx()

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
                "%s?result=success&operation=nginx-cache-expire&event.id=%s"
                % (self._focus_url, dbEvent.id)
            )

        except errors.InvalidRequest as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": exc.args[0],
                }
            raise HTTPSeeOther(
                "%s?result=error&operation=nginx-cache-expire&error=nginx+is+not+enabled"
                % self._focus_url
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_signed:focus:mark", renderer=None)
    @view_config(route_name="admin:certificate_signed:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/certificate-signed/{ID}/mark.json",
            "section": "certificate-signed",
            "about": """Mark""",
            "POST": True,
            "GET": None,
            "examples": [
                "curl {ADMIN_PREFIX}/certificate-signed/1/mark.json",
                """curl --form 'action=active' {ADMIN_PREFIX}/certificate-signed/1/mark.json""",
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
    )
    def mark(self):
        dbCertificateSigned = self._focus()
        if self.request.method == "POST":
            return self._mark__submit(dbCertificateSigned)
        return self._mark__print(dbCertificateSigned)

    def _mark__print(self, dbCertificateSigned):
        if self.request.wants_json:
            return formatted_get_docs(self, "/certificate-signed/{ID}/mark.json")
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

            event_type = "CertificateSigned__mark"

            update_recents = False
            unactivated = False
            activated = False
            event_status: Optional[str] = None

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

            if TYPE_CHECKING:
                assert isinstance(event_status, str)

            self.request.api_context.dbSession.flush(objects=[dbCertificateSigned])

            # bookkeeping
            event_type_id = model_utils.OperationsEventType.from_string(event_type)
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type_id, event_payload_dict
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

        except formhandling.FormInvalid as exc:  # noqa: F841
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
