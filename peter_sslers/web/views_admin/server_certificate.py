# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime

# pypi
import six
import sqlalchemy

# localapp
from .. import lib
from ..lib import form_utils as form_utils
from ..lib import formhandling
from ..lib import text as lib_text
from ..lib.forms import Form_Certificate_mark
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


class ViewAdmin_List(Handler):
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:server_certificates",
        renderer="/admin/server_certificates.mako",
    )
    @view_config(
        route_name="admin:server_certificates_paginated",
        renderer="/admin/server_certificates.mako",
    )
    @view_config(
        route_name="admin:server_certificates:active",
        renderer="/admin/server-certificates.mako",
    )
    @view_config(
        route_name="admin:server_certificates:active_paginated",
        renderer="/admin/server-certificates.mako",
    )
    @view_config(
        route_name="admin:server_certificates:expiring",
        renderer="/admin/server-certificates.mako",
    )
    @view_config(
        route_name="admin:server_certificates:expiring_paginated",
        renderer="/admin/server-certificates.mako",
    )
    @view_config(
        route_name="admin:server_certificates:inactive",
        renderer="/admin/server-certificates.mako",
    )
    @view_config(
        route_name="admin:server_certificates:inactive_paginated",
        renderer="/admin/server-certificates.mako",
    )
    @view_config(route_name="admin:server_certificates|json", renderer="json")
    @view_config(route_name="admin:server_certificates_paginated|json", renderer="json")
    @view_config(route_name="admin:server_certificates:active|json", renderer="json")
    @view_config(
        route_name="admin:server_certificates:active_paginated|json", renderer="json"
    )
    @view_config(route_name="admin:server_certificates:expiring|json", renderer="json")
    @view_config(
        route_name="admin:server_certificates:expiring_paginated|json", renderer="json"
    )
    @view_config(route_name="admin:server_certificates:inactive|json", renderer="json")
    @view_config(
        route_name="admin:server_certificates:inactive_paginated|json", renderer="json"
    )
    def list(self):
        expiring_days = self.request.registry.settings["app_settings"]["expiring_days"]
        if self.request.matched_route.name in (
            "admin:server_certificates:expiring",
            "admin:server_certificates:expiring_paginated",
            "admin:server_certificates:expiring|json",
            "admin:server_certificates:expiring_paginated|json",
        ):
            sidenav_option = "expiring"
            url_template = (
                "%s/server-certificates/expiring/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__ServerCertificate__count(
                self.request.api_context, expiring_days=expiring_days
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__ServerCertificate__paginated(
                self.request.api_context,
                expiring_days=expiring_days,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:server_certificates:active",
            "admin:server_certificates:active_paginated",
            "admin:server_certificates:active|json",
            "admin:server_certificates:active_paginated|json",
        ):
            sidenav_option = "active"
            url_template = (
                "%s/server-certificates/active/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__ServerCertificate__count(
                self.request.api_context, is_active=True
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__ServerCertificate__paginated(
                self.request.api_context,
                is_active=True,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:server_certificates:inactive",
            "admin:server_certificates:inactive_paginated",
            "admin:server_certificates:inactive|json",
            "admin:server_certificates:inactive_paginated|json",
        ):
            sidenav_option = "inactive"
            url_template = (
                "%s/server-certificates/active/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__ServerCertificate__count(
                self.request.api_context, is_active=False
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__ServerCertificate__paginated(
                self.request.api_context,
                is_active=False,
                limit=items_per_page,
                offset=offset,
            )
        else:
            sidenav_option = "all"
            url_template = (
                "%s/server-certificates/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__ServerCertificate__count(
                self.request.api_context
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__ServerCertificate__paginated(
                self.request.api_context,
                limit=items_per_page,
                offset=offset,
                eagerload_web=True,
            )
        if self.request.matched_route.name.endswith("|json"):
            _certificates = {c.id: c.as_json for c in items_paged}
            return {
                "ServerCertificates": _certificates,
                "pagination": json_pagination(items_count, pager),
            }

        return {
            "project": "peter_sslers",
            "ServerCertificates_count": items_count,
            "ServerCertificates": items_paged,
            "sidenav_option": sidenav_option,
            "expiring_days": expiring_days,
            "pager": pager,
        }


class ViewAdmin_New(Handler):
    @view_config(route_name="admin:server_certificate:upload")
    @view_config(route_name="admin:server_certificate:upload|json", renderer="json")
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        if self.request.wants_json:
            return {
                "instructions": """curl --form 'private_key_file_pem=@privkey1.pem' --form 'certificate_file=@cert1.pem' --form 'chain_file=@chain1.pem' %s/server-certificate/upload.json"""
                % self.request.admin_url,
                "form_fields": {
                    "private_key_file_pem": "required",
                    "chain_file": "required",
                    "certificate_file": "required",
                },
            }
        return render_to_response(
            "/admin/server_certificate-upload.mako", {}, self.request
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
                dbCACertificate,
                cacert_is_created,
            ) = lib_db.getcreate.getcreate__CACertificate__by_pem_text(
                self.request.api_context, ca_chain_pem, ca_chain_name="manual upload"
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
                _certificate_domain_names = cert_utils.parse_cert_domains(
                    cert_path=_tmpfileCert.name
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
                dbServerCertificate,
                cert_is_created,
            ) = lib_db.getcreate.getcreate__ServerCertificate(
                self.request.api_context,
                certificate_pem,
                cert_domains_expected=_certificate_domain_names,
                dbCACertificate=dbCACertificate,
                dbUniqueFQDNSet=dbUniqueFQDNSet,
                dbPrivateKey=dbPrivateKey,
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "certificate": {
                        "created": cert_is_created,
                        "id": dbServerCertificate.id,
                        "url": "%s/server-certificate/%s"
                        % (
                            self.request.registry.settings["app_settings"][
                                "admin_prefix"
                            ],
                            dbServerCertificate.id,
                        ),
                    },
                    "ca_certificate": {
                        "created": cacert_is_created,
                        "id": dbCACertificate.id,
                    },
                    "private_key": {"created": pkey_is_created, "id": dbPrivateKey.id},
                }
            return HTTPSeeOther(
                "%s/server-certificate/%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbServerCertificate.id,
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)


class ViewAdmin_Focus(Handler):
    def _focus(self):
        dbServerCertificate = lib_db.get.get__ServerCertificate__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbServerCertificate:
            raise HTTPNotFound("invalid ServerCertificate")
        self._focus_item = dbServerCertificate
        self._focus_url = "%s/server-certificate/%s" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            dbServerCertificate.id,
        )
        return dbServerCertificate

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:server_certificate:focus",
        renderer="/admin/server_certificate-focus.mako",
    )
    @view_config(route_name="admin:server_certificate:focus|json", renderer="json")
    def focus(self):
        dbServerCertificate = self._focus()
        if self.request.wants_json:
            return {"ServerCertificate": dbServerCertificate.as_json}
        # x-x509-server-cert
        return {"project": "peter_sslers", "ServerCertificate": dbServerCertificate}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:server_certificate:focus:parse|json", renderer="json"
    )
    def focus_parse_json(self):
        dbServerCertificate = self._focus()
        return {
            "%s"
            % dbServerCertificate.id: cert_utils.parse_cert(
                cert_pem=dbServerCertificate.cert_pem
            )
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:server_certificate:focus:chain:raw", renderer="string"
    )
    def focus_chain(self):
        dbServerCertificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbServerCertificate.certificate_upchain.cert_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbServerCertificate.certificate_upchain.cert_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbServerCertificate.certificate_upchain.cert_pem
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
        route_name="admin:server_certificate:focus:fullchain:raw", renderer="string"
    )
    def focus_fullchain(self):
        dbServerCertificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbServerCertificate.cert_fullchain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbServerCertificate.cert_fullchain_pem
        return "fullchain.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:server_certificate:focus:privatekey:raw", renderer="string"
    )
    def focus_privatekey(self):
        dbServerCertificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbServerCertificate.private_key.key_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbServerCertificate.private_key.key_pem
        elif self.request.matchdict["format"] == "key":
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbServerCertificate.private_key.key_pem
            )
            response = Response()
            response.content_type = "application/pkcs8"
            response.body = as_der
            return response
        return "privatekey.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:server_certificate:focus:cert:raw", renderer="string"
    )
    def focus_cert(self):
        dbServerCertificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbServerCertificate.cert_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbServerCertificate.cert_pem
        elif self.request.matchdict["format"] == "crt":
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbServerCertificate.cert_pem
            )
            response = Response()
            response.content_type = "application/x-x509-server-cert"
            response.body = as_der
            return response
        return "cert.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:server_certificate:focus:config|json", renderer="json"
    )
    def focus_config_json(self):
        dbServerCertificate = self._focus()
        if self.request.params.get("idonly", None):
            rval = dbServerCertificate.config_payload_idonly
        else:
            rval = dbServerCertificate.config_payload
        return rval


class ViewAdmin_Focus_Manipulate(ViewAdmin_Focus):
    @view_config(
        route_name="admin:server_certificate:focus:nginx_cache_expire", renderer=None
    )
    @view_config(
        route_name="admin:server_certificate:focus:nginx_cache_expire|json",
        renderer="json",
    )
    def nginx_expire(self):
        dbServerCertificate = self._focus()
        if not self.request.registry.settings["app_settings"]["enable_nginx"]:
            raise HTTPSeeOther("%s?result=error&error=no+nginx" % self._focus_url)
        dbDomains = [
            c2d.domain for c2d in dbServerCertificate.unique_fqdn_set.to_domains
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

    @view_config(route_name="admin:server_certificate:focus:mark", renderer=None)
    @view_config(route_name="admin:server_certificate:focus:mark|json", renderer="json")
    def mark(self):
        dbServerCertificate = self._focus()
        if self.request.method == "POST":
            return self._mark__submit(dbServerCertificate)
        return self._mark__print(dbServerCertificate)

    def _mark__print(self, dbServerCertificate):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'action=active' %s/server-certificate/1/mark.json"""
                    % self.request.admin_url
                ],
                "form_fields": {"action": "the intended action"},
                "valid_options": {
                    "action": [
                        "active",
                        "inactive",
                        "revoked",
                        "renew_manual",
                        "renew_auto",
                        "unrevoke",
                    ]
                },
            }
        url_post_required = "%s?result=post+required&operation=mark" % self._focus_url
        return HTTPSeeOther(url_post_required)

    def _mark__submit(self, dbServerCertificate):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Certificate_mark, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["server_certificate.id"] = dbServerCertificate.id
            event_payload_dict["action"] = action
            event_type = model_utils.OperationsEventType.from_string(
                "ServerCertificate__mark"
            )

            update_recents = False
            deactivated = False
            activated = False
            event_status = False

            try:

                if action == "active":
                    event_status = lib_db.update.update_ServerCertificate__set_active(
                        self.request.api_context, dbServerCertificate
                    )
                    update_recents = True
                    activated = True

                elif action == "inactive":
                    event_status = lib_db.update.update_ServerCertificate__unset_active(
                        self.request.api_context, dbServerCertificate
                    )
                    update_recents = True
                    deactivated = True

                elif action == "revoked":
                    event_status = lib_db.update.update_ServerCertificate__set_revoked(
                        self.request.api_context, dbServerCertificate
                    )
                    update_recents = True
                    deactivated = True
                    event_type = "ServerCertificate__revoke"

                elif action == "unrevoke":
                    raise errors.InvalidTransition("invalid option")
                    """
                    event_status = lib_db.update.update_ServerCertificate__unset_revoked(
                        self.request.api_context, dbServerCertificate
                    )
                    update_recents = True
                    activated = None
                    """

                else:
                    raise errors.InvalidTransition("invalid option")

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

            self.request.api_context.dbSession.flush(objects=[dbServerCertificate])

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
                dbServerCertificate=dbServerCertificate,
            )

            if update_recents:
                event_update = lib_db.actions.operations_update_recents(
                    self.request.api_context
                )
                event_update.operations_event_id__child_of = dbOperationsEvent.id
                self.request.api_context.dbSession.flush(objects=[event_update])

            if deactivated:
                # this will handle requeuing
                events.Certificate_deactivated(
                    self.request.api_context, dbServerCertificate
                )

            if activated:
                # nothing to do?
                pass

            if self.request.wants_json:
                return {"result": "success", "Domain": dbServerCertificate.as_json}
            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?&result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                action,
                exc.as_querystring,
            )
            raise HTTPSeeOther(url_failure)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
