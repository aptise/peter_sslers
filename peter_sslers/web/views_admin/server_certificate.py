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
from ..lib.forms import Form_Certificate_Renewal_Custom
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
        expiring_days = self.request.registry.settings["expiring_days"]
        if self.request.matched_route.name in (
            "admin:server_certificates:expiring",
            "admin:server_certificates:expiring_paginated",
            "admin:server_certificates:expiring|json",
            "admin:server_certificates:expiring_paginated|json",
        ):
            sidenav_option = "expiring"
            url_template = (
                "%s/server-certificates/expiring/{0}"
                % self.request.registry.settings["admin_prefix"]
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
            sidenav_option = "active_only"
            url_template = (
                "%s/server-certificates/active/{0}"
                % self.request.registry.settings["admin_prefix"]
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
            sidenav_option = "inactive_only"
            url_template = (
                "%s/server-certificates/active/{0}"
                % self.request.registry.settings["admin_prefix"]
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
                % self.request.registry.settings["admin_prefix"]
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
                self.request.api_context, private_key_pem
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
            (
                dbServerCertificate,
                cert_is_created,
            ) = lib_db.getcreate.getcreate__ServerCertificate__by_pem_text(
                self.request.api_context,
                certificate_pem,
                dbCACertificate=dbCACertificate,
                dbPrivateKey=dbPrivateKey,
                dbAcmeAccountKey=None,
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "certificate": {
                        "created": cert_is_created,
                        "id": dbServerCertificate.id,
                        "url": "%s/server-certificate/%s"
                        % (
                            self.request.registry.settings["admin_prefix"],
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
                    self.request.registry.settings["admin_prefix"],
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
            self.request.registry.settings["admin_prefix"],
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
        if not self.request.registry.settings["enable_nginx"]:
            raise HTTPSeeOther("%s?error=no+nginx" % self._focus_url)
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
            "%s?operation=nginx+cache+expire&result=success&event.id=%s"
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
        url_post_required = "%s?operation=mark&result=post+required" % self._focus_url
        return HTTPSeeOther(url_post_required)

    def _mark__submit(self, dbServerCertificate):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Certificate_mark, validate_get=True
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["server_certificate.id"] = dbServerCertificate.id
            event_payload_dict["action"] = action
            event_type = model_utils.OperationsEventType.from_string(
                "certificate__mark"
            )

            update_recents = False
            deactivated = False
            activated = False
            event_status = False

            if action == "active":
                if dbServerCertificate.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field="action", message="Already active")

                # is_deactivated is our manual toggle;
                if not dbServerCertificate.is_deactivated:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="action",
                        message="Certificate was not manually deactivated",
                    )

                if dbServerCertificate.is_revoked:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="action",
                        message="Certificate is revoked. You must unrevoke first",
                    )

                # now make it active!
                dbServerCertificate.is_active = True
                # unset the manual toggle
                dbServerCertificate.is_deactivated = False
                # cleanup options
                update_recents = True
                activated = True
                event_status = "certificate__mark__active"

            elif action == "inactive":
                if not dbServerCertificate.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field="action", message="Already inactive")

                if dbServerCertificate.is_deactivated:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field="action", message="Already deactivated")

                # deactivate it
                dbServerCertificate.is_active = False
                dbServerCertificate.is_auto_renew = False
                # set the manual toggle
                dbServerCertificate.is_deactivated = True
                # cleanup options
                update_recents = True
                deactivated = True
                event_status = "certificate__mark__inactive"

            elif action == "revoked":
                if dbServerCertificate.is_revoked:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field="action", message="Already revoked")

                # mark revoked
                dbServerCertificate.is_revoked = True
                # deactivate it
                dbServerCertificate.is_active = False
                dbServerCertificate.is_auto_renew = False
                # set the manual toggle
                dbServerCertificate.is_deactivated = True
                # cleanup options
                update_recents = True
                deactivated = True
                event_type = "certificate__revoke"
                event_status = "certificate__mark__revoked"

            elif action == "renew_auto":
                if not dbServerCertificate.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="action", message="Certificate must be `active`"
                    )

                if dbServerCertificate.is_auto_renew:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="action", message="Already set to auto-renew"
                    )

                # set the renewal
                dbServerCertificate.is_auto_renew = True
                # cleanup options
                event_status = "certificate__mark__renew_auto"

            elif action == "renew_manual":
                if not dbServerCertificate.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="action", message="certificate must be `active`"
                    )

                if not dbServerCertificate.is_auto_renew:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="action", message="Already set to manual renewal"
                    )

                # unset the renewal
                dbServerCertificate.is_auto_renew = False
                # cleanup options
                event_status = "certificate__mark__renew_manual"

            elif action == "unrevoke":
                if not dbServerCertificate.is_revoked:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="action", message="Certificate is not revoked"
                    )

                # unset the revoke
                dbServerCertificate.is_revoked = False
                # lead is_active and is_deactivated as-is
                # cleanup options
                update_recents = True
                activated = None
                event_status = "certificate__mark__unrevoked"

            else:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(field="action", message="invalid option")

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
            url_success = "%s?operation=mark&action=%s&result=success" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?operation=mark&action=%s&result=error&error=%s" % (
                self._focus_url,
                action,
                str(exc),
            )
            raise HTTPSeeOther(url_failure)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:server_certificate:focus:renew:queue", renderer=None)
    @view_config(
        route_name="admin:server_certificate:focus:renew:queue|json", renderer="json"
    )
    def renew_queue(self):
        """
        This will allow the ServerCertificate to renew with the associated AcmeAccount
        """
        dbServerCertificate = self._focus()
        try:
            if not dbServerCertificate.is_renewable:
                raise errors.DisplayableError(
                    "This ServerCertificate can not be renewed to the AcmeAccount".replace(
                        " ", "+"
                    )
                )

            # first check to see if this is already queued
            dbQueued = lib_db.get.get__QueueRenewal__by_UniqueFQDNSetId__active(
                self.request.api_context, dbServerCertificate.unique_fqdn_set_id
            )
            if dbQueued:
                raise errors.DisplayableError(
                    "There is an existing entry in the queue for this ServerCertificate's UniqueFQDNSet.".replace(
                        " ", "+"
                    )
                )

            raise ValueError("todo: create a new PrivateKey")

            # okay, we're good to go...'
            event_type = model_utils.OperationsEventType.from_string(
                "queue_renewal__update"
            )
            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type, event_payload_dict
            )
            dbQueue = lib_db.create._create__QueueRenewal(
                self.request.api_context, dbServerCertificate
            )
            event_payload_dict["ssl_certificate-queued.ids"] = str(
                dbServerCertificate.id
            )
            event_payload_dict["sql_queue_renewals.ids"] = str(dbQueue.id)
            dbOperationsEvent.set_event_payload(event_payload_dict)
            self.request.api_context.dbSession.flush(objects=[dbOperationsEvent])

            if self.request.wants_json:
                return {"status": "success", "queue_item": dbQueue.id}
            url_success = (
                "%s?operation=renewal&renewal_type=queue&success=%s&result=success"
                % (self._focus_url, dbQueue.id)
            )
            return HTTPSeeOther(url_success)

        except errors.DisplayableError as exc:
            if self.request.wants_json:
                return {"status": "error", "error": str(exc)}
            url_failure = (
                "%s?operation=renewal&renewal_type=queue&error=%s&result=error"
                % (self._focus_url, str(exc))
            )
            raise HTTPSeeOther(url_failure)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:server_certificate:focus:renew:quick", renderer=None)
    @view_config(route_name="admin:server_certificate:focus:renew:quick|json", renderer="json")
    def renew_quick(self):
        """
        this endpoint is for immediately renewing the certificate
        """
        dbServerCertificate = self._focus()
        try:
            if not dbServerCertificate.is_renewable:
                raise errors.DisplayableError(
                    "This ServerCertificate can not be renewed to the AcmeAccount".replace(
                        " ", "+"
                    )
                )
                
            raise ValueError("todo: create a new PrivateKey")

            if (
                (not dbServerCertificate.private_key)
                or (not dbServerCertificate.private_key.is_active)
                or (not dbServerCertificate.acme_account_key)
                or (not dbServerCertificate.acme_account_key.is_active)
            ):
                raise errors.DisplayableError(
                    "The PrivateKey or AccountKey is not active. You can not Quick-Renew."
                )
            if not dbServerCertificate.is_can_renew_letsencrypt:
                raise errors.DisplayableError(
                    "Thie cert is not eligible for `Quick Renew`"
                )

            try:
                (
                    dbAcmeOrder,
                    result,
                ) = lib_db.actions_acme.do__AcmeOrder__AcmeV2__automated(
                    self.request.api_context,
                    domain_names=None,  # domain_names, handle via the certificate...
                    dbAcmeAccountKey=dbServerCertificate.acme_account_key,
                    dbPrivateKey=dbServerCertificate.private_key,
                    dbServerCertificate__renewal_of=dbServerCertificate,
                )
            except (
                errors.AcmeCommunicationError,
                errors.DomainVerificationError,
            ) as exc:
                raise errors.DisplayableError(str(exc))

            if self.request.wants_json:
                return {
                    "status": "success",
                    "acme_order.id": dbAcmeOrder.id,
                    "certificate_new.id": dbAcmeOrder.server_certificate_id,
                }
            url_success = (
                "%s?operation=renewal&renewal_type=quick&success=%s&result=success"
                % (self._focus_url, dbAcmeOrder.server_certificate_id)
            )
            return HTTPSeeOther(url_success)

        except errors.DisplayableError as exc:
            if self.request.wants_json:
                return {"status": "error", "error": str(exc)}
            url_failure = (
                "%s?operation=renewal&renewal_type=quick&error=%s&result=error"
                % (self._focus_url, str(exc))
            )
            raise HTTPSeeOther(url_failure)


    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:server_certificate:focus:renew:custom", renderer=None)
    @view_config(
        route_name="admin:server_certificate:focus:renew:custom|json", renderer="json"
    )
    def renew_custom(self):
        dbServerCertificate = self._focus()
        self.dbServerCertificate = dbServerCertificate
        self._load_AccountKeyDefault()
        if self.request.method == "POST":
            return self._renew_custom__submit()
        return self._renew_custom__print()

    def _renew_custom__print(self):
        providers = list(model_utils.AcmeAccountProvider.registry.values())
        if self.request.wants_json:
            return {
                "form_fields": {
                    "account_key_option": "One of ('account_key_reuse', 'account_key_default', 'account_key_existing', 'account_key_file'). REQUIRED.",
                    "account_key_reuse": "pem_md5 of the existing account key. Must/Only submit if `account_key_option==account_key_reuse`",
                    "account_key_default": "pem_md5 of the default account key. Must/Only submit if `account_key_option==account_key_default`",
                    "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                    "account_key_file_pem": "pem of the account key file. Must/Only submit if `account_key_option==account_key_file`",
                    "acme_account_provider_id": "account provider. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is used.",
                    "account_key_file_le_meta": "letsencrypt file. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is not used",
                    "account_key_file_le_pkey": "letsencrypt file",
                    "account_key_file_le_reg": "letsencrypt file",
                    "private_key_option": "One of('private_key_reuse', 'private_key_existing', 'private_key_file_pem'). REQUIRED.",
                    "private_key_reuse": "pem_md5 of existing key",
                    "private_key_existing": "pem_md5 of existing key",
                    "private_key_file_pem": "pem to upload",
                },
                "form_fields_related": [
                    ["account_key_file_pem", "acme_account_provider_id"],
                    [
                        "account_key_file_le_meta",
                        "account_key_file_le_pkey",
                        "account_key_file_le_reg",
                    ],
                ],
                "requirements": [
                    "Submit corresponding field(s) to account_key_option. If `account_key_file` is your intent, submit either PEM+ProviderID or the three letsencrypt files."
                ],
                "instructions": [
                    """curl --form 'account_key_option=account_key_reuse' --form 'account_key_reuse=ff00ff00ff00ff00' 'private_key_option=private_key_reuse' --form 'private_key_reuse=ff00ff00ff00ff00' %s/server-certificate/1/renew.json"""
                    % self.request.admin_url
                ],
            }

        return render_to_response(
            "/admin/server_certificate-focus-renew_custom.mako",
            {
                "ServerCertificate": self.dbServerCertificate,
                "AcmeAccountKey_Default": self.dbAcmeAccountKeyDefault,
                "AcmeAccountProviderOptions": providers,
            },
            self.request,
        )

    def _renew_custom__submit(self):
        dbServerCertificate = self.dbServerCertificate
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Certificate_Renewal_Custom, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            # use the form_utils to process account-key selections
            # why? because they may be uploaded in multiple ways
            accountKeySelection = form_utils.parse_AccountKeySelection(
                self.request,
                formStash,
                seek_selected=formStash.results["account_key_option"],
            )
            if accountKeySelection.selection == "upload":
                key_create_args = accountKeySelection.upload_parsed.getcreate_args
                key_create_args["event_type"] = "acme_account_key__insert"
                (
                    dbAcmeAccountKey,
                    _is_created,
                ) = lib_db.getcreate.getcreate__AcmeAccountKey(
                    self.request.api_context, **key_create_args
                )
                accountKeySelection.AcmeAccountKey = dbAcmeAccountKey

            private_key_pem = form_utils.parse_PrivateKeyPem(
                self.request,
                formStash,
                seek_selected=formStash.results["private_key_option"],
            )

            try:
                event_payload_dict = utils.new_event_payload_dict()
                event_payload_dict["server_certificate.id"] = dbServerCertificate.id
                dbEvent = lib_db.logger.log__OperationsEvent(
                    self.request.api_context,
                    model_utils.OperationsEventType.from_string("certificate__renew"),
                    event_payload_dict,
                )

                raise ValueError("figure this out")
                """
                (
                    dbPrivateKey,
                    _is_created,
                ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                    self.request.api_context, private_key_pem
                )
                """
                raise ValueError("need a dbPrivateKey")
                dbPrivateKey = None

                (
                    dbAcmeOrder,
                    result,
                ) = lib_db.actions_acme.do__AcmeOrder__AcmeV2__automated(
                    self.request.api_context,
                    domain_names=None,
                    dbAcmeAccountKey=accountKeySelection.AcmeAccountKey,
                    dbPrivateKey=dbPrivateKey,
                    dbServerCertificate__renewal_of=dbServerCertificate,
                )
            except (
                errors.AcmeCommunicationError,
                errors.DomainVerificationError,
            ) as exc:
                return HTTPSeeOther(
                    "%s/certificate-requests?result=error&error=renew-acme-automated&message=%s"
                    % (self.request.registry.settings["admin_prefix"], str(exc))
                )
            except Exception as exc:
                if self.request.registry.settings["exception_redirect"]:
                    return HTTPSeeOther(
                        "%s/certificate-requests?result=error&error=renew-acme-automated"
                        % self.request.registry.settings["admin_prefix"]
                    )
                raise

            return HTTPSeeOther(
                "%s/server-certificate/%s?is_renewal=True"
                % (
                    self.request.registry.settings["admin_prefix"],
                    dbAcmeOrder.server_certificate_id,
                )
            )

        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(
                self.request, self._renew_custom__print
            )
