import logging

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


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
from ..lib.forms import Form_PrivateKey_mark
from ..lib.forms import Form_PrivateKey_new__file
from ..lib.forms import Form_PrivateKey_new__autogenerate
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ... import lib as lib_core
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class View_List(Handler):
    @view_config(route_name="admin:private_keys", renderer="/admin/private_keys.mako")
    @view_config(
        route_name="admin:private_keys_paginated", renderer="/admin/private_keys.mako"
    )
    @view_config(route_name="admin:private_keys|json", renderer="json")
    @view_config(route_name="admin:private_keys_paginated|json", renderer="json")
    def list(self):
        items_count = lib_db.get.get__PrivateKey__count(self.request.api_context)
        url_template = (
            "%s/private-keys/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__PrivateKey__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _keys = {k.id: k.as_json for k in items_paged}
            return {
                "PrivateKeys": _keys,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "PrivateKeys_count": items_count,
            "PrivateKeys": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    def _focus(self, eagerload_web=False):
        dbPrivateKey = lib_db.get.get__PrivateKey__by_id(
            self.request.api_context,
            self.request.matchdict["id"],
            eagerload_web=eagerload_web,
        )
        if not dbPrivateKey:
            raise HTTPNotFound("the key was not found")
        self._focus_item = dbPrivateKey
        self._focus_url = "%s/private-key/%s" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            dbPrivateKey.id,
        )
        return dbPrivateKey

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:private_key:focus", renderer="/admin/private_key-focus.mako"
    )
    @view_config(route_name="admin:private_key:focus|json", renderer="json")
    def focus(self):
        dbPrivateKey = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "PrivateKey": dbPrivateKey.as_json,
                "raw": {
                    "pem.txt": "%s/key.pem.txt" % self._focus_url,
                    "pem": "%s/key.pem" % self._focus_url,
                    "der": "%s/key.key" % self._focus_url,
                },
            }
        return {"project": "peter_sslers", "PrivateKey": dbPrivateKey}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:private_key:focus:raw", renderer="string")
    def focus_raw(self):
        dbPrivateKey = self._focus()
        if dbPrivateKey.private_key_type == model_utils.PrivateKeyType.from_string(
            "placeholder"
        ):
            return "*placeholder*"
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbPrivateKey.key_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbPrivateKey.key_pem
        elif self.request.matchdict["format"] == "key":
            self.request.response.content_type = "application/pkcs8"
            as_der = cert_utils.convert_pem_to_der(pem_data=dbPrivateKey.key_pem)
            return as_der

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:private_key:focus:parse|json", renderer="json")
    def focus_parse_json(self):
        dbPrivateKey = self._focus()
        return {
            "%s" % dbPrivateKey.id: cert_utils.parse_key(key_pem=dbPrivateKey.key_pem)
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:private_key:focus:certificate_requests",
        renderer="/admin/private_key-focus-certificate_requests.mako",
    )
    @view_config(
        route_name="admin:private_key:focus:certificate_requests_paginated",
        renderer="/admin/private_key-focus-certificate_requests.mako",
    )
    def related__CertificateRequests(self):
        dbPrivateKey = self._focus()
        items_count = lib_db.get.get__CertificateRequest__by_PrivateKeyId__count(
            self.request.api_context, dbPrivateKey.id
        )
        url_template = "%s/certificate-requests/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CertificateRequest__by_PrivateKeyId__paginated(
            self.request.api_context,
            dbPrivateKey.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "PrivateKey": dbPrivateKey,
            "CertificateRequests_count": items_count,
            "CertificateRequests": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:private_key:focus:server_certificates",
        renderer="/admin/private_key-focus-server_certificates.mako",
    )
    @view_config(
        route_name="admin:private_key:focus:server_certificates_paginated",
        renderer="/admin/private_key-focus-server_certificates.mako",
    )
    def related__ServerCertificates(self):
        dbPrivateKey = self._focus()
        items_count = lib_db.get.get__ServerCertificate__by_PrivateKeyId__count(
            self.request.api_context, dbPrivateKey.id
        )
        url_template = "%s/server-certificates/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__ServerCertificate__by_PrivateKeyId__paginated(
            self.request.api_context,
            dbPrivateKey.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "PrivateKey": dbPrivateKey,
            "ServerCertificates_count": items_count,
            "ServerCertificates": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:private_key:focus:queue_certificates",
        renderer="/admin/private_key-focus-queue_certificates.mako",
    )
    @view_config(
        route_name="admin:private_key:focus:queue_certificates_paginated",
        renderer="/admin/private_key-focus-queue_certificates.mako",
    )
    def related__QueueCertificates(self):
        dbPrivateKey = self._focus()
        items_count = lib_db.get.get__QueueCertificate__by_PrivateKeyId__count(
            self.request.api_context, dbPrivateKey.id
        )
        url_template = "%s/queue-certificates/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__QueueCertificate__by_PrivateKeyId__paginated(
            self.request.api_context,
            dbPrivateKey.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "PrivateKey": dbPrivateKey,
            "QueueCertificates_count": items_count,
            "QueueCertificates": items_paged,
            "pager": pager,
        }


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:private_key:focus:mark", renderer=None)
    @view_config(route_name="admin:private_key:focus:mark|json", renderer="json")
    def focus_mark(self):
        dbPrivateKey = self._focus()
        if self.request.method == "POST":
            return self._focus_mark__submit(dbPrivateKey)
        return self._focus_mark__print(dbPrivateKey)

    def _focus_mark__print(self, dbPrivateKey):
        if self.request.wants_json:
            return {
                "instructions": [
                    "HTTP POST required",
                    """curl --form 'action=active' %s/mark.json""" % self._focus_url,
                ],
                "form_fields": {"action": "the intended action"},
                "valid_options": {
                    "action": [
                        "compromised",
                        "active",
                        "inactive",
                    ]
                },
            }
        url_post_required = (
            "%s?result=error&error=post+required&operation=mark" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self, dbPrivateKey):
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_PrivateKey_mark, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            if dbPrivateKey.is_placeholder:
                formStash.fatal_field(
                    field="action",
                    message="The Placeholder PrivateKey can not be marked",
                )

            action = formStash.results["action"]
            event_type_id = model_utils.OperationsEventType.from_string(
                "PrivateKey__mark"
            )
            if action == "compromised":
                event_type_id = model_utils.OperationsEventType.from_string(
                    "PrivateKey__revoke"
                )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["private_key.id"] = dbPrivateKey.id
            event_payload_dict["action"] = formStash.results["action"]

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type_id, event_payload_dict
            )

            event_status = None
            try:

                if action == "active":
                    event_status = lib_db.update.update_PrivateKey__set_active(
                        self.request.api_context, dbPrivateKey
                    )

                elif action == "inactive":
                    event_status = lib_db.update.update_PrivateKey__unset_active(
                        self.request.api_context, dbPrivateKey
                    )

                elif action == "compromised":
                    event_status = lib_db.update.update_PrivateKey__set_compromised(
                        self.request.api_context, dbPrivateKey, dbOperationsEvent
                    )

                else:
                    raise errors.InvalidTransition("invalid option")

            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

            self.request.api_context.dbSession.flush(objects=[dbPrivateKey])

            lib_db.logger._log_object_event(
                self.request.api_context,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    event_status
                ),
                dbPrivateKey=dbPrivateKey,
            )

            if self.request.wants_json:
                return {"result": "success", "PrivateKey": dbPrivateKey.as_json}
            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                errors.formstash_to_querystring(formStash),
                action,
            )
            raise HTTPSeeOther(url_failure)


class View_New(Handler):
    @view_config(route_name="admin:private_key:new")
    @view_config(route_name="admin:private_key:new|json", renderer="json")
    def new(self):
        if self.request.method == "POST":
            return self._new__submit()
        return self._new__print()

    def _new__print(self):
        if self.request.wants_json:
            return {
                "instructions": [
                    "HTTP POST required",
                    '''curl %s/private-key/new.json --form "bits=????"'''
                    % (self.request.registry.settings["app_settings"]["admin_prefix"]),
                ],
                "form_fields": {"bits": "bits for the PrivateKey"},
                "valid_options": {"bits": ["4096"]},
            }
        return render_to_response("/admin/private_key-new.mako", {}, self.request)

    def _new__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_PrivateKey_new__autogenerate,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                dbPrivateKey = lib_db.create.create__PrivateKey(
                    self.request.api_context,
                    # bits=4096,
                    private_key_source_id=model_utils.PrivateKeySource.from_string(
                        "generated"
                    ),
                    private_key_type_id=model_utils.PrivateKeyType.from_string(
                        "standard"
                    ),
                )
            except Exception as exc:
                log.critical("create__PrivateKey: %s", exc)
                raise

            if self.request.wants_json:
                return {
                    "result": "success",
                    "PrivateKey": dbPrivateKey.as_json,
                }
            return HTTPSeeOther(
                "%s/private-key/%s?result=success%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbPrivateKey.id,
                    "&is_created=1",
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:private_key:upload")
    @view_config(route_name="admin:private_key:upload|json", renderer="json")
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        if self.request.wants_json:
            return {
                "instructions": [
                    "HTTP POST required",
                    """curl --form 'private_key_file_pem=@privkey1.pem' %s/private-key/upload.json"""
                    % (self.request.registry.settings["app_settings"]["admin_prefix"]),
                ],
                "form_fields": {"private_key_file_pem": "required"},
            }

        return render_to_response("/admin/private_key-upload.mako", {}, self.request)

    def _upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_PrivateKey_new__file, validate_get=False
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
                _is_created,
            ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                self.request.api_context,
                private_key_pem,
                private_key_source_id=model_utils.PrivateKeySource.from_string(
                    "imported"
                ),
                private_key_type_id=model_utils.PrivateKeyType.from_string("standard"),
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "is_created": True if _is_created else False,
                    "PrivateKey": dbPrivateKey.as_json,
                }
            return HTTPSeeOther(
                "%s/private-key/%s?result=success%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbPrivateKey.id,
                    ("&is_created=1" if _is_created else ""),
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)
