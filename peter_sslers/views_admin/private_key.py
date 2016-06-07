# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime
import pdb

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import *
from ..lib.forms import (Form_PrivateKey_new__file,
                         Form_PrivateKey_mark,
                         )
from ..lib import acme as lib_acme
from ..lib import db as lib_db
from ..lib import events as lib_events
from ..lib import cert_utils as lib_cert_utils
from ..lib import utils as lib_utils
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:private_keys', renderer='/admin/private_keys.mako')
    @view_config(route_name='admin:private_keys_paginated', renderer='/admin/private_keys.mako')
    def private_keys(self):
        items_count = lib_db.get__SslPrivateKey__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/private-keys/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslPrivateKey__paginated(self.request.api_context, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslPrivateKeys_count': items_count,
                'SslPrivateKeys': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _private_key_focus(self, eagerload_web=False):
        dbPrivateKey = lib_db.get__SslPrivateKey__by_id(self.request.api_context, self.request.matchdict['id'], eagerload_web=eagerload_web, )
        if not dbPrivateKey:
            raise HTTPNotFound('the key was not found')
        return dbPrivateKey

    @view_config(route_name='admin:private_key:focus', renderer='/admin/private_key-focus.mako')
    def private_key_focus(self):
        dbPrivateKey = self._private_key_focus(eagerload_web=True)
        return {'project': 'peter_sslers',
                'SslPrivateKey': dbPrivateKey
                }

    @view_config(route_name='admin:private_key:focus:raw', renderer='string')
    def private_key_focus_raw(self):
        dbPrivateKey = self._private_key_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbPrivateKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbPrivateKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib_cert_utils.convert_pem_to_der(pem_data=dbPrivateKey.key_pem)
            return as_der

    @view_config(route_name='admin:private_key:focus:parse.json', renderer='json')
    def private_key_focus_parse_json(self):
        dbPrivateKey = self._private_key_focus()
        return {"%s" % dbPrivateKey.id: lib_cert_utils.parse_key(key_pem=dbPrivateKey.key_pem),
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:private_key:focus:certificates', renderer='/admin/private_key-focus-certificates.mako')
    @view_config(route_name='admin:private_key:focus:certificates_paginated', renderer='/admin/private_key-focus-certificates.mako')
    def private_key_focus__certificates(self):
        dbPrivateKey = self._private_key_focus()
        items_count = lib_db.get__SslServerCertificate__by_SslPrivateKeyId__count(
            self.request.api_context, dbPrivateKey.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/private-key/%s/certificates/{0}' % (self.request.registry.settings['admin_prefix'], dbPrivateKey.id))
        items_paged = lib_db.get__SslServerCertificate__by_SslPrivateKeyId__paginated(
            self.request.api_context, dbPrivateKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslPrivateKey': dbPrivateKey,
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:private_key:focus:certificate_requests', renderer='/admin/private_key-focus-certificate_requests.mako')
    @view_config(route_name='admin:private_key:focus:certificate_requests_paginated', renderer='/admin/private_key-focus-certificate_requests.mako')
    def private_key_focus__certificate_requests(self):
        dbPrivateKey = self._private_key_focus()
        items_count = lib_db.get__SslCertificateRequest__by_SslPrivateKeyId__count(
            self.request.api_context, dbPrivateKey.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/private-key/%s/certificate-requests/{0}' % (self.request.registry.settings['admin_prefix'], dbPrivateKey.id))
        items_paged = lib_db.get__SslCertificateRequest__by_SslPrivateKeyId__paginated(
            self.request.api_context, dbPrivateKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslPrivateKey': dbPrivateKey,
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:private_key:new')
    def private_key_new(self):
        if self.request.method == 'POST':
            return self._private_key_new__submit()
        return self._private_key_new__print()

    def _private_key_new__print(self):
        return render_to_response("/admin/private_key-new.mako", {}, self.request)

    def _private_key_new__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_PrivateKey_new__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            private_key_pem = formStash.results['private_key_file'].file.read()
            dbPrivateKey, _is_created = lib_db.getcreate__SslPrivateKey__by_pem_text(self.request.api_context, private_key_pem)

            return HTTPFound('%s/private-key/%s?result=success%s' % (self.request.registry.settings['admin_prefix'], dbPrivateKey.id, ('&is_created=1' if _is_created else '')))

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._private_key_new__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:private_key:focus:mark', renderer=None)
    @view_config(route_name='admin:private_key:focus:mark.json', renderer='json')
    def private_key_focus_mark(self):
        dbPrivateKey = self._private_key_focus()
        action = '!MISSING or !INVALID'
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_PrivateKey_mark,
                                                             validate_get=True
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = SslOperationsEventType.from_string('private_key__mark')
            event_payload_dict = lib_utils.new_event_payload_dict()
            event_payload_dict['ssl_private_key.id'] = dbPrivateKey.id
            event_payload_dict['action'] = formStash.results['action']

            marked_comprimised = False
            event_status = None

            if action == 'active':
                if dbPrivateKey.is_active:
                    raise formhandling.FormInvalid('Already activated')
                if dbPrivateKey.is_compromised:
                    raise formhandling.FormInvalid('Can not activate a compromised key')
                dbPrivateKey.is_active = True
                event_status = 'private_key__mark__active'

            elif action == 'inactive':
                if not dbPrivateKey.is_active:
                    raise formhandling.FormInvalid('Already deactivated')
                dbPrivateKey.is_active = False
                event_status = 'private_key__mark__inactive'

            elif action == 'compromised':
                if dbPrivateKey.is_compromised:
                    raise formhandling.FormInvalid('Already compromised')
                dbPrivateKey.is_active = False
                dbPrivateKey.is_compromised = True
                event_type = SslOperationsEventType.from_string('private_key__revoke')
                marked_comprimised = True
                event_status = 'private_key__mark__compromised'
            else:
                raise formhandling.FormInvalid('invalid `action`')

            self.request.api_context.dbSession.flush()

            # bookkeeping
            dbOperationsEvent = lib_db.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )
            lib_db._log_object_event(self.request.api_context,
                                     dbOperationsEvent=dbOperationsEvent,
                                     event_status_id=SslOperationsObjectEventStatus.from_string(event_status),
                                     dbPrivateKey=dbPrivateKey,
                                     )
            if marked_comprimised:
                lib_events.PrivateKey_compromised(
                    self.request.api_context,
                    dbPrivateKey,
                )

            url_success = '%s/private-key/%s?operation=mark&action=%s&result=success' % (
                self.request.registry.settings['admin_prefix'],
                dbPrivateKey.id,
                action,
            )
            return HTTPFound(url_success)

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            url_failure = '%s/private-key/%s?operation=mark&action=%s&result=error&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbPrivateKey.id,
                action,
                e.message,
            )
            raise HTTPFound(url_failure)
