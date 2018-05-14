# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import models
from .. import lib
from ..lib.forms import (Form_AccountKey_new__file,
                         Form_AccountKey_mark,
                         )
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_keys', renderer='/admin/account_keys.mako')
    @view_config(route_name='admin:account_keys_paginated', renderer='/admin/account_keys.mako')
    def account_keys(self):
        items_count = lib.db.get.get__SslLetsEncryptAccountKey__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/account-keys/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib.db.get.get__SslLetsEncryptAccountKey__paginated(self.request.api_context, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslLetsEncryptAccountKeys_count': items_count,
                'SslLetsEncryptAccountKeys': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _account_key_focus(self, eagerload_web=False):
        dbLetsEncryptAccountKey = lib.db.get.get__SslLetsEncryptAccountKey__by_id(self.request.api_context, self.request.matchdict['id'], eagerload_web=eagerload_web, )
        if not dbLetsEncryptAccountKey:
            raise HTTPNotFound('the key was not found')
        return dbLetsEncryptAccountKey

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus', renderer='/admin/account_key-focus.mako')
    def account_key_focus(self):
        dbLetsEncryptAccountKey = self._account_key_focus(eagerload_web=True)
        return {'project': 'peter_sslers',
                'SslLetsEncryptAccountKey': dbLetsEncryptAccountKey
                }

    @view_config(route_name='admin:account_key:focus:raw', renderer='string')
    def account_key_focus_raw(self):
        dbLetsEncryptAccountKey = self._account_key_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsEncryptAccountKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsEncryptAccountKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib.cert_utils.convert_pem_to_der(pem_data=dbLetsEncryptAccountKey.key_pem)
            return as_der

    @view_config(route_name='admin:account_key:focus:parse.json', renderer='json')
    def account_key_focus_parse_json(self):
        dbLetsEncryptAccountKey = self._account_key_focus()
        return {"%s" % dbLetsEncryptAccountKey.id: lib.cert_utils.parse_key(key_pem=dbLetsEncryptAccountKey.key_pem),
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:config_json', renderer='json')
    def account_key_focus_config_json(self):
        dbLetsEncryptAccountKey = self._account_key_focus(eagerload_web=True)
        return {'id': dbLetsEncryptAccountKey.id,
                'is_active': dbLetsEncryptAccountKey.is_active,
                'is_default': dbLetsEncryptAccountKey.is_default,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:authenticate', renderer=None)
    def account_key_focus__authenticate(self):
        dbLetsEncryptAccountKey = self._account_key_focus()
        is_authenticated = lib.db.actions.do__SslLetsEncryptAccountKey_authenticate(self.request.api_context, dbLetsEncryptAccountKey)
        return HTTPFound('%s/account-key/%s?result=success&is_authenticated=%s' % (self.request.registry.settings['admin_prefix'], dbLetsEncryptAccountKey.id, ('1' if is_authenticated else '0')))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:certificates', renderer='/admin/account_key-focus-certificates.mako')
    @view_config(route_name='admin:account_key:focus:certificates_paginated', renderer='/admin/account_key-focus-certificates.mako')
    def account_key_focus__certificates(self):
        dbLetsEncryptAccountKey = self._account_key_focus()
        items_count = lib.db.get.get__SslServerCertificate__by_SslLetsEncryptAccountKeyId__count(
            self.request.api_context, dbLetsEncryptAccountKey.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/account-key/%s/certificates/{0}' % (self.request.registry.settings['admin_prefix'], dbLetsEncryptAccountKey.id))
        items_paged = lib.db.get.get__SslServerCertificate__by_SslLetsEncryptAccountKeyId__paginated(
            self.request.api_context, dbLetsEncryptAccountKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslLetsEncryptAccountKey': dbLetsEncryptAccountKey,
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:account_key:focus:certificate_requests', renderer='/admin/account_key-focus-certificate_requests.mako')
    @view_config(route_name='admin:account_key:focus:certificate_requests_paginated', renderer='/admin/account_key-focus-certificate_requests.mako')
    def account_key_focus__certificate_requests(self):
        dbLetsEncryptAccountKey = self._account_key_focus()
        items_count = lib.db.get.get__SslCertificateRequest__by_SslLetsEncryptAccountKeyId__count(
            self.request.api_context, dbLetsEncryptAccountKey.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/account-key/%s/certificate-requests/{0}' % (self.request.registry.settings['admin_prefix'], dbLetsEncryptAccountKey.id))
        items_paged = lib.db.get.get__SslCertificateRequest__by_SslLetsEncryptAccountKeyId__paginated(
            self.request.api_context, dbLetsEncryptAccountKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslLetsEncryptAccountKey': dbLetsEncryptAccountKey,
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:new')
    def account_key_new(self):
        if self.request.method == 'POST':
            return self._account_key_new__submit()
        return self._account_key_new__print()

    def _account_key_new__print(self):
        return render_to_response("/admin/account_key-new.mako", {}, self.request)

    def _account_key_new__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_AccountKey_new__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            account_key_pem = formStash.results['account_key_file'].file.read()
            (dbLetsEncryptAccountKey,
             _is_created
             ) = lib.db.getcreate.getcreate__SslLetsEncryptAccountKey__by_pem_text(
                self.request.api_context,
                account_key_pem,
            )

            return HTTPFound('%s/account-key/%s?result=success%s' % (self.request.registry.settings['admin_prefix'], dbLetsEncryptAccountKey.id, ('&is_created=1' if _is_created else '')))

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._account_key_new__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:mark', renderer=None)
    @view_config(route_name='admin:account_key:focus:mark.json', renderer='json')
    def account_key_focus_mark(self):
        dbLetsEncryptAccountKey = self._account_key_focus()
        action = '!MISSING or !INVALID'
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_AccountKey_mark,
                                                             validate_get=True
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = models.SslOperationsEventType.from_string('letsencrypt_account_key__mark')
            event_payload_dict = lib.utils.new_event_payload_dict()
            event_payload_dict['account_key_id'] = dbLetsEncryptAccountKey.id
            event_payload_dict['action'] = formStash.results['action']

            event_status = False
            event_alt = None

            if action == 'active':
                if dbLetsEncryptAccountKey.is_active:
                    raise formhandling.FormInvalid('Already activated')
                dbLetsEncryptAccountKey.is_active = True
                event_status = 'letsencrypt_account_key__mark__active'

            elif action == 'inactive':
                if dbLetsEncryptAccountKey.is_default:
                    raise formhandling.FormInvalid('You can not deactivate the default. Make another key default first.')
                if not dbLetsEncryptAccountKey.is_active:
                    raise formhandling.FormInvalid('Already deactivated')
                dbLetsEncryptAccountKey.is_active = False
                event_status = 'letsencrypt_account_key__mark__inactive'

            elif action == 'default':
                if dbLetsEncryptAccountKey.is_default:
                    raise formhandling.FormInvalid('Already default')
                formerDefaultKey = lib.db.get.get__SslLetsEncryptAccountKey__default(self.request.api_context)
                if formerDefaultKey:
                    formerDefaultKey.is_default = False
                    event_payload_dict['account_key_id.former_default'] = formerDefaultKey.id
                    event_alt = ('letsencrypt_account_key__mark__notdefault', formerDefaultKey)
                dbLetsEncryptAccountKey.is_default = True
                event_status = 'letsencrypt_account_key__mark__default'

            else:
                raise formhandling.FormInvalid('invalid `action`')

            self.request.api_context.dbSession.flush(objects=[dbLetsEncryptAccountKey, ])

            # bookkeeping
            dbOperationsEvent = lib.db.logger.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )
            lib.db.logger._log_object_event(self.request.api_context,
                                            dbOperationsEvent=dbOperationsEvent,
                                            event_status_id=models.SslOperationsObjectEventStatus.from_string(event_status),
                                            dbLetsEncryptAccountKey=dbLetsEncryptAccountKey,
                                            )
            if event_alt:
                lib.db.logger._log_object_event(self.request.api_context,
                                                dbOperationsEvent=dbOperationsEvent,
                                                event_status_id=models.SslOperationsObjectEventStatus.from_string(event_alt[0]),
                                                dbLetsEncryptAccountKey=event_alt[1],
                                                )
            url_success = '%s/account-key/%s?operation=mark&action=%s&result=success' % (
                self.request.registry.settings['admin_prefix'],
                dbLetsEncryptAccountKey.id,
                action,
            )
            return HTTPFound(url_success)

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            url_failure = '%s/account-key/%s?operation=mark&action=%s&result=error&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbLetsEncryptAccountKey.id,
                action,
                e.message,
            )
            raise HTTPFound(url_failure)
