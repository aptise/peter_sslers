# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import sqlalchemy

# localapp
from ..models import models
from .. import lib
from ..lib import db as lib_db
from ..lib import formhandling
from ..lib import text as lib_text
from ..lib.forms import Form_PrivateKey_mark
from ..lib.forms import Form_PrivateKey_new__file
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin_List(Handler):

    @view_config(route_name='admin:private_keys', renderer='/admin/private_keys.mako')
    @view_config(route_name='admin:private_keys_paginated', renderer='/admin/private_keys.mako')
    @view_config(route_name='admin:private_keys|json', renderer='json')
    @view_config(route_name='admin:private_keys_paginated|json', renderer='json')
    def list(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        items_count = lib_db.get.get__SslPrivateKey__count(self.request.api_context)
        if wants_json:
            (pager, offset) = self._paginate(items_count, url_template='%s/private-keys/{0}' % self.request.registry.settings['admin_prefix'])
        else:
            (pager, offset) = self._paginate(items_count, url_template='%s/private-keys/{0}.json' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslPrivateKey__paginated(self.request.api_context, limit=items_per_page, offset=offset)
        if wants_json:
            _keys = {k.id: k.as_json for k in items_paged}
            return {'SslPrivateKeys': _keys,
                    'pagination': {'total_items': items_count,
                                   'page': pager.page_num,
                                   'page_next': pager.next if pager.has_next else None,
                                   }
                    }
        return {'project': 'peter_sslers',
                'SslPrivateKeys_count': items_count,
                'SslPrivateKeys': items_paged,
                'pager': pager,
                }


class ViewAdmin_Focus(Handler):

    def _focus(self, eagerload_web=False):
        dbPrivateKey = lib_db.get.get__SslPrivateKey__by_id(self.request.api_context, self.request.matchdict['id'], eagerload_web=eagerload_web, )
        if not dbPrivateKey:
            raise HTTPNotFound('the key was not found')
        self._focus_item = dbPrivateKey
        self._focus_url = "%s/private-key/%s" % (self.request.registry.settings['admin_prefix'], dbPrivateKey.id)
        return dbPrivateKey

    @view_config(route_name='admin:private_key:focus', renderer='/admin/private_key-focus.mako')
    @view_config(route_name='admin:private_key:focus|json', renderer='json')
    def focus(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        dbPrivateKey = self._focus(eagerload_web=True)
        if wants_json:
            return {"SslPrivateKey": dbPrivateKey.as_json,
                    "raw": {"pem.txt": "%s/key.pem.txt" % self._focus_url,
                            "pem": "%s/key.pem" % self._focus_url,
                            "der": "%s/key.key" % self._focus_url,
                            }
                    }
        return {'project': 'peter_sslers',
                'SslPrivateKey': dbPrivateKey
                }

    @view_config(route_name='admin:private_key:focus:raw', renderer='string')
    def focus_raw(self):
        dbPrivateKey = self._focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbPrivateKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbPrivateKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib.cert_utils.convert_pem_to_der(pem_data=dbPrivateKey.key_pem)
            return as_der

    @view_config(route_name='admin:private_key:focus:parse|json', renderer='json')
    def focus_parse_json(self):
        dbPrivateKey = self._focus()
        return {"%s" % dbPrivateKey.id: lib.cert_utils.parse_key(key_pem=dbPrivateKey.key_pem),
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:private_key:focus:certificates', renderer='/admin/private_key-focus-certificates.mako')
    @view_config(route_name='admin:private_key:focus:certificates_paginated', renderer='/admin/private_key-focus-certificates.mako')
    def focus__certificates(self):
        dbPrivateKey = self._focus()
        items_count = lib_db.get.get__SslServerCertificate__by_SslPrivateKeyId__count(
            self.request.api_context, dbPrivateKey.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/certificates/{0}' % self._focus_url)
        items_paged = lib_db.get.get__SslServerCertificate__by_SslPrivateKeyId__paginated(
            self.request.api_context, dbPrivateKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslPrivateKey': dbPrivateKey,
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:private_key:focus:certificate_requests', renderer='/admin/private_key-focus-certificate_requests.mako')
    @view_config(route_name='admin:private_key:focus:certificate_requests_paginated', renderer='/admin/private_key-focus-certificate_requests.mako')
    def focus__certificate_requests(self):
        dbPrivateKey = self._focus()
        items_count = lib_db.get.get__SslCertificateRequest__by_SslPrivateKeyId__count(
            self.request.api_context, dbPrivateKey.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/certificate-requests/{0}' % self._focus_url)
        items_paged = lib_db.get.get__SslCertificateRequest__by_SslPrivateKeyId__paginated(
            self.request.api_context, dbPrivateKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslPrivateKey': dbPrivateKey,
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:private_key:focus:mark', renderer=None)
    @view_config(route_name='admin:private_key:focus:mark|json', renderer='json')
    def focus_mark(self):
        dbPrivateKey = self._focus()
        if self.request.method == 'POST':
            return self._focus_mark__submit(dbPrivateKey)
        return self._focus_mark__print(dbPrivateKey)

    def _focus_mark__print(self, dbPrivateKey):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'instructions': ["""curl --form 'action=active' %s/mark.json""" % self._focus_url,
                                     ],
                    'form_fields': {'action': 'the intended action',
                                    },
                    'valid_options': {'action': ['compromised', 'active', 'inactive', 'default'],
                                      }
                    }
        url_post_required = '%s?operation=mark&result=post+required' % self._focus_url
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self, dbPrivateKey):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        try:
            (result,
             formStash
             ) = formhandling.form_validate(self.request,
                                            schema=Form_PrivateKey_mark,
                                            validate_get=True
                                            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = models.SslOperationsEventType.from_string('private_key__mark')
            event_payload_dict = lib.utils.new_event_payload_dict()
            event_payload_dict['ssl_private_key.id'] = dbPrivateKey.id
            event_payload_dict['action'] = formStash.results['action']

            marked_comprimised = False
            event_status = None

            if action == 'active':
                if dbPrivateKey.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field='action',
                                          message="Already activated",
                                          )

                if dbPrivateKey.is_compromised:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field='action',
                                          message="Can not activate a compromised key",
                                          )

                dbPrivateKey.is_active = True
                event_status = 'private_key__mark__active'

            elif action == 'inactive':
                if not dbPrivateKey.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field='action',
                                          message="Already deactivated",
                                          )

                dbPrivateKey.is_active = False
                event_status = 'private_key__mark__inactive'

            elif action == 'compromised':
                if dbPrivateKey.is_compromised:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field='action',
                                          message="Already compromised",
                                          )

                dbPrivateKey.is_active = False
                dbPrivateKey.is_compromised = True
                if dbPrivateKey.is_default:
                    dbPrivateKey.is_default = False
                event_type = models.SslOperationsEventType.from_string('private_key__revoke')
                marked_comprimised = True
                event_status = 'private_key__mark__compromised'

            elif action == 'default':
                if dbPrivateKey.is_default:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field='action',
                                          message="Already default",
                                          )

                if not dbPrivateKey.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field='action',
                                          message="Key not active",
                                          )

                formerDefaultKey = lib_db.get.get__SslPrivateKey__default(self.request.api_context)
                if formerDefaultKey:
                    formerDefaultKey.is_default = False
                    event_payload_dict['private_key_id.former_default'] = formerDefaultKey.id
                    event_alt = ('private_key__mark__notdefault', formerDefaultKey)
                dbPrivateKey.is_default = True
                event_status = 'private_key__mark__default'

            else:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(field='action',
                                      message="invalid `action`",
                                      )

            self.request.api_context.dbSession.flush(objects=[dbPrivateKey, ])

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )
            lib_db.logger._log_object_event(self.request.api_context,
                                            dbOperationsEvent=dbOperationsEvent,
                                            event_status_id=models.SslOperationsObjectEventStatus.from_string(event_status),
                                            dbPrivateKey=dbPrivateKey,
                                            )
            if marked_comprimised:
                lib.events.PrivateKey_compromised(
                    self.request.api_context,
                    dbPrivateKey,
                    dbOperationsEvent=dbOperationsEvent,
                )

            if wants_json:
                return {'result': 'success',
                        'SslDomain': dbPrivateKey.as_json,
                        }
            url_success = '%s?operation=mark&action=%s&result=success' % (self._focus_url, action, )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if wants_json:
                return {'result': 'error',
                        'form_errors': formStash.errors,
                        }
            url_failure = '%s?operation=mark&action=%s&result=error&error=%s' % (
                self._focus_url,
                action,
                exc.message,
            )
            raise HTTPSeeOther(url_failure)


class ViewAdmin_New(Handler):

    @view_config(route_name='admin:private_key:upload')
    @view_config(route_name='admin:private_key:upload|json', renderer='json')
    def upload(self):
        if self.request.method == 'POST':
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'instructions': """curl --form 'private_key_file=@privkey1.pem' %s/private-key/upload.json""" % (self.request.registry.settings['admin_prefix']),
                    'form_fields': {'private_key_file': 'required',
                                    },
                    }

        return render_to_response("/admin/private_key-upload.mako", {}, self.request)

    def _upload__submit(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        try:
            (result,
             formStash
             ) = formhandling.form_validate(self.request,
                                            schema=Form_PrivateKey_new__file,
                                            validate_get=False
                                            )
            if not result:
                raise formhandling.FormInvalid()

            private_key_pem = formStash.results['private_key_file'].file.read()
            (dbPrivateKey,
             _is_created
             ) = lib_db.getcreate.getcreate__SslPrivateKey__by_pem_text(self.request.api_context, private_key_pem)

            if wants_json:
                return {'result': 'success',
                        'is_created': True if _is_created else False,
                        'SslPrivateKey': dbPrivateKey.as_json,
                        }
            return HTTPSeeOther('%s/private-key/%s?result=success%s' % (self.request.registry.settings['admin_prefix'], dbPrivateKey.id, ('&is_created=1' if _is_created else '')))

        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(
                self.request,
                self._upload__print,
            )
