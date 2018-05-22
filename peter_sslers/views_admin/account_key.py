# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import json

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import models
from .. import lib
from ..lib import db as lib_db
from ..lib import text as lib_text
from ..lib.forms import Form_AccountKey_new__file
from ..lib.forms import Form_AccountKey_mark
from ..lib.form_utils import AccountKeyUploadParser
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin_List(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_keys', renderer='/admin/account_keys.mako')
    @view_config(route_name='admin:account_keys_paginated', renderer='/admin/account_keys.mako')
    @view_config(route_name='admin:account_keys|json', renderer='json')
    @view_config(route_name='admin:account_keys_paginated|json', renderer='json')
    def list(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        items_count = lib_db.get.get__SslAcmeAccountKey__count(self.request.api_context)
        if wants_json:
            (pager, offset) = self._paginate(items_count, url_template='%s/account-keys/{0}.json' % self.request.registry.settings['admin_prefix'])
        else:
            (pager, offset) = self._paginate(items_count, url_template='%s/account-keys/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslAcmeAccountKey__paginated(self.request.api_context, limit=items_per_page, offset=offset)
        if wants_json:
            _accountKeys = {k.id: k.as_json for k in items_paged}
            return {'SslAcmeAccountKeys': _accountKeys,
                    'pagination': {'total_items': items_count,
                                   'page': pager.page_num,
                                   'page_next': pager.next if pager.has_next else None,
                                   }
                    }
        return {'project': 'peter_sslers',
                'SslAcmeAccountKeys_count': items_count,
                'SslAcmeAccountKeys': items_paged,
                'pager': pager,
                }


class ViewAdmin_New(Handler):

    @view_config(route_name='admin:account_key:upload')
    @view_config(route_name='admin:account_key:upload|json', renderer="json")
    def upload(self):
        if self.request.method == 'POST':
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'instructions': ["""curl --form 'account_key_file_pem=@key.pem' --form 'acme_account_provider_id=1' %s/account-key/upload.json""" % self.request.admin_url,
                                     """curl --form 'account_key_file_le_meta=@meta.json' 'account_key_file_le_pkey=@private_key.json' 'account_key_file_le_reg=@regr.json' %s/account-key/upload.json""" % self.request.admin_url,
                                     ],
                    'form_fields': {'account_key_file_pem': 'Group A',
                                    'acme_account_provider_id': 'Group A',
                                    'account_key_file_le_meta': 'Group B',
                                    'account_key_file_le_pkey': 'Group B',
                                    'account_key_file_le_reg': 'Group B',
                                    },
                    'notes': ["You must submit ALL items from Group A or Group B"
                              ],
                    'valid_options': {'acme_account_provider_id': {v['id']: v['name'] for v in models.AcmeAccountProvider.registry.values()},
                                      }
                    }
        # quick setup, we need a bunch of options for dropdowns...
        providers = models.AcmeAccountProvider.registry.values()
        return render_to_response("/admin/account_key-upload.mako", {'AcmeAccountProviderOptions': providers}, self.request)

    def _upload__submit(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        try:
            (result,
             formStash
             ) = formhandling.form_validate(self.request,
                                            schema=Form_AccountKey_new__file,
                                            validate_get=False
                                            )
            if not result:
                raise formhandling.FormInvalid()

            parser = AccountKeyUploadParser(formStash)
            parser.require_upload()
            key_create_args = parser.getcreate_args

            (dbAcmeAccountKey,
             _is_created
             ) = lib_db.getcreate.getcreate__SslAcmeAccountKey(
                self.request.api_context,
                **key_create_args
            )

            if wants_json:
                return {'result': 'success',
                        'AcmeAccountKey': dbAcmeAccountKey.as_json,
                        'is_created': True if _is_created else False,
                        'is_existing': False if _is_created else True,
                        }
            return HTTPSeeOther('%s/account-key/%s?result=success%s' % (
                self.request.admin_url,
                dbAcmeAccountKey.id,
                ('&is_created=1' if _is_created else '&is_existing=1')
            ))

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            if wants_json:
                return {'result': 'error',
                        'form_errors': formStash.errors,
                        }
            return formhandling.form_reprint(
                self.request,
                self._upload__print,
                auto_error_formatter=lib_text.formatter_error,
            )


class ViewAdmin_Focus(Handler):

    def _focus(self, eagerload_web=False):
        dbAcmeAccountKey = lib_db.get.get__SslAcmeAccountKey__by_id(self.request.api_context, self.request.matchdict['id'], eagerload_web=eagerload_web, )
        if not dbAcmeAccountKey:
            raise HTTPNotFound('the key was not found')
        self._focus_url = "%s/account-key/%s" % (self.request.admin_url, dbAcmeAccountKey.id)
        return dbAcmeAccountKey

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus', renderer='/admin/account_key-focus.mako')
    @view_config(route_name='admin:account_key:focus|json', renderer='json')
    def focus(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        dbAcmeAccountKey = self._focus(eagerload_web=True)
        if wants_json:
            _prefix = "%s" % (self._focus_url)
            return {"LetsEncryptAccountKey": dbAcmeAccountKey.as_json,
                    "raw": {"pem.txt": "%s/key.pem.txt" % _prefix,
                            "pem": "%s/key.pem" % _prefix,
                            "der": "%s/key.key" % _prefix,
                            }
                    }
        return {'project': 'peter_sslers',
                'SslAcmeAccountKey': dbAcmeAccountKey
                }

    @view_config(route_name='admin:account_key:focus:raw', renderer='string')
    def focus_raw(self):
        dbAcmeAccountKey = self._focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbAcmeAccountKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbAcmeAccountKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib.cert_utils.convert_pem_to_der(pem_data=dbAcmeAccountKey.key_pem)
            return as_der

    @view_config(route_name='admin:account_key:focus:parse|json', renderer='json')
    def focus_parse_json(self):
        dbAcmeAccountKey = self._focus()
        return {"%s" % dbAcmeAccountKey.id: lib.cert_utils.parse_key(key_pem=dbAcmeAccountKey.key_pem),
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:config|json', renderer='json')
    def focus_config_json(self):
        dbAcmeAccountKey = self._focus(eagerload_web=True)
        return {'id': dbAcmeAccountKey.id,
                'is_active': dbAcmeAccountKey.is_active,
                'is_default': dbAcmeAccountKey.is_default,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:authenticate', renderer=None)
    @view_config(route_name='admin:account_key:focus:authenticate|json', renderer='json')
    def focus__authenticate(self):
        """
        this just hits the api, hoping we authenticate correctly.
        """
        dbAcmeAccountKey = self._focus()
        if self.request.method == 'POST':
            return self._focus__authenticate__submit(dbAcmeAccountKey)
        return self._focus__authenticate__print(dbAcmeAccountKey)

    def _focus__authenticate__print(self, dbAcmeAccountKey):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'instructions': ["""curl -X POST %s/authenticate.json""" % self._focus_url,
                                     ],
                    }
        url_post_required = '%s?operation=authenticate&result=post+required' % (self._focus_url, )
        return HTTPSeeOther(url_post_required)

    def _focus__authenticate__submit(self, dbAcmeAccountKey):
        # result is either: `new-account` or `existing-account`
        # failing will raise an exception
        result = lib_db.actions.do__SslAcmeAccountKey_authenticate(self.request.api_context, dbAcmeAccountKey)
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {"LetsEncryptAccountKey": dbAcmeAccountKey.as_json, }
        return HTTPSeeOther('%s?result=success&is_authenticated=%s' % (self._focus_url, result))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:certificates', renderer='/admin/account_key-focus-certificates.mako')
    @view_config(route_name='admin:account_key:focus:certificates_paginated', renderer='/admin/account_key-focus-certificates.mako')
    def focus__certificates(self):
        dbAcmeAccountKey = self._focus()
        items_count = lib_db.get.get__SslServerCertificate__by_SslAcmeAccountKeyId__count(
            self.request.api_context, dbAcmeAccountKey.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/certificates/{0}' % (self._focus_url))
        items_paged = lib_db.get.get__SslServerCertificate__by_SslAcmeAccountKeyId__paginated(
            self.request.api_context, dbAcmeAccountKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslAcmeAccountKey': dbAcmeAccountKey,
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:account_key:focus:certificate_requests', renderer='/admin/account_key-focus-certificate_requests.mako')
    @view_config(route_name='admin:account_key:focus:certificate_requests_paginated', renderer='/admin/account_key-focus-certificate_requests.mako')
    def focus__certificate_requests(self):
        dbAcmeAccountKey = self._focus()
        items_count = lib_db.get.get__SslCertificateRequest__by_SslAcmeAccountKeyId__count(
            self.request.api_context, dbAcmeAccountKey.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/certificate-requests/{0}' % (self._focus_url))
        items_paged = lib_db.get.get__SslCertificateRequest__by_SslAcmeAccountKeyId__paginated(
            self.request.api_context, dbAcmeAccountKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslAcmeAccountKey': dbAcmeAccountKey,
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:mark', renderer=None)
    @view_config(route_name='admin:account_key:focus:mark|json', renderer='json')
    def focus_mark(self):
        dbAcmeAccountKey = self._focus()
        if self.request.method == 'POST':
            return self._focus_mark__submit(dbAcmeAccountKey)
        return self._focus_mark__print(dbAcmeAccountKey)

    def _focus_mark__print(self, dbAcmeAccountKey):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'instructions': ["""curl --form 'action=active' %s/mark.json""" % self._focus_url,
                                     ],
                    'form_fields': {'action': 'the intended action',
                                    },
                    'valid_options': {'action': ['default', 'active', 'inactive'],
                                      }
                    }
        url_post_required = '%s?operation=mark&result=post+required' % (self._focus_url)
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self, dbAcmeAccountKey):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        try:
            (result,
             formStash
             ) = formhandling.form_validate(self.request,
                                            schema=Form_AccountKey_mark,
                                            validate_get=False,
                                            # validate_post=False
                                            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = models.SslOperationsEventType.from_string('acme_account_key__mark')
            event_payload_dict = lib.utils.new_event_payload_dict()
            event_payload_dict['account_key_id'] = dbAcmeAccountKey.id
            event_payload_dict['action'] = formStash.results['action']

            event_status = False
            event_alt = None

            if action == 'active':
                if dbAcmeAccountKey.is_active:
                    formStash.set_error(field='Error_Main',
                                        message='Already activated',
                                        raise_FormInvalid=True,
                                        )
                dbAcmeAccountKey.is_active = True
                event_status = 'acme_account_key__mark__active'

            elif action == 'inactive':
                if dbAcmeAccountKey.is_default:
                    formStash.set_error(field='Error_Main',
                                        message='You can not deactivate the default. Make another key default first.',
                                        raise_FormInvalid=True,
                                        )
                if not dbAcmeAccountKey.is_active:
                    formStash.set_error(field='Error_Main',
                                        message='Already deactivated.',
                                        raise_FormInvalid=True,
                                        )
                dbAcmeAccountKey.is_active = False
                event_status = 'acme_account_key__mark__inactive'

            elif action == 'default':
                if dbAcmeAccountKey.is_default:
                    formStash.set_error(field='Error_Main',
                                        message='Already default.',
                                        raise_FormInvalid=True,
                                        )
                formerDefaultKey = lib_db.get.get__SslAcmeAccountKey__default(self.request.api_context)
                if formerDefaultKey:
                    formerDefaultKey.is_default = False
                    event_payload_dict['account_key_id.former_default'] = formerDefaultKey.id
                    event_alt = ('acme_account_key__mark__notdefault', formerDefaultKey)
                dbAcmeAccountKey.is_default = True
                event_status = 'acme_account_key__mark__default'

            else:
                formStash.set_error(field='action',
                                    message='invalid option',
                                    raise_FormInvalid=True,
                                    )

            self.request.api_context.dbSession.flush(objects=[dbAcmeAccountKey, ])

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )
            lib_db.logger._log_object_event(self.request.api_context,
                                            dbOperationsEvent=dbOperationsEvent,
                                            event_status_id=models.SslOperationsObjectEventStatus.from_string(event_status),
                                            dbAcmeAccountKey=dbAcmeAccountKey,
                                            )
            if event_alt:
                lib_db.logger._log_object_event(self.request.api_context,
                                                dbOperationsEvent=dbOperationsEvent,
                                                event_status_id=models.SslOperationsObjectEventStatus.from_string(event_alt[0]),
                                                dbAcmeAccountKey=event_alt[1],
                                                )
            if wants_json:
                return {'result': 'success',
                        'SslAcmeAccountKey': dbAcmeAccountKey,
                        }
            url_success = '%s?operation=mark&action=%s&result=success' % (self._focus_url, action,)
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            if wants_json:
                return {'result': 'error',
                        'form_errors': formStash.errors,
                        }
            url_failure = '%s/operation=mark&action=%s&result=error&error=%s' % (
                self._focus_url,
                action,
                e.message,
            )
            raise HTTPSeeOther(url_failure)
