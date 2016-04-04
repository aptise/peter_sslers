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
from ..lib.forms import (Form_CertificateRequest_new_flow,
                         # Form_CertificateRequest_new_full,
                         Form_CertificateRequest_new_full__file,
                         Form_CertificateRequest_process_domain,
                         Form_CertificateUpload__file,
                         Form_CACertificateUpload__file,
                         Form_CACertificateUploadBundle__file,
                         Form_PrivateKey_new__file,
                         Form_AccountKey_new__file,
                         )
from ..lib import acme as lib_acme
from ..lib import cert_utils as lib_cert_utils
from ..lib import db as lib_db
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_keys', renderer='/admin/account_keys.mako')
    @view_config(route_name='admin:account_keys_paginated', renderer='/admin/account_keys.mako')
    def account_keys(self):
        items_count = lib_db.get__LetsencryptAccountKey__count(DBSession)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/account-keys/{0}')
        items_paged = lib_db.get__LetsencryptAccountKey__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptAccountKeys_count': items_count,
                'LetsencryptAccountKeys': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _account_key_focus(self, eagerload_web=False):
        dbLetsencryptAccountKey = lib_db.get__LetsencryptAccountKey__by_id(DBSession, self.request.matchdict['id'], eagerload_web=eagerload_web, )
        if not dbLetsencryptAccountKey:
            raise HTTPNotFound('the key was not found')
        return dbLetsencryptAccountKey

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus', renderer='/admin/account_key-focus.mako')
    def account_key_focus(self):
        dbLetsencryptAccountKey = self._account_key_focus(eagerload_web=True)
        return {'project': 'peter_sslers',
                'LetsencryptAccountKey': dbLetsencryptAccountKey
                }

    @view_config(route_name='admin:account_key:focus:raw', renderer='string')
    def account_key_focus_raw(self):
        dbLetsencryptAccountKey = self._account_key_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptAccountKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptAccountKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib_cert_utils.convert_pem_to_der(pem_data=dbLetsencryptAccountKey.key_pem)
            return as_der

    @view_config(route_name='admin:account_key:focus:parse.json', renderer='json')
    def account_key_focus_parse_json(self):
        dbLetsencryptAccountKey = self._account_key_focus()
        return {"%s" % dbLetsencryptAccountKey.id: lib_cert_utils.parse_key(key_pem=dbLetsencryptAccountKey.key_pem),
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:authenticate', renderer=None)
    def account_key_focus__authenticate(self):
        dbLetsencryptAccountKey = self._account_key_focus()
        is_authenticated = lib_db.do__LetsencryptAccountKey_authenticate(DBSession, dbLetsencryptAccountKey)
        return HTTPFound('/.well-known/admin/account-key/%s?is_authenticated=%s' % (dbLetsencryptAccountKey.id, ('1' if is_authenticated else '0')))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus:certificates', renderer='/admin/account_key-focus-certificates.mako')
    @view_config(route_name='admin:account_key:focus:certificates_paginated', renderer='/admin/account_key-focus-certificates.mako')
    def account_key_focus__certificates(self):
        dbLetsencryptAccountKey = self._account_key_focus()
        items_count = lib_db.get__LetsencryptServerCertificate__by_LetsencryptAccountKeyId__count(
            DBSession, dbLetsencryptAccountKey.id)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/account-key/%s/certificates/{0}' % dbLetsencryptAccountKey.id)
        items_paged = lib_db.get__LetsencryptServerCertificate__by_LetsencryptAccountKeyId__paginated(
            DBSession, dbLetsencryptAccountKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptAccountKey': dbLetsencryptAccountKey,
                'LetsencryptServerCertificates_count': items_count,
                'LetsencryptServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:account_key:focus:certificate_requests', renderer='/admin/account_key-focus-certificate_requests.mako')
    @view_config(route_name='admin:account_key:focus:certificate_requests_paginated', renderer='/admin/account_key-focus-certificate_requests.mako')
    def account_key_focus__certificate_requests(self):
        dbLetsencryptAccountKey = self._account_key_focus()
        items_count = lib_db.get__LetsencryptCertificateRequest__by_LetsencryptAccountKeyId__count(
            DBSession, dbLetsencryptAccountKey.id)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/account-key/%s/certificate-requests/{0}' % dbLetsencryptAccountKey.id)
        items_paged = lib_db.get__LetsencryptCertificateRequest__by_LetsencryptAccountKeyId__paginated(
            DBSession, dbLetsencryptAccountKey.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptAccountKey': dbLetsencryptAccountKey,
                'LetsencryptCertificateRequests_count': items_count,
                'LetsencryptCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:new')
    def account_key_new(self):
        if self.request.POST:
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
            dbLetsencryptAccountKey, _is_created = lib_db.getcreate__LetsencryptAccountKey__by_pem_text(DBSession, account_key_pem)

            return HTTPFound('/.well-known/admin/account-key/%s%s' % (dbLetsencryptAccountKey.id, ('?is_created=1' if _is_created else '')))

        except formhandling.FormInvalid:
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
