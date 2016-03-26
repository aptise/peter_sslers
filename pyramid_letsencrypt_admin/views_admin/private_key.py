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
from ..lib import db as lib_db
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:private_keys', renderer='/admin/private_keys.mako')
    @view_config(route_name='admin:private_keys_paginated', renderer='/admin/private_keys.mako')
    def private_keys(self):
        items_count = lib_db.get__LetsencryptPrivateKey__count(DBSession)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/private_keys/{0}')
        items_paged = lib_db.get__LetsencryptPrivateKey__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptPrivateKeys_count': items_count,
                'LetsencryptPrivateKeys': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:private_key:focus', renderer='/admin/private_key-focus.mako')
    def private_key_focus(self):
        dbLetsencryptPrivateKey = lib_db.get__LetsencryptPrivateKey__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptPrivateKey:
            raise HTTPNotFound('the key was not found')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptPrivateKey': dbLetsencryptPrivateKey
                }

    @view_config(route_name='admin:private_key:focus:raw', renderer='string')
    def private_key_focus_raw(self):
        dbLetsencryptPrivateKey = lib_db.get__LetsencryptPrivateKey__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptPrivateKey:
            raise HTTPNotFound('the key was not found')
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptPrivateKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptPrivateKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib_acme.convert_pem_to_der(pem_data=dbLetsencryptPrivateKey.key_pem)
            return as_der

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:private_key:new')
    def private_key_new(self):
        if self.request.POST:
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
            dbLetsencryptPrivateKey, _is_created = lib_db.getcreate__LetsencryptPrivateKey__by_pem_text(DBSession, private_key_pem)

            return HTTPFound('/.well-known/admin/private_key/%s%s' % (dbLetsencryptPrivateKey.id, ('?is_created=1' if _is_created else '')))

        except formhandling.FormInvalid:
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
