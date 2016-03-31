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
from ..lib import utils as lib_utils


# ==============================================================================


class ViewAdmin(Handler):
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificates', renderer='/admin/certificates.mako')
    @view_config(route_name='admin:certificates_paginated', renderer='/admin/certificates.mako')
    def certificates(self):
        items_count = lib_db.get__LetsencryptServerCertificate__count(DBSession)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/certificates/{0}')
        items_paged = lib_db.get__LetsencryptServerCertificate__paginated(DBSession, limit=items_per_page, offset=offset, eagerload_web=True)
        return {'project': 'peter_sslers',
                'LetsencryptServerCertificates_count': items_count,
                'LetsencryptServerCertificates': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    @view_config(route_name='admin:certificates:expiring', renderer='/admin/certificates.mako')
    @view_config(route_name='admin:certificates:expiring_paginated', renderer='/admin/certificates.mako')
    def certificates_expiring_only(self):
        expiring_days = self.request.registry.settings['expiring_days']
        items_count = lib_db.get__LetsencryptServerCertificate__count(DBSession, expiring_days=expiring_days)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/certificates/expiring/{0}')
        items_paged = lib_db.get__LetsencryptServerCertificate__paginated(DBSession, expiring_days=expiring_days, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptServerCertificates_count': items_count,
                'LetsencryptServerCertificates': items_paged,
                'sidenav_option': 'expiring',
                'expiring_days': expiring_days,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:upload')
    @view_config(route_name='admin:certificate:upload:json', renderer='json')
    def certificate_upload(self):
        if self.request.POST:
            return self._certificate_upload__submit()
        return self._certificate_upload__print()

    def _certificate_upload__print(self):
        if self.request.matched_route.name == 'admin:certificate:upload:json':
            return {'instructions': """curl --form 'private_key_file=@privkey1.pem' --form 'certificate_file=@cert1.pem' --form 'chain_file=@chain1.pem' http://127.0.0.1:6543/.well-known/admin/certificate/upload.json""",
                    'form_fields': {'private_key_file': 'required',
                                    'chain_file': 'required',
                                    'certificate_file': 'required',
                                    },
                    }
        return render_to_response("/admin/certificate-upload.mako", {}, self.request)

    def _certificate_upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateUpload__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            private_key_pem = formStash.results['private_key_file'].file.read()
            dbLetsencryptPrivateKey, pkey_is_created = lib_db.getcreate__LetsencryptPrivateKey__by_pem_text(
                DBSession,
                private_key_pem
            )

            chain_pem = formStash.results['chain_file'].file.read()
            dbLetsencryptCACertificate, cacert_is_created = lib_db.getcreate__LetsencryptCACertificate__by_pem_text(
                DBSession,
                chain_pem,
                'manual upload'
            )

            certificate_pem = formStash.results['certificate_file'].file.read()
            dbLetsencryptServerCertificate, cert_is_created = lib_db.getcreate__LetsencryptServerCertificate__by_pem_text(
                DBSession, certificate_pem,
                dbCACertificate=dbLetsencryptCACertificate,
                dbPrivateKey=dbLetsencryptPrivateKey,
                dbAccountKey=None,
            )

            if self.request.matched_route.name == 'admin:certificate:upload:json':
                return {'result': 'success',
                        'certificate': {'created': cert_is_created,
                                        'id': dbLetsencryptServerCertificate.id,
                                        'url': '/.well-known/admin/certificate/%s' % dbLetsencryptServerCertificate.id,
                                        },
                        'ca_certificate': {'created': cacert_is_created,
                                           'id': dbLetsencryptCACertificate.id,
                                           },
                        'private_key': {'created': pkey_is_created,
                                        'id': dbLetsencryptPrivateKey.id,
                                        },
                        }
            return HTTPFound('/.well-known/admin/certificate/%s' % dbLetsencryptServerCertificate.id)

        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            if self.request.matched_route.name == 'admin:certificate:upload:json':
                return {'result': 'error',
                        'form_errors': formStash.errors,
                        }
            return formhandling.form_reprint(
                self.request,
                self._certificate_upload__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _certificate_focus(self):
        dbLetsencryptServerCertificate = lib_db.get__LetsencryptServerCertificate__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptServerCertificate:
            raise HTTPNotFound('the certificate was not found')
        return dbLetsencryptServerCertificate

    @view_config(route_name='admin:certificate:focus', renderer='/admin/certificate-focus.mako')
    def certificate_focus(self):
        dbLetsencryptServerCertificate = self._certificate_focus()
        # x-x509-server-cert
        return {'project': 'peter_sslers',
                'LetsencryptServerCertificate': dbLetsencryptServerCertificate
                }

    @view_config(route_name='admin:certificate:focus:chain:raw', renderer='string')
    def certificate_focus_chain(self):
        dbLetsencryptServerCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptServerCertificate.certificate_upchain.cert_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptServerCertificate.certificate_upchain.cert_pem
        elif self.request.matchdict['format'] in ('cer', 'crt', 'der'):
            as_der = lib_acme.convert_pem_to_der(pem_data=dbLetsencryptServerCertificate.certificate_upchain.cert_pem)
            response = Response()
            if self.request.matchdict['format'] in ('crt', 'der'):
                response.content_type = 'application/x-x509-ca-cert'
            elif self.request.matchdict['format'] in ('cer', ):
                response.content_type = 'application/pkix-cert'
            response.body = as_der
            return response
        return 'chain.pem'

    @view_config(route_name='admin:certificate:focus:fullchain:raw', renderer='string')
    def certificate_focus_fullchain(self):
        dbLetsencryptServerCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptServerCertificate.cert_fullchain_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptServerCertificate.cert_fullchain_pem
        return 'fullchain.pem'

    @view_config(route_name='admin:certificate:focus:privatekey:raw', renderer='string')
    def certificate_focus_privatekey(self):
        dbLetsencryptServerCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptServerCertificate.private_key.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptServerCertificate.private_key.key_pem
        elif self.request.matchdict['format'] == 'key':
            as_der = lib_acme.convert_pem_to_der(pem_data=dbLetsencryptServerCertificate.private_key.key_pem)
            response = Response()
            response.content_type = 'application/pkcs8'
            response.body = as_der
            return response
        return 'privatekey.pem'

    @view_config(route_name='admin:certificate:focus:cert:raw', renderer='string')
    def certificate_focus_cert(self):
        dbLetsencryptServerCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptServerCertificate.cert_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptServerCertificate.cert_pem
        elif self.request.matchdict['format'] == 'crt':
            as_der = lib_acme.convert_pem_to_der(pem_data=dbLetsencryptServerCertificate.cert_pem)
            response = Response()
            response.content_type = 'application/x-x509-server-cert'
            response.body = as_der
            return response
        return 'cert.pem'

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:focus:config_json', renderer='json')
    def certificate_focus_json(self):
        dbLetsencryptServerCertificate = self._certificate_focus()
        if self.request.params.get('idonly', None):
            rval = dbLetsencryptServerCertificate.config_payload_idonly
        else:
            rval = dbLetsencryptServerCertificate.config_payload
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:focus:nginx_cache_expire', renderer=None)
    @view_config(route_name='admin:certificate:focus:nginx_cache_expire:json', renderer='json')
    def certificate_focus_nginx_expire(self):
        dbLetsencryptServerCertificate = self._certificate_focus()
        if not self.request.registry.settings['enable_nginx']:
            raise HTTPFound('/.well-known/admin/certificate/%s?error=no_nginx' % dbLetsencryptServerCertificate.id)
        dbDomains = [c2d.domain for c2d in dbLetsencryptServerCertificate.certificate_to_domains]
        success, dbEvent = lib_utils.nginx_expire_cache(self.request, DBSession, dbDomains=dbDomains)
        if self.request.matched_route.name == 'admin:certificate:focus:nginx_cache_expire:json':
            return {'result': 'success',
                    'operations_event': {'id': dbEvent.id,
                                         },
                    }
        return HTTPFound('/.well-known/admin/certificate/%s?operation=nginx_cache_expire&result=success&event.id=%s' % (dbLetsencryptServerCertificate.id, dbEvent.id))
