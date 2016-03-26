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

    @view_config(route_name='admin:ca_certificates', renderer='/admin/ca_certificates.mako')
    @view_config(route_name='admin:ca_certificates_paginated', renderer='/admin/ca_certificates.mako')
    def ca_certificates(self):
        items_count = lib_db.get__LetsencryptCACertificate__count(DBSession)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/ca_certificates/{0}')
        items_paged = lib_db.get__LetsencryptCACertificate__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificates_count': items_count,
                'LetsencryptCACertificates': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _ca_certificate_focus(self):
        dbLetsencryptCACertificate = lib_db.get__LetsencryptCACertificate__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptCACertificate:
            raise HTTPNotFound('the cert was not found')
        return dbLetsencryptCACertificate

    @view_config(route_name='admin:ca_certificate:focus', renderer='/admin/ca_certificate-focus.mako')
    def ca_certificate_focus(self):
        dbLetsencryptCACertificate = self._ca_certificate_focus()
        items_count = lib_db.get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__count(
            DBSession, dbLetsencryptCACertificate.id)
        items_paged = lib_db.get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__paginated(
            DBSession, dbLetsencryptCACertificate.id, limit=10, offset=0)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificate': dbLetsencryptCACertificate,
                'LetsencryptServerCertificates_count': items_count,
                'LetsencryptServerCertificates': items_paged,
                }

    @view_config(route_name='admin:ca_certificate:focus:raw', renderer='string')
    def ca_certificate_focus_raw(self):
        dbLetsencryptCACertificate = self._ca_certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptCACertificate.cert_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptCACertificate.cert_pem
        elif self.request.matchdict['format'] in ('cer', 'crt', 'der'):
            as_der = lib_acme.convert_pem_to_der(pem_data=dbLetsencryptCACertificate.cert_pem)
            response = Response()
            if self.request.matchdict['format'] in ('crt', 'der'):
                response.content_type = 'application/x-x509-ca-cert'
            elif self.request.matchdict['format'] in ('cer', ):
                response.content_type = 'application/pkix-cert'
            response.body = as_der
            return response
        return 'chain.?'

    @view_config(route_name='admin:ca_certificate:focus:signed_certificates', renderer='/admin/ca_certificate-focus-signed_certificates.mako')
    @view_config(route_name='admin:ca_certificate:focus:signed_certificates_paginated', renderer='/admin/ca_certificate-focus-signed_certificates.mako')
    def ca_certificate_focus__signed_certificates(self):
        dbLetsencryptCACertificate = self._ca_certificate_focus()
        items_count = lib_db.get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__count(
            DBSession, dbLetsencryptCACertificate.id)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/ca_certificate/%s/signed_certificates/{0}' % dbLetsencryptCACertificate.id)
        items_paged = lib_db.get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__paginated(
            DBSession, dbLetsencryptCACertificate.id, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificate': dbLetsencryptCACertificate,
                'LetsencryptServerCertificates_count': items_count,
                'LetsencryptServerCertificates': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:ca_certificate:upload')
    @view_config(route_name='admin:ca_certificate:upload:json', renderer='json')
    def ca_certificate_upload(self):
        if self.request.POST:
            return self._ca_certificate_upload__submit()
        return self._ca_certificate_upload__print()

    def _ca_certificate_upload__print(self):
        if self.request.matched_route.name == 'admin:ca_certificate:upload:json':
            return {'instructions': """curl --form 'chain_file=@chain1.pem' --form http://127.0.0.1:6543/.well-known/admin/ca_certificate/upload/json""",
                    'form_fields': {'chain_file': 'required',
                                    },
                    }
        return render_to_response("/admin/ca_certificate-new.mako", {}, self.request)

    def _ca_certificate_upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CACertificateUpload__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            chain_pem = formStash.results['chain_file'].file.read()
            chain_file_name = formStash.results['chain_file_name'] or 'manual upload'
            dbLetsencryptCACertificate, cacert_is_created = lib_db.getcreate__LetsencryptCACertificate__by_pem_text(
                DBSession,
                chain_pem,
                chain_file_name
            )

            if self.request.matched_route.name == 'admin:ca_certificate:upload:json':
                return {'result': 'success',
                        'ca_certificate': {'created': cacert_is_created,
                                           'id': dbLetsencryptCACertificate.id,
                                           },
                        }
            return HTTPFound('/.well-known/admin/ca_certificate/%s?is_created=%s' % (dbLetsencryptCACertificate.id, (1 if cacert_is_created else 0)))

        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            if self.request.matched_route.name == 'admin:ca_certificate:upload:json':
                return {'result': 'error',
                        'form_errors': formStash.errors,
                        }
            return formhandling.form_reprint(
                self.request,
                self._ca_certificate_upload__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:ca_certificate:upload_bundle')
    @view_config(route_name='admin:ca_certificate:upload_bundle:json', renderer='json')
    def ca_certificate_upload_bundle(self):
        if self.request.POST:
            return self._ca_certificate_upload_bundle__submit()
        return self._ca_certificate_upload_bundle__print()

    def _ca_certificate_upload_bundle__print(self):
        if self.request.matched_route.name == 'admin:ca_certificate:upload_bundle:json':
            return {'instructions': """curl --form 'isrgrootx1_file=@isrgrootx1.pem' --form 'le_x1_cross_signed_file=@lets-encrypt-x1-cross-signed.pem' --form 'le_x2_cross_signed_file=@lets-encrypt-x2-cross-signed.pem' --form 'le_x1_auth_file=@letsencryptauthorityx2.pem' --form 'le_x2_auth_file=@letsencryptauthorityx2.pem' --form http://127.0.0.1:6543/.well-known/admin/ca_certificate/upload_bundle/json""",
                    'form_fields': {'isrgrootx1_file': 'optional',
                                    'le_x1_cross_signed_file': 'optional',
                                    'le_x2_cross_signed_file': 'optional',
                                    'le_x1_auth_file': 'optional',
                                    'le_x2_auth_file': 'optional',
                                    },
                    }
        return render_to_response("/admin/ca_certificate-new_bundle.mako", {}, self.request)

    def _ca_certificate_upload_bundle__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CACertificateUploadBundle__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()
            has_uploads = [i for i in formStash.results.values() if i is not None]
            if not has_uploads:
                formStash.set_error(field="Error_Main",
                                    message="Nothing uploaded!",
                                    raise_FormInvalid=True,
                                    )

            bundle_data = {'isrgrootx1_pem': None,
                           'le_x1_cross_signed_pem': None,
                           'le_x2_cross_signed_pem': None,
                           'le_x1_auth_pem': None,
                           'le_x2_auth_pem': None,
                           }
            if formStash.results['isrgrootx1_file'] is not None:
                bundle_data['isrgrootx1_pem'] = formStash.results['isrgrootx1_file'].file.read()

            if formStash.results['le_x1_cross_signed_file'] is not None:
                bundle_data['le_x1_cross_signed_pem'] = formStash.results['le_x1_cross_signed_file'].file.read()

            if formStash.results['le_x2_cross_signed_file'] is not None:
                bundle_data['le_x2_cross_signed_pem'] = formStash.results['le_x2_cross_signed_file'].file.read()

            if formStash.results['le_x1_auth_file'] is not None:
                bundle_data['le_x1_auth_pem'] = formStash.results['le_x1_auth_file'].file.read()

            if formStash.results['le_x2_auth_file'] is not None:
                bundle_data['le_x2_auth_pem'] = formStash.results['le_x2_auth_file'].file.read()

            bundle_data = dict([i for i in bundle_data.items() if i[1]])

            dbResults = lib_db.upload__LetsencryptCACertificateBundle__by_pem_text(
                DBSession,
                bundle_data
            )

            if self.request.matched_route.name == 'admin:ca_certificate:upload_bundle:json':
                rval = {'result': 'success'}
                for (cert_type, cert_result) in dbResults.items():
                    rval[cert_type] = {'created': cert_result[1],
                                       'id': cert_result[0].id,
                                       }
                return rval
            return HTTPFound('/.well-known/admin/ca_certificates')

        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            if self.request.matched_route.name == 'admin:ca_certificate:upload_bundle:json':
                return {'result': 'error',
                        'form_errors': formStash.errors,
                        }
            return formhandling.form_reprint(
                self.request,
                self._ca_certificate_upload_bundle__print,
                auto_error_formatter=formhandling.formatter_none,
            )
