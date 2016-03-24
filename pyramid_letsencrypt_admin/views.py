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
import sqlalchemy
import pyramid_formencode_classic as formhandling

# localapp
from .models import *
from .lib.forms import (Form_CertificateRequest_new_flow,
                        Form_CertificateRequest_new_full,
                        Form_CertificateRequest_new_full__file,
                        Form_CertificateRequest_process_domain,
                        Form_CertificateUpload__file,
                        Form_DomainKey_new__file,
                        )
import lib.acme
import lib.db
import lib.text


# ==============================================================================


class Handler(object):
    request = None
    active_domain_name = None

    def __init__(self, request):
        self.request = request
        self.request.formhandling = formhandling
        self.request.text_library = lib.text
        self.active_domain_name = self.request.environ['HTTP_HOST'].split(':')[0]
        self.request.active_domain_name = self.active_domain_name


class ViewPublic(Handler):

    @view_config(route_name="public_whoami", renderer="string")
    def public_whoami(self):
        """this is really only useful for testing"""
        return self.active_domain_name

    @view_config(route_name='public_challenge', renderer='string')
    def public_challenge(self):
        challenge = self.request.matchdict['challenge']
        active_request = lib.db.get__LetsencryptCertificateRequest_2_ManagedDomain__challenged(DBSession,
                                                                                               challenge,
                                                                                               self.active_domain_name,
                                                                                               )
        if False:
            print "----------------------"
            print self.active_domain_name
            print challenge
            print active_request
            print "-  -  -  -  -  -  -  -"
            print self.request
            print "----------------------"
        if active_request:
            log_verification = True if 'test' not in self.request.params else False
            if log_verification:
                active_request.timestamp_verified = datetime.datetime.now()
                active_request.ip_verified = self.request.environ['REMOTE_ADDR']
                DBSession.flush()
                # quick cleanup
                dbLetsencryptCertificateRequest = lib.db.get__LetsencryptCertificateRequest__by_id(DBSession,
                                                                                                   active_request.letsencrypt_certificate_request_id,
                                                                                                   )
                has_unverified = False
                for d in dbLetsencryptCertificateRequest.certificate_request_to_domains:
                    if not d.timestamp_verified:
                        has_unverified = True
                        break
                if not has_unverified and not dbLetsencryptCertificateRequest.timestamp_finished:
                    dbLetsencryptCertificateRequest.timestamp_finished = datetime.datetime.now()
                    DBSession.flush()
            return active_request.challenge_text
        return 'ERROR'


class ViewAdmin(Handler):

    @view_config(route_name='admin', renderer='/admin/index.mako')
    def index(self):
        return {'project': 'pyramid_letsencrypt_admin'}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domains', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains_paginated', renderer='/admin/domains.mako')
    def domains(self):
        dbLetsencryptManagedDomains = lib.db.get__LetsencryptManagedDomain__paginated(DBSession, limit=100, offset=0)
        dbLetsencryptManagedDomains_count = lib.db.get__LetsencryptManagedDomain__count(DBSession)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptManagedDomains': dbLetsencryptManagedDomains,
                'LetsencryptManagedDomains_count': dbLetsencryptManagedDomains_count,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus', renderer='/admin/domain-focus.mako')
    def domain_focus(self):
        dbLetsencryptManagedDomain = lib.db.get__LetsencryptManagedDomain__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptManagedDomain:
            raise HTTPNotFound('the domain was not found')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptManagedDomain': dbLetsencryptManagedDomain
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificates', renderer='/admin/certificates.mako')
    @view_config(route_name='admin:certificates_paginated', renderer='/admin/certificates.mako')
    def certificates(self):
        dbLetsencryptHttpsCertificates = lib.db.get__LetsencryptHttpsCertificate__paginated(DBSession, limit=100, offset=0)
        dbLetsencryptHttpsCertificates_count = lib.db.get__LetsencryptHttpsCertificate__count(DBSession)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptHttpsCertificates': dbLetsencryptHttpsCertificates,
                'LetsencryptHttpsCertificates_count': dbLetsencryptHttpsCertificates_count,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:upload')
    def certificate_upload(self):
        if self.request.POST:
            return self._certificate_upload__submit()
        return self._certificate_upload__print()

    def _certificate_upload__print(self):
        return render_to_response("/admin/certificate-upload.mako", {}, self.request)

    def _certificate_upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateUpload__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            domain_key_pem = formStash.results['domain_key_file'].file.read()
            dbLetsencryptDomainKey, _is_created = lib.db.getcreate__LetsencryptDomainKey__by_pem_text(
                DBSession,
                domain_key_pem
            )

            chain_pem = formStash.results['chain_file'].file.read()
            dbLetsencryptCACertificate, _is_created = lib.db.getcreate__LetsencryptCACertificate__by_pem_text(
                DBSession,
                chain_pem,
                'manual upload'
            )

            certificate_pem = formStash.results['certificate_file'].file.read()
            dbLetsencryptHttpsCertificate, _is_created = lib.db.getcreate__LetsencryptHttpsCertificate__by_pem_text(
                DBSession, certificate_pem,
                dbCACertificate=dbLetsencryptCACertificate,
                dbDomainKey=dbLetsencryptDomainKey,
            )

            return HTTPFound('/.well-known/admin/certificate/%s' % dbLetsencryptHttpsCertificate.id)

        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_upload__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _certificate_focus(self):
        dbLetsencryptHttpsCertificate = lib.db.get__LetsencryptHttpsCertificate__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptHttpsCertificate:
            raise HTTPNotFound('the certificate was not found')
        return dbLetsencryptHttpsCertificate

    @view_config(route_name='admin:certificate:focus', renderer='/admin/certificate-focus.mako')
    def certificate_focus(self):
        dbLetsencryptHttpsCertificate = self._certificate_focus()
        # x-x509-server-cert
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptHttpsCertificate': dbLetsencryptHttpsCertificate
                }

    @view_config(route_name='admin:certificate:focus:chain:raw', renderer='string')
    def certificate_focus_chain(self):
        dbLetsencryptHttpsCertificate = self._certificate_focus()
        return 'chain.pem'
        # application/x-pem-file              .pem

    @view_config(route_name='admin:certificate:focus:fullchain:raw', renderer='string')
    def certificate_focus_fullchain(self):
        dbLetsencryptHttpsCertificate = self._certificate_focus()
        return 'fullchain.pem'
        #  application/x-pkcs7-certificates    .p7b .spc

    @view_config(route_name='admin:certificate:focus:privatekey:raw', renderer='string')
    def certificate_focus_privatekey(self):
        dbLetsencryptHttpsCertificate = self._certificate_focus()
        return 'privatekey.pem'

    # PKCS#12 bundles of private key + certificate(s)
    # application/x-pkcs7-certificates    .p7b .spc

    @view_config(route_name='admin:certificate:focus:cert:raw', renderer='string')
    def certificate_focus_cert(self):
        dbLetsencryptHttpsCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptHttpsCertificate.cert_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptHttpsCertificate.cert_pem
        elif self.request.matchdict['format'] == 'crt':
            as_der = lib.acme.convert_pem_to_der(pem_data=dbLetsencryptHttpsCertificate.cert_pem)
            response = Response()
            response.content_type = 'application/x-x509-server-cert'
            response.body = as_der
            return response
        return 'cert.pem'

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_requests', renderer='/admin/certificate_requests.mako')
    @view_config(route_name='admin:certificate_requests_paginated', renderer='/admin/certificate_requests.mako')
    def certificate_requests(self):
        dbLetsencryptCertificateRequests = lib.db.get__LetsencryptCertificateRequest__paginated(DBSession, limit=100, offset=0)
        dbLetsencryptCertificateRequests_count = lib.db.get__LetsencryptCertificateRequest__count(DBSession)

        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCertificateRequests': dbLetsencryptCertificateRequests,
                'LetsencryptCertificateRequests_count': dbLetsencryptCertificateRequests_count
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:focus', renderer='/admin/certificate_request-focus.mako')
    def certificate_request_focus(self):
        certificate_request_id = int(self.request.matchdict['id'])
        dbLetsencryptCertificateRequest = lib.db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
        if not dbLetsencryptCertificateRequest:
            raise HTTPNotFound('the certificate_request was not found')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCertificateRequest': dbLetsencryptCertificateRequest
                }

    @view_config(route_name='admin:certificate_request:focus:raw', renderer='string')
    def certificate_request_focus_raw(self):
        dbLetsencryptCertificateRequest = lib.db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
        if not dbLetsencryptCertificateRequest:
            raise HTTPNotFound('the certificate_request was not found')
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptCertificateRequest.csr_pem
        if self.request.matchdict['format'] == 'csr':
            self.request.response.content_type = 'application/pkcs10'
            return dbLetsencryptCertificateRequest.csr_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptCertificateRequest.csr_pem
        return 'cert.pem'

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:process', renderer='/admin/certificate_request-process.mako')
    def certificate_request_process(self):
        certificate_request_id = int(self.request.matchdict['id'])
        dbLetsencryptCertificateRequest = lib.db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
        if not dbLetsencryptCertificateRequest:
            raise HTTPNotFound('the certificate_request was not found')
        if not dbLetsencryptCertificateRequest.certificate_request_type_is('flow'):
            raise HTTPNotFound('Only availble for FLOW')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCertificateRequest': dbLetsencryptCertificateRequest,
                'LetsencryptCertificateRequest_2_ManagedDomain': None,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:deactivate')
    def certificate_request_deactivate(self):
        certificate_request_id = int(self.request.matchdict['id'])
        dbLetsencryptCertificateRequest = lib.db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
        if not dbLetsencryptCertificateRequest:
            raise HTTPNotFound('the certificate_request was not found')
        if not dbLetsencryptCertificateRequest.certificate_request_type_is('flow'):
            raise HTTPNotFound('Only availble for FLOW')
        dbLetsencryptCertificateRequest.is_active = False
        DBSession.flush()
        return HTTPFound('/.well-known/admin/certificate_request/%s' % dbLetsencryptCertificateRequest.id)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:process:domain', )
    def certificate_request_process_domain(self):
        certificate_request_id = int(self.request.matchdict['id'])
        dbLetsencryptCertificateRequest = lib.db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
        if not dbLetsencryptCertificateRequest:
            raise HTTPNotFound('the certificate_request was not found')
        if not dbLetsencryptCertificateRequest.certificate_request_type_is('flow'):
            raise HTTPNotFound('Only availble for FLOW')
        dbLetsencryptCertificateRequest_2_ManagedDomain = None
        domain_id = int(self.request.matchdict['domain_id'])
        for to_domain in dbLetsencryptCertificateRequest.certificate_request_to_domains:
            if to_domain.letsencrypt_managed_domain_id == domain_id:
                dbLetsencryptCertificateRequest_2_ManagedDomain = to_domain
                break
        if dbLetsencryptCertificateRequest_2_ManagedDomain is None:
            raise HTTPNotFound('invalid domain for certificate request')

        self.db_LetsencryptCertificateRequest = dbLetsencryptCertificateRequest
        self.db_LetsencryptCertificateRequest_2_ManagedDomain = dbLetsencryptCertificateRequest_2_ManagedDomain

        if self.request.POST:
            return self._certificate_request_process_domain__submit()
        return self._certificate_request_process_domain__print()

    def _certificate_request_process_domain__print(self):
        return render_to_response("/admin/certificate_request-process.mako",
                                  {'LetsencryptCertificateRequest': self.db_LetsencryptCertificateRequest,
                                   'LetsencryptCertificateRequest_2_ManagedDomain': self.db_LetsencryptCertificateRequest_2_ManagedDomain,
                                   },
                                  self.request)

    def _certificate_request_process_domain__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateRequest_process_domain,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            if self.db_LetsencryptCertificateRequest_2_ManagedDomain.timestamp_verified:
                raise ValueError("You can not edit the challenge of a verified item")

            changed = False
            for attribute in ('challenge_key', 'challenge_text'):
                submitted_value = formStash.results[attribute]
                if submitted_value != getattr(self.db_LetsencryptCertificateRequest_2_ManagedDomain, attribute):
                    setattr(self.db_LetsencryptCertificateRequest_2_ManagedDomain, attribute, submitted_value)
                    changed = True

            if not changed:
                raise ValueError("No changes!")

            DBSession.flush()

            return HTTPFound('/.well-known/admin/certificate_request/%s/process/domain/%s' %
                             (self.db_LetsencryptCertificateRequest.id,
                              self.db_LetsencryptCertificateRequest_2_ManagedDomain.letsencrypt_managed_domain_id
                              )
                             )

        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_process_domain__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:new:flow')
    def certificate_request_new_flow(self):
        if self.request.POST:
            return self._certificate_request_new_flow__submit()
        return self._certificate_request_new_flow__print()

    def _certificate_request_new_flow__print(self):
        return render_to_response("/admin/certificate_request-new_flow.mako", {}, self.request)

    def _certificate_request_new_flow__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateRequest_new_flow,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = [i.lower() for i in [d.strip() for d in formStash.results['domain_names'].split(',')] if i]
            domain_names = set(domain_names)
            if not domain_names:
                raise ValueError("missing valid domain names")
            dbLetsencryptCertificateRequest = lib.db.create__CertificateRequest__by_domainNamesList_FLOW(DBSession, domain_names)

            return HTTPFound('/.well-known/admin/certificate_request/%s/process' % dbLetsencryptCertificateRequest.id)

        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_new_flow__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:new:full')
    def certificate_request_new_full(self):
        if self.request.POST:
            return self._certificate_request_new_full__submit()
        return self._certificate_request_new_full__print()

    def _certificate_request_new_full__print(self):
        return render_to_response("/admin/certificate_request-new_full.mako", {}, self.request)

    def _certificate_request_new_full__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateRequest_new_full__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = [i.lower() for i in [d.strip() for d in formStash.results['domain_names'].split(',')] if i]
            domain_names = set(domain_names)
            if not domain_names:
                raise ValueError("missing valid domain names")

            account_key_pem = formStash.results['account_key_file'].file.read()
            domain_key_pem = formStash.results['domain_key_file'].file.read()

            try:
                dbLetsencryptCertificate = lib.db.create__CertificateRequest__FULL(
                    DBSession,
                    domain_names,
                    account_key_pem=account_key_pem,
                    domain_key_pem=domain_key_pem,
                )
            except:
                if self.request.registry.settings['exception_redirect']:
                    return HTTPFound('/.well-known/admin/certificate_requests?error=new-full')
                raise

            return HTTPFound('/.well-known/admin/certificate/%s' % dbLetsencryptCertificate.id)

        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_new_full__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_keys', renderer='/admin/account_keys.mako')
    @view_config(route_name='admin:account_keys_paginated', renderer='/admin/account_keys.mako')
    def account_keys(self):
        dbLetsencryptAccountKeys = lib.db.get__LetsencryptAccountKey__paginated(DBSession, limit=100, offset=0)
        dbLetsencryptAccountKeys_count = lib.db.get__LetsencryptAccountKey__count(DBSession)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptAccountKeys': dbLetsencryptAccountKeys,
                'LetsencryptAccountKeys_count': dbLetsencryptAccountKeys_count,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus', renderer='/admin/account_key-focus.mako')
    def account_key_focus(self):
        dbLetsencryptAccountKey = lib.db.get__LetsencryptAccountKey__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptAccountKey:
            raise HTTPNotFound('the key was not found')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptAccountKey': dbLetsencryptAccountKey
                }

    @view_config(route_name='admin:account_key:focus:raw', renderer='string')
    def account_key_focus_raw(self):
        dbLetsencryptAccountKey = lib.db.get__LetsencryptAccountKey__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptAccountKey:
            raise HTTPNotFound('the key was not found')
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptAccountKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptAccountKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib.acme.convert_pem_to_der(pem_data=dbLetsencryptAccountKey.key_pem)
            return as_der

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain_keys', renderer='/admin/domain_keys.mako')
    @view_config(route_name='admin:domain_keys_paginated', renderer='/admin/domain_keys.mako')
    def domain_keys(self):
        dbLetsencryptDomainKeys = lib.db.get__LetsencryptDomainKey__paginated(DBSession, limit=100, offset=0)
        dbLetsencryptDomainKeys_count = lib.db.get__LetsencryptDomainKey__count(DBSession)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptDomainKeys': dbLetsencryptDomainKeys,
                'LetsencryptDomainKeys_count': dbLetsencryptDomainKeys_count,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain_key:focus', renderer='/admin/domain_key-focus.mako')
    def domain_key_focus(self):
        dbLetsencryptDomainKey = lib.db.get__LetsencryptDomainKey__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptDomainKey:
            raise HTTPNotFound('the key was not found')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptDomainKey': dbLetsencryptDomainKey
                }

    @view_config(route_name='admin:domain_key:focus:raw', renderer='string')
    def domain_key_focus_raw(self):
        dbLetsencryptDomainKey = lib.db.get__LetsencryptDomainKey__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptDomainKey:
            raise HTTPNotFound('the key was not found')
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptDomainKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptDomainKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib.acme.convert_pem_to_der(pem_data=dbLetsencryptDomainKey.key_pem)
            return as_der

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain_key:new')
    def domain_key_new(self):
        if self.request.POST:
            return self._domain_key_new__submit()
        return self._domain_key_new__print()

    def _domain_key_new__print(self):
        return render_to_response("/admin/domain_key-new.mako", {}, self.request)

    def _domain_key_new__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_DomainKey_new__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            domain_key_pem = formStash.results['domain_key_file'].file.read()
            dbLetsencryptDomainKey, _is_created = lib.db.getcreate__LetsencryptDomainKey__by_pem_text(DBSession, domain_key_pem)

            return HTTPFound('/.well-known/admin/domain_key/%s%s' % (dbLetsencryptDomainKey.id, ('?is_created=1' if _is_created else '')))

        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._domain_key_new__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:ca_certificates', renderer='/admin/ca_certificates.mako')
    @view_config(route_name='admin:ca_certificates_paginated', renderer='/admin/ca_certificates.mako')
    def ca_certificates(self):
        dbLetsencryptCACertificates = lib.db.get__LetsencryptCACertificate__paginated(DBSession, limit=100, offset=0)
        dbLetsencryptCACertificates_count = lib.db.get__LetsencryptCACertificate__count(DBSession)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificates': dbLetsencryptCACertificates,
                'LetsencryptCACertificates_count': dbLetsencryptCACertificates_count,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _ca_certificate_focus(self):
        dbLetsencryptCACertificate = lib.db.get__LetsencryptCACertificate__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptCACertificate:
            raise HTTPNotFound('the cert was not found')
        return dbLetsencryptCACertificate

    @view_config(route_name='admin:ca_certificate:focus', renderer='/admin/ca_certificate-focus.mako')
    def ca_certificate_focus(self):
        dbLetsencryptCACertificate = self._ca_certificate_focus()
        dbLetsencryptHttpsCertificates = lib.db.get__LetsencryptHttpsCertificate_by_LetsencryptCACertificateId__paginated(
            DBSession, dbLetsencryptCACertificate.id, limit=10, offset=0)
        dbLetsencryptHttpsCertificates_count = lib.db.get__LetsencryptHttpsCertificate_by_LetsencryptCACertificateId__count(
            DBSession, dbLetsencryptCACertificate.id)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificate': dbLetsencryptCACertificate,
                'LetsencryptHttpsCertificates': dbLetsencryptHttpsCertificates,
                'LetsencryptHttpsCertificates_count': dbLetsencryptHttpsCertificates_count,
                }

    @view_config(route_name='admin:ca_certificate:focus:raw', renderer='string')
    def ca_certificate_focus_raw(self):
        dbLetsencryptCACertificate = self._ca_certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptCACertificate.cert_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptCACertificate.cert_pem
        elif self.request.matchdict['format'] in ('cer', 'der'):
            as_der = lib.acme.convert_pem_to_der(pem_data=dbLetsencryptCACertificate.cert_pem)
            response = Response()
            if self.request.matchdict['format'] == 'cer':
                response.content_type = 'application/pkix-cert'
            elif self.request.matchdict['format'] == 'der':
                response.content_type = 'application/x-x509-ca-cert'
            response.body = as_der
            return response
        return 'chain.?'

    @view_config(route_name='admin:ca_certificate:focus:signed_certificates', renderer='/admin/ca_certificate-focus-signed_certificates.mako')
    @view_config(route_name='admin:ca_certificate:focus:signed_certificates_paginated', renderer='/admin/ca_certificate-focus-signed_certificates.mako')
    def ca_certificate_focus__signed_certificates(self):
        dbLetsencryptCACertificate = self._ca_certificate_focus()
        dbLetsencryptHttpsCertificates = lib.db.get__LetsencryptHttpsCertificate_by_LetsencryptCACertificateId__paginated(
            DBSession, dbLetsencryptCACertificate.id, limit=10, offset=0)
        dbLetsencryptHttpsCertificates_count = lib.db.get__LetsencryptHttpsCertificate_by_LetsencryptCACertificateId__count(
            DBSession, dbLetsencryptCACertificate.id)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificate': dbLetsencryptCACertificate,
                'LetsencryptHttpsCertificates': dbLetsencryptHttpsCertificates,
                'LetsencryptHttpsCertificates_count': dbLetsencryptHttpsCertificates_count,
                }
