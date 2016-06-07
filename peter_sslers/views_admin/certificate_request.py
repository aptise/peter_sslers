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
from ..lib.forms import (Form_CertificateRequest_new_AcmeFlow,
                         # Form_CertificateRequest_new_AcmeAutomated,
                         Form_CertificateRequest_new_AcmeAutomated__file,
                         Form_CertificateRequest_AcmeFlow_manage_domain,
                         )
from ..lib import acme as lib_acme
from ..lib import db as lib_db
from ..lib import errors as lib_errors
from ..lib import utils as lib_utils
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:certificate_requests', renderer='/admin/certificate_requests.mako')
    @view_config(route_name='admin:certificate_requests_paginated', renderer='/admin/certificate_requests.mako')
    def certificate_requests(self):
        items_count = lib_db.get__SslCertificateRequest__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/certificate-requests/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslCertificateRequest__paginated(self.request.api_context, limit=items_per_page, offset=offset)

        return {'project': 'peter_sslers',
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _certificate_request_focus(self):
        dbCertificateRequest = lib_db.get__SslCertificateRequest__by_id(self.request.api_context, self.request.matchdict['id'])
        if not dbCertificateRequest:
            raise HTTPNotFound('the certificate was not found')
        return dbCertificateRequest

    @view_config(route_name='admin:certificate_request:focus', renderer='/admin/certificate_request-focus.mako')
    def certificate_request_focus(self):
        dbCertificateRequest = self._certificate_request_focus()
        return {'project': 'peter_sslers',
                'SslCertificateRequest': dbCertificateRequest
                }

    @view_config(route_name='admin:certificate_request:focus:raw', renderer='string')
    def certificate_request_focus_raw(self):
        dbCertificateRequest = self._certificate_request_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbCertificateRequest.csr_pem
        if self.request.matchdict['format'] == 'csr':
            self.request.response.content_type = 'application/pkcs10'
            return dbCertificateRequest.csr_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbCertificateRequest.csr_pem
        return 'cert.pem'

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:focus:acme-flow:deactivate')
    def certificate_request_deactivate(self):
        dbCertificateRequest = self._certificate_request_focus()
        if not dbCertificateRequest.certificate_request_type_is('acme flow'):
            raise HTTPNotFound('Only availble for Acme Flow')
        dbCertificateRequest.is_active = False
        self.request.api_context.dbSession.flush()
        return HTTPFound('%s/certificate-request/%s?result=success' % (self.request.registry.settings['admin_prefix'], dbCertificateRequest.id))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:focus:acme-flow:manage', renderer='/admin/certificate_request-focus-AcmeFlow-manage.mako')
    def certificate_request_AcmeFlow_manage(self):
        dbCertificateRequest = self._certificate_request_focus()
        if not dbCertificateRequest.certificate_request_type_is('acme flow'):
            raise HTTPNotFound('Only availble for Acme Flow')
        return {'project': 'peter_sslers',
                'SslCertificateRequest': dbCertificateRequest,
                'SslCertificateRequest2SslDomain': None,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:focus:acme-flow:manage:domain', )
    def certificate_request_AcmeFlow_manage_domain(self):
        dbCertificateRequest = self._certificate_request_focus()
        if not dbCertificateRequest.certificate_request_type_is('acme flow'):
            raise HTTPNotFound('Only availble for Acme Flow')
        dbCertificateRequest2SslDomain = None

        domain_identifier = self.request.matchdict['domain_identifier'].strip()
        if domain_identifier.isdigit():
            dbDomain = lib_db.get__SslDomain__by_id(self.request.api_context, domain_identifier, preload=False, eagerload_web=False)
        else:
            dbDomain = lib_db.get__SslDomain__by_name(self.request.api_context, domain_identifier, preload=False, eagerload_web=False)
        if not dbDomain:
            raise HTTPNotFound('invalid domain')

        for to_domain in dbCertificateRequest.certificate_request_to_domains:
            if to_domain.ssl_domain_id == dbDomain.id:
                dbCertificateRequest2SslDomain = to_domain
                break
        if dbCertificateRequest2SslDomain is None:
            raise HTTPNotFound('invalid domain for certificate request')

        self.db_SslCertificateRequest = dbCertificateRequest
        self.db_SslCertificateRequest2SslDomain = dbCertificateRequest2SslDomain

        if self.request.method == 'POST':
            return self._certificate_request_AcmeFlow_manage_domain__submit()
        return self._certificate_request_AcmeFlow_manage_domain__print()

    def _certificate_request_AcmeFlow_manage_domain__print(self):
        return render_to_response("/admin/certificate_request-focus-AcmeFlow-manage.mako",
                                  {'SslCertificateRequest': self.db_SslCertificateRequest,
                                   'SslCertificateRequest2SslDomain': self.db_SslCertificateRequest2SslDomain,
                                   },
                                  self.request)

    def _certificate_request_AcmeFlow_manage_domain__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateRequest_AcmeFlow_manage_domain,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            if self.db_SslCertificateRequest2SslDomain.timestamp_verified:
                raise ValueError("You can not edit the challenge of a verified item")

            changed = False
            for attribute in ('challenge_key', 'challenge_text'):
                submitted_value = formStash.results[attribute]
                if submitted_value != getattr(self.db_SslCertificateRequest2SslDomain, attribute):
                    setattr(self.db_SslCertificateRequest2SslDomain, attribute, submitted_value)
                    changed = True

            if not changed:
                raise ValueError("No changes!")

            self.request.api_context.dbSession.flush()

            return HTTPFound('%s/certificate-request/%s/acme-flow/manage/domain/%s?result=success' %
                             (self.request.registry.settings['admin_prefix'],
                              self.db_SslCertificateRequest.id,
                              self.db_SslCertificateRequest2SslDomain.ssl_domain_id
                              )
                             )

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_AcmeFlow_manage_domain__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:new:acme-flow')
    def certificate_request_new_AcmeFlow(self):
        if self.request.method == 'POST':
            return self._certificate_request_new_AcmeFlow__submit()
        return self._certificate_request_new_AcmeFlow__print()

    def _certificate_request_new_AcmeFlow__print(self):
        return render_to_response("/admin/certificate_request-new-AcmeFlow.mako", {}, self.request)

    def _certificate_request_new_AcmeFlow__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateRequest_new_AcmeFlow,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = lib_utils.domains_from_string(formStash.results['domain_names'])
            if not domain_names:
                raise ValueError("missing valid domain names")
            dbCertificateRequest, dbDomainObjects = lib_db.create__SslCertificateRequest(
                self.request.api_context,
                csr_pem = None,
                certificate_request_type_id = SslCertificateRequestType.ACME_FLOW,
                domain_names = domain_names,
            )

            return HTTPFound('%s/certificate-request/%s/acme-flow/manage' % (self.request.registry.settings['admin_prefix'], dbCertificateRequest.id))

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_new_AcmeFlow__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:new:acme-automated')
    def certificate_request_new_AcmeAutomated(self):
        if self.request.method == 'POST':
            return self._certificate_request_new_AcmeAutomated__submit()
        return self._certificate_request_new_AcmeAutomated__print()

    def _certificate_request_new_AcmeAutomated__print(self):
        active_ca = lib_acme.CERTIFICATE_AUTHORITY
        return render_to_response("/admin/certificate_request-new-AcmeAutomated.mako",
                                  {'CERTIFICATE_AUTHORITY': active_ca,
                                   }, self.request)

    def _certificate_request_new_AcmeAutomated__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateRequest_new_AcmeAutomated__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = lib_utils.domains_from_string(formStash.results['domain_names'])
            if not domain_names:
                raise ValueError("missing valid domain names")

            account_key_pem = formStash.results['account_key_file'].file.read()
            private_key_pem = formStash.results['private_key_file'].file.read()

            try:
                dbLetsencryptCertificate = lib_db.do__CertificateRequest__AcmeAutomated(
                    self.request.api_context,
                    domain_names,
                    account_key_pem=account_key_pem,
                    private_key_pem=private_key_pem,
                )
            except (lib_errors.AcmeCommunicationError, lib_errors.DomainVerificationError), e:
                return HTTPFound('%s/certificate-requests?error=new-AcmeAutomated&message=%s' % (self.request.registry.settings['admin_prefix'], e.message))
            except:
                if self.request.registry.settings['exception_redirect']:
                    return HTTPFound('%s/certificate-requests?error=new-AcmeAutomated' % self.request.registry.settings['admin_prefix'])
                raise

            return HTTPFound('%s/certificate/%s' % (self.request.registry.settings['admin_prefix'], dbLetsencryptCertificate.id))

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_new_AcmeAutomated__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
