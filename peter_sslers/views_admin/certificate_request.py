# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import models
from .. import lib
from ..lib import db as lib_db
from ..lib import text as lib_text
from ..lib import form_utils as form_utils
from ..lib.forms import Form_CertificateRequest_new_AcmeFlow
from ..lib import errors
from ..lib.forms import Form_CertificateRequest_AcmeFlow_manage_domain
from ..lib.forms import Form_CertificateRequest_new_AcmeAutomated
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:certificate_requests', renderer='/admin/certificate_requests.mako')
    @view_config(route_name='admin:certificate_requests_paginated', renderer='/admin/certificate_requests.mako')
    @view_config(route_name='admin:certificate_requests|json', renderer='json')
    @view_config(route_name='admin:certificate_requests_paginated|json', renderer='json')
    def certificate_requests(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        items_count = lib_db.get.get__SslCertificateRequest__count(self.request.api_context)
        if wants_json:
            (pager, offset) = self._paginate(items_count, url_template='%s/certificate-requests/{0}.json' % self.request.registry.settings['admin_prefix'])
        else:
            (pager, offset) = self._paginate(items_count, url_template='%s/certificate-requests/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslCertificateRequest__paginated(self.request.api_context, limit=items_per_page, offset=offset)
        if wants_json:
            csrs = {csr.id: csr.as_json for csr in items_paged}
            return {'SslCertificateRequests': csrs,
                    'pagination': {'total_items': items_count,
                                   'page': pager.page_num,
                                   'page_next': pager.next if pager.has_next else None,
                                   }
                    }
        return {'project': 'peter_sslers',
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _certificate_request_focus(self):
        dbCertificateRequest = lib_db.get.get__SslCertificateRequest__by_id(self.request.api_context, self.request.matchdict['id'])
        if not dbCertificateRequest:
            raise HTTPNotFound('the certificate was not found')
        return dbCertificateRequest

    @view_config(route_name='admin:certificate_request:focus', renderer='/admin/certificate_request-focus.mako')
    @view_config(route_name='admin:certificate_request:focus|json', renderer='json')
    def certificate_request_focus(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        dbCertificateRequest = self._certificate_request_focus()
        if wants_json:
            return {'SslCertificateRequest': dbCertificateRequest.as_json_extended,
                    }
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
    @view_config(route_name='admin:certificate_request:focus:acme-flow:deactivate|json', renderer="json")
    def certificate_request_deactivate(self):
        # todo: post only?
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        dbCertificateRequest = self._certificate_request_focus()
        if not dbCertificateRequest.certificate_request_type_is('acme flow'):
            if wants_json:
                return {"result": "error",
                        "error": "Only availble for Acme Flow",
                        }
            raise HTTPNotFound('Only availble for Acme Flow')
        dbCertificateRequest.is_active = False
        self.request.api_context.dbSession.flush(objects=[dbCertificateRequest, ])
        if wants_json:
            return {"result": "success",
                    "SslCertificateRequest": dbCertificateRequest.as_json,
                    }
        return HTTPSeeOther('%s/certificate-request/%s?result=success' % (self.request.registry.settings['admin_prefix'], dbCertificateRequest.id))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:focus:acme-flow:manage', renderer='/admin/certificate_request-focus-AcmeFlow-manage.mako')
    def certificate_request_AcmeFlow_manage(self):
        if not self.request.registry.settings['enable_acme_flow']:
            raise HTTPNotFound('Acme-Flow is disabled on this system')
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
        if not self.request.registry.settings['enable_acme_flow']:
            raise HTTPNotFound('Acme-Flow is disabled on this system')

        dbCertificateRequest = self._certificate_request_focus()
        if not dbCertificateRequest.certificate_request_type_is('acme flow'):
            raise HTTPNotFound('Only availble for Acme Flow')
        dbCertificateRequest2SslDomain = None

        domain_identifier = self.request.matchdict['domain_identifier'].strip()
        if domain_identifier.isdigit():
            dbDomain = lib_db.get.get__SslDomain__by_id(self.request.api_context, domain_identifier, preload=False, eagerload_web=False)
        else:
            dbDomain = lib_db.get.get__SslDomain__by_name(self.request.api_context, domain_identifier, preload=False, eagerload_web=False)
        if not dbDomain:
            raise HTTPNotFound('invalid domain')

        for to_domain in dbCertificateRequest.to_domains:
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

            self.request.api_context.dbSession.flush(objects=[self.db_SslCertificateRequest2SslDomain, ])

            return HTTPSeeOther('%s/certificate-request/%s/acme-flow/manage/domain/%s?result=success' %
                                (self.request.registry.settings['admin_prefix'],
                                 self.db_SslCertificateRequest.id,
                                 self.db_SslCertificateRequest2SslDomain.ssl_domain_id
                                 )
                                )

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_AcmeFlow_manage_domain__print,
                auto_error_formatter=lib_text.formatter_error,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:new:acme-flow')
    def certificate_request_new_AcmeFlow(self):
        if not self.request.registry.settings['enable_acme_flow']:
            raise HTTPNotFound('Acme-Flow is disabled on this system')

        if self.request.method == 'POST':
            return self._certificate_request_new_AcmeFlow__submit()
        return self._certificate_request_new_AcmeFlow__print()

    def _certificate_request_new_AcmeFlow__print(self):
        self._load_AccountKeyDefault()
        return render_to_response("/admin/certificate_request-new-AcmeFlow.mako",
                                  {'dbAccountKeyDefault': self.dbAccountKeyDefault,
                                   },
                                  self.request)

    def _certificate_request_new_AcmeFlow__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_CertificateRequest_new_AcmeFlow,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = lib.utils.domains_from_string(formStash.results['domain_names'])
            if not domain_names:
                raise ValueError("missing valid domain names")
            (dbCertificateRequest,
             dbDomainObjects
             ) = lib_db.create.create__SslCertificateRequest(
                self.request.api_context,
                csr_pem = None,
                certificate_request_type_id = models.SslCertificateRequestType.ACME_FLOW,
                domain_names = domain_names,
            )

            return HTTPSeeOther('%s/certificate-request/%s/acme-flow/manage' % (self.request.registry.settings['admin_prefix'], dbCertificateRequest.id))

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_new_AcmeFlow__print,
                auto_error_formatter=lib_text.formatter_error,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:new:acme-automated')
    def certificate_request_new_AcmeAutomated(self):
        self._load_AccountKeyDefault()
        self._load_PrivateKeyDefault()
        if self.request.method == 'POST':
            return self._certificate_request_new_AcmeAutomated__submit()
        return self._certificate_request_new_AcmeAutomated__print()

    def _certificate_request_new_AcmeAutomated__print(self):
        active_ca = lib.acme_v1.CERTIFICATE_AUTHORITY
        providers = models.AcmeAccountProvider.registry.values()
        return render_to_response("/admin/certificate_request-new-AcmeAutomated.mako",
                                  {'CERTIFICATE_AUTHORITY': active_ca,
                                   'dbAccountKeyDefault': self.dbAccountKeyDefault,
                                   'dbPrivateKeyDefault': self.dbPrivateKeyDefault,
                                   'AcmeAccountProviderOptions': providers,
                                   }, self.request)

    def _certificate_request_new_AcmeAutomated__submit(self):
        try:
            (result,
             formStash
             ) = formhandling.form_validate(self.request,
                                            schema=Form_CertificateRequest_new_AcmeAutomated,
                                            validate_get=False
                                            )
            formStash.html_error_main_template = lib_text.TEMPLATE_FORMSTASH_ERRORS
            if not result:
                raise formhandling.FormInvalid()

            try:
                domain_names = lib.utils.domains_from_string(formStash.results['domain_names'])
            except ValueError as e:
                formStash.set_error(field='domain_names',
                                    message="invalid domain names detected",
                                    raise_FormInvalid=True,
                                    )
            if not domain_names:
                formStash.set_error(field='domain_names',
                                    message="invalid or no valid domain names detected",
                                    raise_FormInvalid=True,
                                    )

            accountKeySelection = form_utils.parse_AccountKeySelection(
                self.request,
                formStash,
                seek_selected=formStash.results['account_key_option']
            )
            if accountKeySelection.selection == 'upload':
                key_create_args = accountKeySelection.upload_parsed.getcreate_args
                (dbAcmeAccountKey,
                 _is_created
                 ) = lib_db.getcreate.getcreate__SslAcmeAccountKey(
                    self.request.api_context,
                    **key_create_args
                )
                accountKeySelection.SslAcmeAccountKey = dbAcmeAccountKey

            private_key_pem = form_utils.parse_PrivateKeyPem(self.request, formStash)

            try:
                dbLetsencryptCertificate = lib_db.actions.do__CertificateRequest__AcmeAutomated(
                    self.request.api_context,
                    domain_names,
                    dbAccountKey = accountKeySelection.SslAcmeAccountKey,
                    private_key_pem=private_key_pem,
                )
            except (errors.AcmeCommunicationError,
                    errors.DomainVerificationError,
                    ) as e:
                return HTTPSeeOther('%s/certificate-requests?error=new-AcmeAutomated&message=%s' % (self.request.registry.settings['admin_prefix'], e.message.replace('\n', '+').replace(' ', '+')))
            except Exception as exc:
                if self.request.registry.settings['exception_redirect']:
                    return HTTPSeeOther('%s/certificate-requests?error=new-AcmeAutomated' % self.request.registry.settings['admin_prefix'])
                raise

            return HTTPSeeOther('%s/certificate/%s' % (self.request.registry.settings['admin_prefix'], dbLetsencryptCertificate.id))

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_request_new_AcmeAutomated__print,
                auto_error_formatter=lib_text.formatter_error,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
