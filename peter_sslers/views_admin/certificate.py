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
from ..lib.forms import (Form_Certificate_Upload__file,
                         Form_Certificate_Renewal_Custom,
                         Form_Certificate_mark,
                         )
from ..lib.handler import Handler, items_per_page
from ..lib import acme as lib_acme
from ..lib import cert_utils as lib_cert_utils
from ..lib import db as lib_db
from ..lib import errors as lib_errors
from ..lib import events as lib_events
from ..lib import utils as lib_utils


# ==============================================================================


class ViewAdmin(Handler):
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificates', renderer='/admin/certificates.mako')
    @view_config(route_name='admin:certificates_paginated', renderer='/admin/certificates.mako')
    def certificates(self):
        items_count = lib_db.get__SslServerCertificate__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/certificates/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslServerCertificate__paginated(self.request.api_context, limit=items_per_page, offset=offset, eagerload_web=True)
        return {'project': 'peter_sslers',
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    @view_config(route_name='admin:certificates:expiring', renderer='/admin/certificates.mako')
    @view_config(route_name='admin:certificates:expiring_paginated', renderer='/admin/certificates.mako')
    def certificates_expiring_only(self):
        expiring_days = self.request.registry.settings['expiring_days']
        items_count = lib_db.get__SslServerCertificate__count(self.request.api_context, expiring_days=expiring_days)
        (pager, offset) = self._paginate(items_count, url_template='%s/certificates/expiring/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslServerCertificate__paginated(self.request.api_context, expiring_days=expiring_days, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'sidenav_option': 'expiring',
                'expiring_days': expiring_days,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:upload')
    @view_config(route_name='admin:certificate:upload.json', renderer='json')
    def certificate_upload(self):
        if self.request.method == 'POST':
            return self._certificate_upload__submit()
        return self._certificate_upload__print()

    def _certificate_upload__print(self):
        if self.request.matched_route.name == 'admin:certificate:upload.json':
            return {'instructions': """curl --form 'private_key_file=@privkey1.pem' --form 'certificate_file=@cert1.pem' --form 'chain_file=@chain1.pem' http://127.0.0.1:6543%s/certificate/upload.json""" % self.request.registry.settings['admin_prefix'],
                    'form_fields': {'private_key_file': 'required',
                                    'chain_file': 'required',
                                    'certificate_file': 'required',
                                    },
                    }
        return render_to_response("/admin/certificate-upload.mako", {}, self.request)

    def _certificate_upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_Certificate_Upload__file,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            private_key_pem = formStash.results['private_key_file'].file.read()
            dbPrivateKey, pkey_is_created = lib_db.getcreate__SslPrivateKey__by_pem_text(
                self.request.api_context,
                private_key_pem
            )

            chain_pem = formStash.results['chain_file'].file.read()
            dbCaCertificate, cacert_is_created = lib_db.getcreate__SslCaCertificate__by_pem_text(
                self.request.api_context,
                chain_pem,
                'manual upload'
            )

            certificate_pem = formStash.results['certificate_file'].file.read()
            dbServerCertificate, cert_is_created = lib_db.getcreate__SslServerCertificate__by_pem_text(
                self.request.api_context, certificate_pem,
                dbCACertificate=dbCaCertificate,
                dbPrivateKey=dbPrivateKey,
                dbAccountKey=None,
            )

            if self.request.matched_route.name == 'admin:certificate:upload.json':
                return {'result': 'success',
                        'certificate': {'created': cert_is_created,
                                        'id': dbServerCertificate.id,
                                        'url': '%s/certificate/%s' % (self.request.registry.settings['admin_prefix'], dbServerCertificate.id),
                                        },
                        'ca_certificate': {'created': cacert_is_created,
                                           'id': dbCaCertificate.id,
                                           },
                        'private_key': {'created': pkey_is_created,
                                        'id': dbPrivateKey.id,
                                        },
                        }
            return HTTPFound('%s/certificate/%s' % (self.request.registry.settings['admin_prefix'], dbServerCertificate.id))

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            if self.request.matched_route.name == 'admin:certificate:upload.json':
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
        dbServerCertificate = lib_db.get__SslServerCertificate__by_id(self.request.api_context, self.request.matchdict['id'])
        if not dbServerCertificate:
            raise HTTPNotFound('the certificate was not found')
        return dbServerCertificate

    @view_config(route_name='admin:certificate:focus', renderer='/admin/certificate-focus.mako')
    def certificate_focus(self):
        dbServerCertificate = self._certificate_focus()
        # x-x509-server-cert
        return {'project': 'peter_sslers',
                'SslServerCertificate': dbServerCertificate
                }

    @view_config(route_name='admin:certificate:focus:parse.json', renderer='json')
    def certificate_focus_parse_json(self):
        dbServerCertificate = self._certificate_focus()
        return {"%s" % dbServerCertificate.id: lib_cert_utils.parse_cert(cert_pem=dbServerCertificate.cert_pem),
                }

    @view_config(route_name='admin:certificate:focus:chain:raw', renderer='string')
    def certificate_focus_chain(self):
        dbServerCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbServerCertificate.certificate_upchain.cert_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbServerCertificate.certificate_upchain.cert_pem
        elif self.request.matchdict['format'] in ('cer', 'crt', 'der'):
            as_der = lib_cert_utils.convert_pem_to_der(pem_data=dbServerCertificate.certificate_upchain.cert_pem)
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
        dbServerCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbServerCertificate.cert_fullchain_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbServerCertificate.cert_fullchain_pem
        return 'fullchain.pem'

    @view_config(route_name='admin:certificate:focus:privatekey:raw', renderer='string')
    def certificate_focus_privatekey(self):
        dbServerCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbServerCertificate.private_key.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbServerCertificate.private_key.key_pem
        elif self.request.matchdict['format'] == 'key':
            as_der = lib_cert_utils.convert_pem_to_der(pem_data=dbServerCertificate.private_key.key_pem)
            response = Response()
            response.content_type = 'application/pkcs8'
            response.body = as_der
            return response
        return 'privatekey.pem'

    @view_config(route_name='admin:certificate:focus:cert:raw', renderer='string')
    def certificate_focus_cert(self):
        dbServerCertificate = self._certificate_focus()
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbServerCertificate.cert_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbServerCertificate.cert_pem
        elif self.request.matchdict['format'] == 'crt':
            as_der = lib_cert_utils.convert_pem_to_der(pem_data=dbServerCertificate.cert_pem)
            response = Response()
            response.content_type = 'application/x-x509-server-cert'
            response.body = as_der
            return response
        return 'cert.pem'

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:focus:config_json', renderer='json')
    def certificate_focus_config_json(self):
        dbServerCertificate = self._certificate_focus()
        if self.request.params.get('idonly', None):
            rval = dbServerCertificate.config_payload_idonly
        else:
            rval = dbServerCertificate.config_payload
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:focus:nginx_cache_expire', renderer=None)
    @view_config(route_name='admin:certificate:focus:nginx_cache_expire.json', renderer='json')
    def certificate_focus_nginx_expire(self):
        dbServerCertificate = self._certificate_focus()
        if not self.request.registry.settings['enable_nginx']:
            raise HTTPFound('%s/certificate/%s?error=no_nginx' % (self.request.registry.settings['admin_prefix'], dbServerCertificate.id))
        dbDomains = [c2d.domain for c2d in dbServerCertificate.unique_fqdn_set.to_domains]

        # this will generate it's own log__SslOperationsEvent
        success, dbEvent = lib_utils.nginx_expire_cache(self.request, self.request.api_context, dbDomains=dbDomains)
        if self.request.matched_route.name == 'admin:certificate:focus:nginx_cache_expire.json':
            return {'result': 'success',
                    'operations_event': {'id': dbEvent.id,
                                         },
                    }
        return HTTPFound('%s/certificate/%s?operation=nginx_cache_expire&result=success&event.id=%s' % (self.request.registry.settings['admin_prefix'], dbServerCertificate.id, dbEvent.id))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:focus:renew:quick', renderer=None)
    @view_config(route_name='admin:certificate:focus:renew:quick.json', renderer='json')
    def certificate_focus_renew_quick(self):
        dbServerCertificate = self._certificate_focus()
        try:
            if not self.request.method == 'POST':
                raise lib_errors.DisplayableError('Post Only')
            if not dbServerCertificate.can_quick_renew:
                raise lib_errors.DisplayableError('Thie cert is not eligible for `Quick Renew`')

            raise NotImplementedError()

        except lib_errors.DisplayableError, e:
            url_failure = '%s/certificate/%s?operation=renewal&renewal_type=quick&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbServerCertificate.id,
                e.message,
            )
            raise HTTPFound("%s&error=POST-ONLY" % url_failure)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:focus:renew:custom', renderer=None)
    @view_config(route_name='admin:certificate:focus:renew:custom.json', renderer='json')
    def certificate_focus_renew_custom(self):
        dbServerCertificate = self._certificate_focus()
        self.dbServerCertificate = dbServerCertificate
        if self.request.method == 'POST':
            return self._certificate_focus_renew_custom__submit()
        return self._certificate_focus_renew_custom__print()

    def _certificate_focus_renew_custom__print(self):
        return render_to_response("/admin/certificate-focus-renew.mako",
                                  {'SslServerCertificate': self.dbServerCertificate},
                                  self.request
                                  )

    def _certificate_focus_renew_custom__submit(self):
        dbServerCertificate = self.dbServerCertificate
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_Certificate_Renewal_Custom,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            #
            # handle the Account Key
            #
            dbAccountKey = None
            account_key_pem = None
            if formStash.results['account_key_option'] == 'upload':
                account_key_pem = formStash.results['account_key_file'].file.read()
            elif formStash.results['account_key_option'] == 'existing':
                if not dbServerCertificate.ssl_letsencrypt_account_key_id:
                    raise ValueError("This Certificate does not have an existing Account Key")
                dbAccountKey = dbServerCertificate.letsencrypt_account_key
            else:
                raise ValueError("unknown option")

            #
            # handle the Private Key
            #
            dbPrivateKey = None
            private_key_pem = None
            if formStash.results['private_key_option'] == 'upload':
                private_key_pem = formStash.results['private_key_file'].file.read()
            elif formStash.results['private_key_option'] == 'existing':
                dbPrivateKey = dbServerCertificate.private_key
            else:
                raise ValueError("unknown option")

            try:
                event_payload_dict = lib_utils.new_event_payload_dict()
                event_payload_dict['ssl_server_certificate.id'] = dbServerCertificate.id
                dbEvent = lib_db.log__SslOperationsEvent(self.request.api_context,
                                                         models.SslOperationsEventType.from_string('certificate__renew'),
                                                         event_payload_dict
                                                         )

                newLetsencryptCertificate = lib_db.do__CertificateRequest__AcmeAutomated(
                    self.request.api_context,
                    domain_names=dbServerCertificate.domains_as_list,
                    account_key_pem=account_key_pem,
                    dbAccountKey=dbAccountKey,
                    private_key_pem=private_key_pem,
                    dbPrivateKey=dbPrivateKey,
                    dbServerCertificate__renewal_of=dbServerCertificate,
                )
            except (lib_errors.AcmeCommunicationError, lib_errors.DomainVerificationError), e:
                return HTTPFound('%s/certificate-requests?result=error&error=renew-acme-automated&message=%s' % (self.request.registry.settings['admin_prefix'], e.message))
            except:
                if self.request.registry.settings['exception_redirect']:
                    return HTTPFound('%s/certificate-requests?result=error&error=renew-acme-automated' % self.request.registry.settings['admin_prefix'])
                raise

            return HTTPFound('%s/certificate/%s?is_renewal=True' % (self.request.registry.settings['admin_prefix'], newLetsencryptCertificate.id))

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            return formhandling.form_reprint(
                self.request,
                self._certificate_focus_renew_custom__print,
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate:focus:mark', renderer=None)
    @view_config(route_name='admin:certificate:focus:mark.json', renderer='json')
    def certificate_focus_mark(self):
        dbServerCertificate = self._certificate_focus()
        action = '!MISSING or !INVALID'
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_Certificate_mark,
                                                             validate_get=True
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_payload_dict = lib_utils.new_event_payload_dict()
            event_payload_dict['ssl_server_certificate.id'] = dbServerCertificate.id
            event_payload_dict['action'] = action
            event_type = SslOperationsEventType.from_string('certificate__mark')

            update_recents = False
            deactivated = False
            activated = False
            event_status = False

            if action == 'active':
                if dbServerCertificate.is_active:
                    raise formhandling.FormInvalid('already active!')
                if dbServerCertificate.is_revoked:
                    raise formhandling.FormInvalid('Certificate is revoked revoked')
                dbServerCertificate.is_active = True
                if dbServerCertificate.is_deactivated:
                    dbServerCertificate.is_deactivated = False
                update_recents = True
                activated = True
                event_status = 'certificate__mark__active'

            elif action == 'inactive':
                if dbServerCertificate.is_deactivated:
                    raise formhandling.FormInvalid('Already deactivated')
                dbServerCertificate.is_deactivated = True
                dbServerCertificate.is_active = False
                update_recents = True
                deactivated = True
                event_status = 'certificate__mark__inactive'

            elif action == 'revoked':
                if dbServerCertificate.is_revoked:
                    raise formhandling.FormInvalid('Already revoked')
                dbServerCertificate.is_revoked = True
                dbServerCertificate.is_active = False
                update_recents = True
                deactivated = True
                event_type = 'certificate__revoke'
                event_status = 'certificate__mark__revoked'

            else:
                raise formhandling.FormInvalid('invalid `action`')

            self.request.api_context.dbSession.flush()

            # bookkeeping
            dbOperationsEvent = lib_db.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )
            lib_db._log_object_event(self.request.api_context,
                                     dbOperationsEvent=dbOperationsEvent,
                                     event_status_id=SslOperationsObjectEventStatus.from_string(event_status),
                                     dbServerCertificate=dbServerCertificate,
                                     )

            if update_recents:
                event_update = lib_db.operations_update_recents(self.request.api_context)
                event_update.ssl_operations_event_id__child_of = dbOperationsEvent.id
                self.request.api_context.dbSession.flush()

            if deactivated:
                # this will handle requeuing
                lib_events.Certificate_deactivated(self.request.api_context,
                                                   dbServerCertificate,
                                                   )

            if activated:
                # nothing to do?
                pass

            url_success = '%s/certificate/%s?operation=mark&action=%s&result=success' % (
                self.request.registry.settings['admin_prefix'],
                dbServerCertificate.id,
                action,
            )
            return HTTPFound(url_success)

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            url_failure = '%s/certificate/%s?operation=mark&action=%s&result=error&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbServerCertificate.id,
                action,
                e.message,
            )
            raise HTTPFound(url_failure)
