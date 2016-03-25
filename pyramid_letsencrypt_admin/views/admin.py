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
import pypages
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import *
from ..lib.forms import (Form_CertificateRequest_new_flow,
                         # Form_CertificateRequest_new_full,
                         Form_CertificateRequest_new_full__file,
                         Form_CertificateRequest_process_domain,
                         Form_CertificateUpload__file,
                         Form_PrivateKey_new__file,
                         Form_AccountKey_new__file,
                         )
from ..lib import acme as lib_acme
from ..lib import db as lib_db
from ._core import Handler


# ==============================================================================


# misc config options
items_per_page = 50


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name="admin_whoami", renderer="string")
    def public_whoami(self):
        """this is really only useful for testing"""
        return self.request.active_domain_name

    @view_config(route_name='admin', renderer='/admin/index.mako')
    def index(self):
        return {'project': 'pyramid_letsencrypt_admin',
                'enable_redis': self.request.registry.settings['enable_redis'],
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _paginate(self, collection_count, items_per_page=items_per_page, url_template=None):
        page_requested = 1 if 'page' not in self.request.matchdict else int(self.request.matchdict['page'])
        pager = pypages.Paginator(collection_count,
                                  per_page=items_per_page,
                                  current=page_requested,
                                  start=None,
                                  range_num=10
                                  )
        pager.template = url_template
        if page_requested == 0:
            raise HTTPFound(pager.template.format(1))
        if page_requested > pager.page_num:
            if pager.page_num > 0:
                raise HTTPFound(pager.template.format(pager.page_num))
        # return pager, offset
        return pager, ((page_requested - 1) * items_per_page)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domains', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains_paginated', renderer='/admin/domains.mako')
    def domains(self):
        dbLetsencryptDomains_count = lib_db.get__LetsencryptDomain__count(DBSession)
        (pager, offset) = self._paginate(dbLetsencryptDomains_count, url_template='/.well-known/admin/domains/{0}')
        dbLetsencryptDomains = lib_db.get__LetsencryptDomain__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptDomains_count': dbLetsencryptDomains_count,
                'LetsencryptDomains': dbLetsencryptDomains,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _domain_focus(self):
        dbLetsencryptDomain = lib_db.get__LetsencryptDomain__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptDomain:
            raise HTTPNotFound('the domain was not found')
        return dbLetsencryptDomain

    @view_config(route_name='admin:domain:focus', renderer='/admin/domain-focus.mako')
    def domain_focus(self):
        dbLetsencryptDomain = self._domain_focus()
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptDomain': dbLetsencryptDomain
                }

    @view_config(route_name='admin:domain:focus:certificates', renderer='/admin/domain-focus-certificates.mako')
    @view_config(route_name='admin:domain:focus:certificates_paginated', renderer='/admin/domain-focus-certificates.mako')
    def domain_focus__certificates(self):
        dbLetsencryptDomain = self._domain_focus()
        dbLetsencryptServerCertificates_count = lib_db.get__LetsencryptServerCertificate__by_LetsencryptDomain__count(
            DBSession, dbLetsencryptDomain.id)
        (pager, offset) = self._paginate(dbLetsencryptServerCertificates_count, url_template='/.well-known/admin/domain/%s/certificates/{0}' % dbLetsencryptDomain.id)
        dbLetsencryptServerCertificates = lib_db.get__LetsencryptServerCertificate__by_LetsencryptDomain__paginated(
            DBSession, dbLetsencryptDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptDomain': dbLetsencryptDomain,
                'LetsencryptServerCertificates_count': dbLetsencryptServerCertificates_count,
                'LetsencryptServerCertificates': dbLetsencryptServerCertificates,
                'pager': pager,
                }

    @view_config(route_name='admin:domain:focus:certificate_requests', renderer='/admin/domain-focus-certificate_requests.mako')
    @view_config(route_name='admin:domain:focus:certificate_requests_paginated', renderer='/admin/domain-focus-certificate_requests.mako')
    def domain_focus__certificate_requests(self):
        dbLetsencryptDomain = self._domain_focus()
        dbLetsencryptCertificateRequests_count = lib_db.get__LetsencryptCertificateRequest__by_LetsencryptDomain__count(
            DBSession, LetsencryptDomain.id)
        (pager, offset) = self._paginate(dbLetsencryptCertificateRequests_count, url_template='/.well-known/admin/domain/%s/certificate_requests/{0}' % LetsencryptDomain.id)
        dbLetsencryptCertificateRequests = lib_db.get__LetsencryptCertificateRequest__by_LetsencryptDomain__paginated(
            DBSession, dbLetsencryptDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptDomain': dbLetsencryptDomain,
                'LetsencryptCertificateRequests_count': dbLetsencryptCertificateRequests_count,
                'LetsencryptCertificateRequests': dbLetsencryptCertificateRequests,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:deactivate_expired', renderer='json')
    def operations_deactivate_expired(self):
        rval = {}

        # deactivate expired certificates
        expired_certs = DBSession.query(LetsencryptServerCertificate)\
            .filter(LetsencryptServerCertificate.is_active is True,  # noqa
                    LetsencryptServerCertificate.timestamp_expires < datetime.datetime.utcnow(),
                    )\
            .all()
        for c in expired_certs:
            c.is_active = False
        rval['LetsencryptServerCertificate'] = {'expired': len(expired_certs), }
        DBSession.flush()

        # track latest_cert_single and multi

        # deactivate duplicate certificates
        if False:
            """
            UPDATE letsencrypt_domain
            SET letsencrypt_server_certificate_id__latest_single = (
                SELECT id FROM (
                    SELECT
                        letsencrypt_server_certificate.id,
                        letsencrypt_server_certificate_to_domain.letsencrypt_domain_id
                    FROM letsencrypt_server_certificate
                    JOIN letsencrypt_server_certificate_to_domain
                        ON (letsencrypt_server_certificate.id = letsencrypt_server_certificate_to_domain.letsencrypt_server_certificate_id)
                    WHERE letsencrypt_server_certificate.is_single_domain_cert = 1
                    ORDER BY letsencrypt_server_certificate.timestamp_expires DESC
                    LIMIT 1
                ) q_inner
                WHERE letsencrypt_domain.id = q_inner.letsencrypt_domain_id
            );

            UPDATE letsencrypt_domain
            SET letsencrypt_server_certificate_id__latest_multi = (
                SELECT id FROM (
                    SELECT
                        letsencrypt_server_certificate.id,
                        letsencrypt_server_certificate_to_domain.letsencrypt_domain_id
                    FROM letsencrypt_server_certificate
                    JOIN letsencrypt_server_certificate_to_domain
                        ON (letsencrypt_server_certificate.id = letsencrypt_server_certificate_to_domain.letsencrypt_server_certificate_id)
                    WHERE letsencrypt_server_certificate.is_single_domain_cert = -1
                    ORDER BY letsencrypt_server_certificate.timestamp_expires DESC
                    LIMIT 1
                ) q_inner
                WHERE letsencrypt_domain.id = q_inner.letsencrypt_domain_id
            );


            """

            """
            this doesn't work right.
            since CERTs can have multiple domains, it's a bit of a pain to find the latest cert.
            """
            q_inner = DBSession.query(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id,
                                      sqlalchemy.func.count(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id).label('counted'),
                                      )\
                .join(LetsencryptServerCertificate,
                      LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id == LetsencryptServerCertificate.id
                      )\
                .filter(LetsencryptServerCertificate.is_active == True,  # noqa
                        )\
                .group_by(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id)
            q_inner = q_inner.subquery()
            q_domains = DBSession.query(q_inner)\
                .filter(q_inner.c.counted >= 2)
            result = q_domains.all()
            domain_ids_with_multiple_active_certs = [i.letsencrypt_domain_id for i in result]

            print "domain_ids_with_multiple_active_certs"
            print domain_ids_with_multiple_active_certs

            _turned_off = []
            for _domain_id in domain_ids_with_multiple_active_certs:
                domain_certs = DBSession.query(LetsencryptServerCertificate)\
                    .join(LetsencryptServerCertificate2LetsencryptDomain,
                          LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id,
                          )\
                    .filter(LetsencryptServerCertificate.is_active == True,  # noqa
                            LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == _domain_id,
                            )\
                    .order_by(LetsencryptServerCertificate.timestamp_expires.desc())\
                    .all()
                if True:
                    print "CHECKING DOMAIN_ID(%s)" % _domain_id
                    print "-FOUND %s certs" % len(domain_certs)
                    print domain_certs
                    for d in domain_certs:
                        print "-- %s, %s" % (d.id, d)
                    print "len(domain_certs) <= 1: %s" % (len(domain_certs) <= 1)
                if len(domain_certs) <= 1:
                    raise ValueError("Expected more >= 2 certs")
                for cert in domain_certs[1:]:
                    print "TURNING OFF CERT - %s" % cert.id
                    cert.is_active = False
                    _turned_off.append(cert)
            raise ValueError("ok")

        rval['LetsencryptServerCertificate']['duplicates.deactivated'] = len(_turned_off)
        DBSession.flush()

        raise ValueError(domains_with_multiple_active_certs)

        duplicate_certs = DBSession.query(LetsencryptServerCertificate)\
            .join(LetsencryptServerCertificate2LetsencryptDomain,
                  LetsencryptServerCertificate.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id,
                  )\
            .join(LetsencryptDomain,
                  LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id == LetsencryptDomain.id,
                  )\
            .filter(LetsencryptServerCertificate.is_active.op('IS')(True),
                    )\
            .group_by(LetsencryptDomain.id,)\
            .all()
        print duplicate_certs
        raise ValueError(duplicate_certs)

        return rval
        return HTTPFound('/.well-known/admin?result=success&operation=operations.deactivate_expired')

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificates', renderer='/admin/certificates.mako')
    @view_config(route_name='admin:certificates_paginated', renderer='/admin/certificates.mako')
    def certificates(self):
        dbLetsencryptServerCertificates_count = lib_db.get__LetsencryptServerCertificate__count(DBSession)
        (pager, offset) = self._paginate(dbLetsencryptServerCertificates_count, url_template='/.well-known/admin/certificates/{0}')
        dbLetsencryptServerCertificates = lib_db.get__LetsencryptServerCertificate__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptServerCertificates_count': dbLetsencryptServerCertificates_count,
                'LetsencryptServerCertificates': dbLetsencryptServerCertificates,
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
            return {'instructions': """curl --form 'private_key_file=@privkey1.pem' --form 'certificate_file=@cert1.pem' --form 'chain_file=@chain1.pem' http://127.0.0.1:6543/.well-known/admin/certificate/upload/json""",
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
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptServerCertificate': dbLetsencryptServerCertificate
                }

    @view_config(route_name='admin:certificate:focus:chain:raw', renderer='string')
    def certificate_focus_chain(self):
        # application/x-pem-file              .pem
        dbLetsencryptServerCertificate = self._certificate_focus()
        return 'chain.pem'

    @view_config(route_name='admin:certificate:focus:fullchain:raw', renderer='string')
    def certificate_focus_fullchain(self):
        #  application/x-pkcs7-certificates    .p7b .spc
        # PKCS#12 bundles of private key + certificate(s)
        # application/x-pkcs7-certificates    .p7b .spc
        dbLetsencryptServerCertificate = self._certificate_focus()
        return 'fullchain.pem'

    @view_config(route_name='admin:certificate:focus:privatekey:raw', renderer='string')
    def certificate_focus_privatekey(self):
        dbLetsencryptServerCertificate = self._certificate_focus()
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

    @view_config(route_name='admin:certificate_requests', renderer='/admin/certificate_requests.mako')
    @view_config(route_name='admin:certificate_requests_paginated', renderer='/admin/certificate_requests.mako')
    def certificate_requests(self):
        dbLetsencryptCertificateRequests_count = lib_db.get__LetsencryptCertificateRequest__count(DBSession)
        (pager, offset) = self._paginate(dbLetsencryptCertificateRequests_count, url_template='/.well-known/admin/certificate_requests/{0}')
        dbLetsencryptCertificateRequests = lib_db.get__LetsencryptCertificateRequest__paginated(DBSession, limit=items_per_page, offset=offset)

        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCertificateRequests_count': dbLetsencryptCertificateRequests_count,
                'LetsencryptCertificateRequests': dbLetsencryptCertificateRequests,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:focus', renderer='/admin/certificate_request-focus.mako')
    def certificate_request_focus(self):
        certificate_request_id = int(self.request.matchdict['id'])
        dbLetsencryptCertificateRequest = lib_db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
        if not dbLetsencryptCertificateRequest:
            raise HTTPNotFound('the certificate_request was not found')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCertificateRequest': dbLetsencryptCertificateRequest
                }

    @view_config(route_name='admin:certificate_request:focus:raw', renderer='string')
    def certificate_request_focus_raw(self):
        dbLetsencryptCertificateRequest = lib_db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
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
        dbLetsencryptCertificateRequest = lib_db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
        if not dbLetsencryptCertificateRequest:
            raise HTTPNotFound('the certificate_request was not found')
        if not dbLetsencryptCertificateRequest.certificate_request_type_is('flow'):
            raise HTTPNotFound('Only availble for FLOW')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCertificateRequest': dbLetsencryptCertificateRequest,
                'LetsencryptCertificateRequest2LetsencryptDomain': None,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:certificate_request:deactivate')
    def certificate_request_deactivate(self):
        certificate_request_id = int(self.request.matchdict['id'])
        dbLetsencryptCertificateRequest = lib_db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
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
        dbLetsencryptCertificateRequest = lib_db.get__LetsencryptCertificateRequest__by_id(DBSession, certificate_request_id)
        if not dbLetsencryptCertificateRequest:
            raise HTTPNotFound('the certificate_request was not found')
        if not dbLetsencryptCertificateRequest.certificate_request_type_is('flow'):
            raise HTTPNotFound('Only availble for FLOW')
        dbLetsencryptCertificateRequest2LetsencryptDomain = None
        domain_id = int(self.request.matchdict['domain_id'])
        for to_domain in dbLetsencryptCertificateRequest.certificate_request_to_domains:
            if to_domain.letsencrypt_domain_id == domain_id:
                dbLetsencryptCertificateRequest2LetsencryptDomain = to_domain
                break
        if dbLetsencryptCertificateRequest2LetsencryptDomain is None:
            raise HTTPNotFound('invalid domain for certificate request')

        self.db_LetsencryptCertificateRequest = dbLetsencryptCertificateRequest
        self.db_LetsencryptCertificateRequest2LetsencryptDomain = dbLetsencryptCertificateRequest2LetsencryptDomain

        if self.request.POST:
            return self._certificate_request_process_domain__submit()
        return self._certificate_request_process_domain__print()

    def _certificate_request_process_domain__print(self):
        return render_to_response("/admin/certificate_request-process.mako",
                                  {'LetsencryptCertificateRequest': self.db_LetsencryptCertificateRequest,
                                   'LetsencryptCertificateRequest2LetsencryptDomain': self.db_LetsencryptCertificateRequest2LetsencryptDomain,
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

            if self.db_LetsencryptCertificateRequest2LetsencryptDomain.timestamp_verified:
                raise ValueError("You can not edit the challenge of a verified item")

            changed = False
            for attribute in ('challenge_key', 'challenge_text'):
                submitted_value = formStash.results[attribute]
                if submitted_value != getattr(self.db_LetsencryptCertificateRequest2LetsencryptDomain, attribute):
                    setattr(self.db_LetsencryptCertificateRequest2LetsencryptDomain, attribute, submitted_value)
                    changed = True

            if not changed:
                raise ValueError("No changes!")

            DBSession.flush()

            return HTTPFound('/.well-known/admin/certificate_request/%s/process/domain/%s' %
                             (self.db_LetsencryptCertificateRequest.id,
                              self.db_LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id
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
            dbLetsencryptCertificateRequest = lib_db.create__CertificateRequest__by_domainNamesList_FLOW(DBSession, domain_names)

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
            private_key_pem = formStash.results['private_key_file'].file.read()

            try:
                dbLetsencryptCertificate = lib_db.create__CertificateRequest__FULL(
                    DBSession,
                    domain_names,
                    account_key_pem=account_key_pem,
                    private_key_pem=private_key_pem,
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
        dbLetsencryptAccountKeys_count = lib_db.get__LetsencryptAccountKey__count(DBSession)
        (pager, offset) = self._paginate(dbLetsencryptAccountKeys_count, url_template='/.well-known/admin/account_keys/{0}')
        dbLetsencryptAccountKeys = lib_db.get__LetsencryptAccountKey__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptAccountKeys_count': dbLetsencryptAccountKeys_count,
                'LetsencryptAccountKeys': dbLetsencryptAccountKeys,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:account_key:focus', renderer='/admin/account_key-focus.mako')
    def account_key_focus(self):
        dbLetsencryptAccountKey = lib_db.get__LetsencryptAccountKey__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptAccountKey:
            raise HTTPNotFound('the key was not found')
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptAccountKey': dbLetsencryptAccountKey
                }

    @view_config(route_name='admin:account_key:focus:raw', renderer='string')
    def account_key_focus_raw(self):
        dbLetsencryptAccountKey = lib_db.get__LetsencryptAccountKey__by_id(DBSession, self.request.matchdict['id'])
        if not dbLetsencryptAccountKey:
            raise HTTPNotFound('the key was not found')
        if self.request.matchdict['format'] == 'pem':
            self.request.response.content_type = 'application/x-pem-file'
            return dbLetsencryptAccountKey.key_pem
        elif self.request.matchdict['format'] == 'pem.txt':
            return dbLetsencryptAccountKey.key_pem
        elif self.request.matchdict['format'] == 'key':
            self.request.response.content_type = 'application/pkcs8'
            as_der = lib_acme.convert_pem_to_der(pem_data=dbLetsencryptAccountKey.key_pem)
            return as_der

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

            return HTTPFound('/.well-known/admin/account_key/%s%s' % (dbLetsencryptAccountKey.id, ('?is_created=1' if _is_created else '')))

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

    @view_config(route_name='admin:private_keys', renderer='/admin/private_keys.mako')
    @view_config(route_name='admin:private_keys_paginated', renderer='/admin/private_keys.mako')
    def private_keys(self):
        dbLetsencryptPrivateKeys_count = lib_db.get__LetsencryptPrivateKey__count(DBSession)
        (pager, offset) = self._paginate(dbLetsencryptPrivateKeys_count, url_template='/.well-known/admin/private_keys/{0}')
        dbLetsencryptPrivateKeys = lib_db.get__LetsencryptPrivateKey__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptPrivateKeys_count': dbLetsencryptPrivateKeys_count,
                'LetsencryptPrivateKeys': dbLetsencryptPrivateKeys,
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

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:ca_certificates', renderer='/admin/ca_certificates.mako')
    @view_config(route_name='admin:ca_certificates_paginated', renderer='/admin/ca_certificates.mako')
    def ca_certificates(self):
        dbLetsencryptCACertificates_count = lib_db.get__LetsencryptCACertificate__count(DBSession)
        (pager, offset) = self._paginate(dbLetsencryptCACertificates_count, url_template='/.well-known/admin/ca_certificates/{0}')
        dbLetsencryptCACertificates = lib_db.get__LetsencryptCACertificate__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificates_count': dbLetsencryptCACertificates_count,
                'LetsencryptCACertificates': dbLetsencryptCACertificates,
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
        dbLetsencryptServerCertificates_count = lib_db.get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__count(
            DBSession, dbLetsencryptCACertificate.id)
        dbLetsencryptServerCertificates = lib_db.get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__paginated(
            DBSession, dbLetsencryptCACertificate.id, limit=10, offset=0)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificate': dbLetsencryptCACertificate,
                'LetsencryptServerCertificates_count': dbLetsencryptServerCertificates_count,
                'LetsencryptServerCertificates': dbLetsencryptServerCertificates,
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
            as_der = lib_acme.convert_pem_to_der(pem_data=dbLetsencryptCACertificate.cert_pem)
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
        dbLetsencryptServerCertificates_count = lib_db.get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__count(
            DBSession, dbLetsencryptCACertificate.id)
        (pager, offset) = self._paginate(dbLetsencryptServerCertificates_count, url_template='/.well-known/admin/ca_certificate/%s/signed_certificates/{0}' % dbLetsencryptCACertificate.id)
        dbLetsencryptServerCertificates = lib_db.get__LetsencryptServerCertificate__by_LetsencryptCACertificateId__paginated(
            DBSession, dbLetsencryptCACertificate.id, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificate': dbLetsencryptCACertificate,
                'LetsencryptServerCertificates_count': dbLetsencryptServerCertificates_count,
                'LetsencryptServerCertificates': dbLetsencryptServerCertificates,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:ca_certificate_probes', renderer='/admin/ca_certificate_probes.mako')
    def ca_certificate_probes(self):
        dbLetsencryptCACertificateProbes_count = lib_db.get__LetsencryptCACertificateProbe__count(DBSession)
        (pager, offset) = self._paginate(dbLetsencryptCACertificateProbes_count, url_template='/.well-known/admin/ca_certificate_probes/{0}')
        dbLetsencryptCACertificateProbes = lib_db.get__LetsencryptCACertificateProbe__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptCACertificateProbes_count': dbLetsencryptCACertificateProbes_count,
                'LetsencryptCACertificateProbes': dbLetsencryptCACertificateProbes,
                'pager': pager,
                }

    @view_config(route_name='admin:ca_certificate_probes:probe', renderer=None)
    def ca_certificate_probes_probe(self):
        if self.request.POST:
            return HTTPFound("/.well-known/admin/ca_certificate_probes?error=POST-only")

        probeEvent = lib_db.ca_certificate_probe(DBSession)

        return HTTPFound("/.well-known/admin/ca_certificate_probes?success=True")

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _ensure_redis(self):
        if not self.request.registry.settings['enable_redis']:
            raise HTTPFound('/.well-known/admin?error=no_redis')

    @view_config(route_name='admin:redis', renderer='/admin/redis.mako')
    def admin_redis(self):
        self._ensure_redis()
        return {'project': 'pyramid_letsencrypt_admin',
                'enable_redis': self.request.registry.settings['enable_redis'],
                }

    @view_config(route_name='admin:redis:prime', renderer=None)
    def admin_redis_prime(self):
        self._ensure_redis()

        redis_url = self.request.registry.settings['redis.url']
        redis_options = {}
        redis_client = lib.utils.get_default_connection(self.request, redis_url, **redis_options)

        """
        r['d:foo.example.com'] = ('cert:1', 'key:a', 'fullcert:99')
        r['d:foo2.example.com'] = ('cert:2', 'key:a', 'fullcert:99')
        r['c:1'] = CERT.DER
        r['c:2'] = CERT.DER
        r['k:2'] = PKEY.DER
        r['s:99'] = CACERT.DER

        prime script should:
            loop through all ca_cert> cache into redis
            loop through all pkey> cache into redis
            loop through all cert> cache into redis
        """

        raise HTTPFound('/.well-known/admin/redis?operation=prime&result=success')
