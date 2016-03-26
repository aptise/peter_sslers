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
        dbLetsencryptDomain = lib_db.get__LetsencryptDomain__by_id(DBSession, self.request.matchdict['id'], preload=True)
        if not dbLetsencryptDomain:
            raise HTTPNotFound('the domain was not found')
        return dbLetsencryptDomain

    @view_config(route_name='admin:domain:focus', renderer='/admin/domain-focus.mako')
    def domain_focus(self):
        dbLetsencryptDomain = self._domain_focus()
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptDomain': dbLetsencryptDomain
                }

    @view_config(route_name='admin:domain:focus:config_json', renderer='json')
    def domain_focus_config_json(self):
        dbLetsencryptDomain = self._domain_focus()
        rval = {'domain': {'id': dbLetsencryptDomain.id,
                           'domain_name': dbLetsencryptDomain.domain_name,
                           },
                'latest_certificate_single': None,
                'latest_certificate_multi': None,
                }
        if dbLetsencryptDomain.letsencrypt_server_certificate_id__latest_single:
            rval['latest_certificate_single'] = dbLetsencryptDomain.latest_certificate_single.config_payload
        if dbLetsencryptDomain.letsencrypt_server_certificate_id__latest_multi:
            rval['latest_certificate_multi'] = dbLetsencryptDomain.latest_certificate_multi.config_payload
        return rval

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
