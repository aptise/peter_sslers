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
from ..lib import acme as lib_acme
from ..lib import db as lib_db
from ..lib.handler import Handler, items_per_page
from ..lib import utils as lib_utils
from ..lib import errors as lib_errors


# ==============================================================================


class ViewAdmin(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:unique_fqdn_sets', renderer='/admin/unique_fqdn_sets.mako')
    @view_config(route_name='admin:unique_fqdn_sets_paginated', renderer='/admin/unique_fqdn_sets.mako')
    def unique_fqdn_sets(self):
        items_count = lib_db.get__LetsencryptUniqueFQDNSet__count(self.request.dbsession)
        (pager, offset) = self._paginate(items_count, url_template='%s/unique-fqdn-sets/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__LetsencryptUniqueFQDNSet__paginated(self.request.dbsession, limit=items_per_page, offset=offset, eagerload_web=True)
        return {'project': 'peter_sslers',
                'LetsencryptUniqueFQDNSets_count': items_count,
                'LetsencryptUniqueFQDNSets': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _unique_fqdn_set_focus(self):
        dbItem = lib_db.get__LetsencryptUniqueFQDNSet__by_id(self.request.dbsession, self.request.matchdict['id'])
        if not dbItem:
            raise HTTPNotFound('the fqdn set was not found')
        return dbItem

    @view_config(route_name='admin:unique_fqdn_set:focus', renderer='/admin/unique_fqdn_set-focus.mako')
    def unique_fqdn_set_focus(self):
        dbItem = self._unique_fqdn_set_focus()
        return {'project': 'peter_sslers',
                'LetsencryptUniqueFQDNSet': dbItem
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:unique_fqdn_set:focus:calendar', renderer='json')
    def unique_fqdn_set_focus__calendar(self):
        rval = {}
        dbLetsencryptUniqueFQDNSet = self._unique_fqdn_set_focus()
        weekly_certs = self.request.dbsession.query(year_week(LetsencryptServerCertificate.timestamp_signed).label('week_num'),
                                                    sqlalchemy.func.count(LetsencryptServerCertificate.id)
                                                    )\
            .filter(LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == dbLetsencryptUniqueFQDNSet.id,
                    )\
            .group_by('week_num')\
            .order_by(sqlalchemy.asc('week_num'))\
            .all()
        rval['issues'] = {}
        for wc in weekly_certs:
            rval['issues'][str(wc[0])] = wc[1]
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:unique_fqdn_set:focus:certificates', renderer='/admin/unique_fqdn_set-focus-certificates.mako')
    @view_config(route_name='admin:unique_fqdn_set:focus:certificates_paginated', renderer='/admin/unique_fqdn_set-focus-certificates.mako')
    def unique_fqdn_set_focus__certificates(self):
        dbLetsencryptUniqueFQDNSet = self._unique_fqdn_set_focus()
        items_count = lib_db.get__LetsencryptServerCertificate__by_LetsencryptUniqueFQDNSetId__count(
            self.request.dbsession, dbLetsencryptUniqueFQDNSet.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/unique-fqdn-set/%s/certificates/{0}' % (self.request.registry.settings['admin_prefix'], dbLetsencryptUniqueFQDNSet.id))
        items_paged = lib_db.get__LetsencryptServerCertificate__by_LetsencryptUniqueFQDNSetId__paginated(
            self.request.dbsession, dbLetsencryptUniqueFQDNSet.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptUniqueFQDNSet': dbLetsencryptUniqueFQDNSet,
                'LetsencryptServerCertificates_count': items_count,
                'LetsencryptServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:unique_fqdn_set:focus:certificate_requests', renderer='/admin/unique_fqdn_set-focus-certificate_requests.mako')
    @view_config(route_name='admin:unique_fqdn_set:focus:certificate_requests_paginated', renderer='/admin/unique_fqdn_set-focus-certificate_requests.mako')
    def unique_fqdn_set_focus__certificate_requests(self):
        dbLetsencryptUniqueFQDNSet = self._unique_fqdn_set_focus()
        items_count = lib_db.get__LetsencryptCertificateRequest__by_LetsencryptUniqueFQDNSetId__count(
            self.request.dbsession, LetsencryptDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/unique-fqdn-set/%s/certificate-requests/{0}' % (self.request.registry.settings['admin_prefix'], dbLetsencryptUniqueFQDNSet.id))
        items_paged = lib_db.get__LetsencryptCertificateRequest__by_LetsencryptUniqueFQDNSetId__paginated(
            self.request.dbsession, dbLetsencryptUniqueFQDNSet.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptUniqueFQDNSet': dbLetsencryptUniqueFQDNSet,
                'LetsencryptCertificateRequests_count': items_count,
                'LetsencryptCertificateRequests': items_paged,
                'pager': pager,
                }
