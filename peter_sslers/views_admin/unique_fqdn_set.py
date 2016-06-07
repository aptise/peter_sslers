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
        items_count = lib_db.get__SslUniqueFQDNSet__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/unique-fqdn-sets/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslUniqueFQDNSet__paginated(self.request.api_context, limit=items_per_page, offset=offset, eagerload_web=True)
        return {'project': 'peter_sslers',
                'SslUniqueFQDNSets_count': items_count,
                'SslUniqueFQDNSets': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _unique_fqdn_set_focus(self):
        dbItem = lib_db.get__SslUniqueFQDNSet__by_id(self.request.api_context, self.request.matchdict['id'])
        if not dbItem:
            raise HTTPNotFound('the fqdn set was not found')
        return dbItem

    @view_config(route_name='admin:unique_fqdn_set:focus', renderer='/admin/unique_fqdn_set-focus.mako')
    def unique_fqdn_set_focus(self):
        dbItem = self._unique_fqdn_set_focus()
        return {'project': 'peter_sslers',
                'SslUniqueFQDNSet': dbItem
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:unique_fqdn_set:focus:calendar', renderer='json')
    def unique_fqdn_set_focus__calendar(self):
        rval = {}
        dbUniqueFQDNSet = self._unique_fqdn_set_focus()
        weekly_certs = self.request.api_context.dbSession.query(year_week(SslServerCertificate.timestamp_signed).label('week_num'),
                                                                sqlalchemy.func.count(SslServerCertificate.id)
                                                                )\
            .filter(SslServerCertificate.ssl_unique_fqdn_set_id == dbUniqueFQDNSet.id,
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
        dbUniqueFQDNSet = self._unique_fqdn_set_focus()
        items_count = lib_db.get__SslServerCertificate__by_SslUniqueFQDNSetId__count(
            self.request.api_context, dbUniqueFQDNSet.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/unique-fqdn-set/%s/certificates/{0}' % (self.request.registry.settings['admin_prefix'], dbUniqueFQDNSet.id))
        items_paged = lib_db.get__SslServerCertificate__by_SslUniqueFQDNSetId__paginated(
            self.request.api_context, dbUniqueFQDNSet.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslUniqueFQDNSet': dbUniqueFQDNSet,
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:unique_fqdn_set:focus:certificate_requests', renderer='/admin/unique_fqdn_set-focus-certificate_requests.mako')
    @view_config(route_name='admin:unique_fqdn_set:focus:certificate_requests_paginated', renderer='/admin/unique_fqdn_set-focus-certificate_requests.mako')
    def unique_fqdn_set_focus__certificate_requests(self):
        dbUniqueFQDNSet = self._unique_fqdn_set_focus()
        items_count = lib_db.get__SslCertificateRequest__by_SslUniqueFQDNSetId__count(
            self.request.api_context, SslDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/unique-fqdn-set/%s/certificate-requests/{0}' % (self.request.registry.settings['admin_prefix'], dbUniqueFQDNSet.id))
        items_paged = lib_db.get__SslCertificateRequest__by_SslUniqueFQDNSetId__paginated(
            self.request.api_context, dbUniqueFQDNSet.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslUniqueFQDNSet': dbUniqueFQDNSet,
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }
