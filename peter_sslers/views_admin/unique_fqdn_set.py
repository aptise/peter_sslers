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
from ..lib.forms import (Form_CertificateUpload__file,
                         Form_CertificateRenewal_Custom,
                         )
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
        items_count = lib_db.get__LetsencryptUniqueFQDNSet__count(DBSession)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/unique_fqdn_sets/{0}')
        items_paged = lib_db.get__LetsencryptUniqueFQDNSet__paginated(DBSession, limit=items_per_page, offset=offset, eagerload_web=True)
        return {'project': 'peter_sslers',
                'LetsencryptUniqueFQDNSets_count': items_count,
                'LetsencryptUniqueFQDNSets': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _unique_fqdn_set_focus(self):
        dbItem = lib_db.get__LetsencryptUniqueFQDNSet__by_id(DBSession, self.request.matchdict['id'])
        if not dbItem:
            raise HTTPNotFound('the fqdn set was not found')
        return dbItem

    @view_config(route_name='admin:unique_fqdn_set:focus', renderer='/admin/unique_fqdn_set-focus.mako')
    def unique_fqdn_set_focus(self):
        dbItem = self._unique_fqdn_set_focus()
        return {'project': 'peter_sslers',
                'LetsencryptUniqueFQDNSet': dbItem
                }


