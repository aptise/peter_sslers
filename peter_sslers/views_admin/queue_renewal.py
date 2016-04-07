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
import transaction

# localapp
from ..models import *
from ..lib import acme as lib_acme
from ..lib import cert_utils as lib_cert_utils
from ..lib import db as lib_db
from ..lib import letsencrypt_info as lib_letsencrypt_info
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:queue_renewals', renderer='/admin/queue-renewals.mako')
    @view_config(route_name='admin:queue_renewals_paginated', renderer='/admin/queue-renewals.mako')
    def rewnewal_queue(self):
        items_count = lib_db.get__LetsencryptQueueRenewal__count(self.request.dbsession, show_all=False)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/queue-renewals/{0}')
        items_paged = lib_db.get__LetsencryptQueueRenewal__paginated(self.request.dbsession, show_all=False, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptQueueRenewals_count': items_count,
                'LetsencryptQueueRenewals': items_paged,
                'sidenav_option': 'unprocessed',
                'pager': pager,
                }

    @view_config(route_name='admin:queue_renewals:all', renderer='/admin/queue-renewals.mako')
    @view_config(route_name='admin:queue_renewals:all_paginated', renderer='/admin/queue-renewals.mako')
    def queue_renewal_all(self):
        items_count = lib_db.get__LetsencryptQueueRenewal__count(self.request.dbsession, show_all=True)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/queue-renewals/all/{0}')
        items_paged = lib_db.get__LetsencryptQueueRenewal__paginated(self.request.dbsession, show_all=True, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptQueueRenewals_count': items_count,
                'LetsencryptQueueRenewals': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _queue_renewal_focus(self):
        item = lib_db.get__LetsencryptQueueRenewal__by_id(self.request.dbsession, self.request.matchdict['id'])
        if not item:
            raise HTTPNotFound('the item was not found')
        return item

    @view_config(route_name='admin:queue_renewal:focus', renderer='/admin/queue-renewal-focus.mako')
    def queue_renewal_focus(self):
        dbRenewalQueueItem = self._queue_renewal_focus()
        return {'project': 'peter_sslers',
                'RenewalQueueItem': dbRenewalQueueItem,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_renewals:process', renderer=None)
    @view_config(route_name='admin:queue_renewals:process.json', renderer='json')
    def queue_renewal_process(self):
        try:
            queue_results = lib_db.queue_renewals__process(self.request.dbsession)
            if self.request.matched_route.name == 'admin:queue_renewals:process.json':
                return {'result': 'success',
                        }
            return HTTPFound("/.well-known/admin/queue-renewals?processed=1")
        except Exception as e:
            transaction.abort()
            if self.request.matched_route.name == 'admin:queue_renewals:process.json':
                return {'result': 'error',
                        'error': e.message,
                        }
            raise        
            