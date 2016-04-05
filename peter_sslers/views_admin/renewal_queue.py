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
from ..lib import cert_utils as lib_cert_utils
from ..lib import db as lib_db
from ..lib import letsencrypt_info as lib_letsencrypt_info
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:renewal_queue', renderer='/admin/renewal_queue.mako')
    @view_config(route_name='admin:renewal_queue_paginated', renderer='/admin/renewal_queue.mako')
    def rewnewal_queue(self):
        items_count = lib_db.get__LetsencryptRenewalQueue__count(DBSession, show_all=False)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/renewal_queue/{0}')
        items_paged = lib_db.get__LetsencryptRenewalQueue__paginated(DBSession, show_all=False, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptRenewalQueues_count': items_count,
                'LetsencryptRenewalQueues': items_paged,
                'sidenav_option': 'unprocessed',
                'pager': pager,
                }

    @view_config(route_name='admin:renewal_queue:all', renderer='/admin/renewal_queue.mako')
    @view_config(route_name='admin:renewal_queue:all_paginated', renderer='/admin/renewal_queue.mako')
    def renewal_queue_all(self):
        items_count = lib_db.get__LetsencryptRenewalQueue__count(DBSession, show_all=True)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/items_per_page/all/{0}')
        items_paged = lib_db.get__LetsencryptRenewalQueue__paginated(DBSession, show_all=True, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptRenewalQueues_count': items_count,
                'LetsencryptRenewalQueues': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _renewal_queue_focus(self):
        item = lib_db.get__LetsencryptRenewalQueue__by_id(DBSession, self.request.matchdict['id'])
        if not item:
            raise HTTPNotFound('the item was not found')
        return item

    @view_config(route_name='admin:renewal_queue:focus', renderer='/admin/renewal_queue-focus.mako')
    def renewal_queue_focus(self):
        dbRenewalQueueItem = self._renewal_queue_focus()
        return {'project': 'peter_sslers',
                'RenewalQueueItem': dbRenewalQueueItem,
                }

