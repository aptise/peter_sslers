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
from ..lib import acme as lib_acme
from ..lib import db as lib_db
from ..lib import utils as lib_utils
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdminOperations(Handler):

    @view_config(route_name='admin:operations', renderer=None)
    def operations(self):

        return HTTPFound('%s/operations/log' % self.request.registry.settings['admin_prefix'])

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:log', renderer='/admin/operations-log.mako')
    @view_config(route_name='admin:operations:log_paginated', renderer='/admin/operations-log.mako')
    def operations_log(self):
        _items_per_page = 25
        items_count = lib_db.get__SslOperationsEvent__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/log/{0}' % self.request.registry.settings['admin_prefix'], items_per_page=_items_per_page)
        items_paged = lib_db.get__SslOperationsEvent__paginated(self.request.api_context, limit=_items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslOperationsEvents__count': items_count,
                'SslOperationsEvents': items_paged,
                'pager': pager,
                'enable_redis': self.request.registry.settings['enable_redis'],
                'enable_nginx': self.request.registry.settings['enable_nginx'],
                }

    @view_config(route_name='admin:operations:log:focus', renderer='/admin/operations-log-focus.mako')
    def operations_log_focus(self):
        _items_per_page = 25
        item = lib_db.get__SslOperationsEvent__by_id(self.request.api_context, self.request.matchdict['id'], eagerload_log=True)
        if not item:
            raise ValueError("no item")
        return {'project': 'peter_sslers',
                'SslOperationsEvent': item,
                'enable_redis': self.request.registry.settings['enable_redis'],
                'enable_nginx': self.request.registry.settings['enable_nginx'],
                }
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:ca_certificate_probes', renderer='/admin/operations-ca_certificate_probes.mako')
    @view_config(route_name='admin:operations:ca_certificate_probes_paginated', renderer='/admin/operations-ca_certificate_probes.mako')
    def ca_certificate_probes(self):
        items_count = lib_db.get__SslOperationsEvent__certificate_probe__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/ca-certificate-probes/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslOperationsEvent__certificate_probe__paginated(self.request.api_context, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslOperationsEvents_count': items_count,
                'SslOperationsEvents': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:redis', renderer='/admin/operations-redis.mako')
    @view_config(route_name='admin:operations:redis_paginated', renderer='/admin/operations-redis.mako')
    def admin_redis(self):
        self._ensure_redis()

        _items_per_page = 25
        items_count = lib_db.get__SslOperationsEvent__count(self.request.api_context, event_type_ids=(SslOperationsEventType.from_string('operations__redis_prime'), ))
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/redis/log/{0}' % self.request.registry.settings['admin_prefix'], items_per_page=_items_per_page)
        items_paged = lib_db.get__SslOperationsEvent__paginated(self.request.api_context, event_type_ids=(SslOperationsEventType.from_string('operations__redis_prime'), ), limit=_items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslOperationsEvents__count': items_count,
                'SslOperationsEvents': items_paged,
                'pager': pager,
                'enable_redis': self.request.registry.settings['enable_redis'],
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:nginx', renderer='/admin/operations-nginx.mako')
    @view_config(route_name='admin:operations:nginx_paginated', renderer='/admin/operations-nginx.mako')
    def admin_nginx(self):
        self._ensure_nginx()

        _items_per_page = 25
        _event_type_ids = (SslOperationsEventType.from_string('operations__nginx_cache_expire'), SslOperationsEventType.from_string('operations__nginx_cache_flush'))
        items_count = lib_db.get__SslOperationsEvent__count(self.request.api_context, event_type_ids=_event_type_ids)
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/nginx/log/{0}' % self.request.registry.settings['admin_prefix'], items_per_page=_items_per_page)
        items_paged = lib_db.get__SslOperationsEvent__paginated(self.request.api_context, event_type_ids=_event_type_ids,
                                                                limit=_items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslOperationsEvents__count': items_count,
                'SslOperationsEvents': items_paged,
                'pager': pager,
                'enable_nginx': self.request.registry.settings['enable_nginx'],
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:object_log', renderer='/admin/operations-object_log.mako')
    @view_config(route_name='admin:operations:object_log_paginated', renderer='/admin/operations-object_log.mako')
    def object_log(self):
        _items_per_page = 25
        items_count = lib_db.get__SslOperationsObjectEvent__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/domain-log/{0}' % self.request.registry.settings['admin_prefix'], items_per_page=_items_per_page)
        items_paged = lib_db.get__SslOperationsObjectEvent__paginated(self.request.api_context, limit=_items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslOperationsObjectEvent__count': items_count,
                'SslOperationsObjectEvents': items_paged,
                'pager': pager,
                'enable_redis': self.request.registry.settings['enable_redis'],
                'enable_nginx': self.request.registry.settings['enable_nginx'],
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
