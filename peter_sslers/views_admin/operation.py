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
        items_count = lib_db.get__SslOperationsEvent__count(self.request.dbsession)
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/log/{0}' % self.request.registry.settings['admin_prefix'], items_per_page=_items_per_page)
        items_paged = lib_db.get__SslOperationsEvent__paginated(self.request.dbsession, limit=_items_per_page, offset=offset)
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
        item = lib_db.get__SslOperationsEvent__by_id(self.request.dbsession, self.request.matchdict['id'])
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
        items_count = lib_db.get__SslOperationsEvent__certificate_probe__count(self.request.dbsession)
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/ca-certificate-probes/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslOperationsEvent__certificate_probe__paginated(self.request.dbsession, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslOperationsEvents_count': items_count,
                'SslOperationsEvents': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:operations:ca_certificate_probes:probe', renderer=None)
    @view_config(route_name='admin:operations:ca_certificate_probes:probe.json', renderer='json')
    def ca_certificate_probes__probe(self):
        operations_event = lib_db.ca_certificate_probe(self.request.dbsession)

        if self.request.matched_route.name == 'admin:operations:ca_certificate_probes:probe.json':
            return {'result': 'success',
                    'operations_event': {'id': operations_event.id,
                                         'is_certificates_discovered': operations_event.event_payload_json['is_certificates_discovered'],
                                         'is_certificates_updated': operations_event.event_payload_json['is_certificates_updated'],
                                         },
                    }
        return HTTPFound("%s/operations/ca-certificate-probes?success=True&event.id=%s" % (self.request.registry.settings['admin_prefix'], operations_event.id))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:update_recents', renderer=None)
    @view_config(route_name='admin:operations:update_recents.json', renderer='json')
    def operations_update_recents(self):
        operations_event = lib_db.operations_update_recents(self.request.dbsession)

        if self.request.matched_route.name == 'admin:operations:update_recents.json':
            return {'result': 'success',
                    'operations_event': operations_event.id,
                    }

        return HTTPFound("%s/operations/log?success=True&event.id=%s" % (self.request.registry.settings['admin_prefix'], operations_event.id))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:deactivate_expired', renderer=None)
    @view_config(route_name='admin:operations:deactivate_expired.json', renderer='json')
    def operations_deactivate_expired(self):
        rval = {}

        # MUST run this first
        operations_event1 = lib_db.operations_update_recents(self.request.dbsession)

        # then this
        operations_event2 = lib_db.operations_deactivate_expired(self.request.dbsession)
        count_deactivated_expired = operations_event2.event_payload_json['count_deactivated']
        rval['SslServerCertificate'] = {'expired': count_deactivated_expired, }

        operations_event1.ssl_operations_event_id__child_of = operations_event2.id

        rval['result'] = 'success'
        rval['operations_event'] = operations_event2.id

        if self.request.matched_route.name == 'admin:operations:deactivate_expired.json':
            return rval

        return HTTPFound('%s/operations/log?result=success&event.id=%s' % (self.request.registry.settings['admin_prefix'], operations_event2.id))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _ensure_redis(self):
        if not self.request.registry.settings['enable_redis']:
            raise HTTPFound('%s?error=no_redis' % self.request.registry.settings['admin_prefix'])

    @view_config(route_name='admin:operations:redis', renderer='/admin/operations-redis.mako')
    @view_config(route_name='admin:operations:redis_paginated', renderer='/admin/operations-redis.mako')
    def admin_redis(self):
        self._ensure_redis()

        _items_per_page = 25
        items_count = lib_db.get__SslOperationsEvent__count(self.request.dbsession, event_type_ids=(SslOperationsEventType.redis_prime, ))
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/redis/log/{0}' % self.request.registry.settings['admin_prefix'], items_per_page=_items_per_page)
        items_paged = lib_db.get__SslOperationsEvent__paginated(self.request.dbsession, event_type_ids=(SslOperationsEventType.redis_prime, ), limit=_items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslOperationsEvents__count': items_count,
                'SslOperationsEvents': items_paged,
                'pager': pager,
                'enable_redis': self.request.registry.settings['enable_redis'],
                }

    @view_config(route_name='admin:operations:redis:prime', renderer=None)
    @view_config(route_name='admin:operations:redis:prime.json', renderer='json')
    def admin_redis_prime(self):
        self._ensure_redis()

        prime_style = lib_utils.redis_prime_style(self.request)
        if not prime_style:
            raise ValueError("invalid `redis.prime_style`")
        redis_client = lib_utils.redis_connection_from_registry(self.request)
        redis_timeouts = lib_utils.redis_timeouts_from_registry(self.request)

        total_primed = {'cacert': 0,
                        'cert': 0,
                        'pkey': 0,
                        'domain': 0,
                        }

        dbEvent = None
        if prime_style == '1':
            """
            first priming style
            --
            the redis datastore will look like this:

                r['d:foo.example.com'] = {'c': '1', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
                r['d:foo2.example.com'] = {'c': '2', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
                r['c1'] = CERT.PEM  # (c)ert
                r['c2'] = CERT.PEM
                r['p2'] = PKEY.PEM  # (p)rivate
                r['i99'] = CACERT.PEM  # (i)ntermediate cert

            to assemble the data for `foo.example.com`:

                * (c, p, i) = r.hmget('d:foo.example.com', 'c', 'p', 'i')
                ** returns {'c': '1', 'p': '1', 'i': '99'}
                * cert = r.get('c1')
                * pkey = r.get('p1')
                * chain = r.get('i99')
                * fullchain = cert + "\n" + chain
            """
            # prime the CACertificates that are active
            offset = 0
            limit = 100
            while True:
                active_certs = lib_db.get__SslCaCertificate__paginated(
                    self.request.dbsession,
                    offset=offset,
                    limit=limit,
                    active_only=True
                )
                if not active_certs:
                    # no certs
                    break
                for dbCACertificate in active_certs:
                    total_primed['cacert'] += 1
                    is_primed = lib_utils.redis_prime_logic__style_1_CACertificate(redis_client, dbCACertificate, redis_timeouts)
                if len(active_certs) < limit:
                    # no more
                    break
                offset += limit

            # prime PrivateKeys that are active
            offset = 0
            limit = 100
            while True:
                active_keys = lib_db.get__SslPrivateKey__paginated(
                    self.request.dbsession,
                    offset=offset,
                    limit=limit,
                    active_only=True
                )
                if not active_keys:
                    # no keys
                    break
                for dbPrivateKey in active_keys:
                    total_primed['pkey'] += 1
                    is_primed = lib_utils.redis_prime_logic__style_1_PrivateKey(redis_client, dbPrivateKey, redis_timeouts)

                if len(active_keys) < limit:
                    # no more
                    break
                offset += limit

            # prime Domains
            offset = 0
            limit = 100
            while True:
                active_domains = lib_db.get__SslDomain__paginated(
                    self.request.dbsession,
                    offset=offset,
                    limit=limit,
                    active_only=True
                )
                if not active_domains:
                    # no domains
                    break
                for dbDomain in active_domains:
                    # favor the multi:
                    total_primed['domain'] += 1
                    is_primed = lib_utils.redis_prime_logic__style_1_Domain(redis_client, dbDomain, redis_timeouts)

                if len(active_domains) < limit:
                    # no more
                    break
                offset += limit

        elif prime_style == '2':
            """
            first priming style
            --
            the redis datastore will look like this:

                r['foo.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}
                r['foo2.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}

            to assemble the data for `foo.example.com`:

                * (f, p) = r.hmget('foo.example.com', 'f', 'p')
            """

            # prime Domains
            offset = 0
            limit = 100
            while True:
                active_domains = lib_db.get__SslDomain__paginated(
                    self.request.dbsession,
                    offset=offset,
                    limit=limit,
                    active_only=True
                )
                if not active_domains:
                    # no domains
                    break
                for domain in active_domains:
                    # favor the multi:
                    total_primed['domain'] += 1
                    is_primed = lib_utils.redis_prime_logic__style_2_domain(redis_client, dbDomain, redis_timeouts)

                if len(active_domains) < limit:
                    # no more
                    break
                offset += limit

        dbEvent = lib_db.create__SslOperationsEvent(self.request.dbsession,
                                                    SslOperationsEventType.redis_prime,
                                                    {'v': 1,
                                                     'prime_style': prime_style,
                                                     'total_primed': total_primed,
                                                     }
                                                    )
        if self.request.matched_route.name == 'admin:operations:redis:prime.json':
            return {'result': 'success',
                    'operations_event': {'id': dbEvent.id,
                                         'total_primed': dbEvent.event_payload_json['total_primed'],
                                         },
                    }
        return HTTPFound('%s/operations/redis?operation=redis_prime&result=success&event.id=%s' % (self.request.registry.settings['admin_prefix'], dbEvent.id))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _ensure_nginx(self):
        if not self.request.registry.settings['enable_nginx']:
            raise HTTPFound('%s?error=no_nginx' % self.request.registry.settings['admin_prefix'])

    @view_config(route_name='admin:operations:nginx', renderer='/admin/operations-nginx.mako')
    @view_config(route_name='admin:operations:nginx_paginated', renderer='/admin/operations-nginx.mako')
    def admin_nginx(self):
        self._ensure_nginx()

        _items_per_page = 25
        _event_type_ids = (SslOperationsEventType.nginx_cache_expire, SslOperationsEventType.nginx_cache_flush)
        items_count = lib_db.get__SslOperationsEvent__count(self.request.dbsession, event_type_ids=_event_type_ids)
        (pager, offset) = self._paginate(items_count, url_template='%s/operations/nginx/log/{0}' % self.request.registry.settings['admin_prefix'], items_per_page=_items_per_page)
        items_paged = lib_db.get__SslOperationsEvent__paginated(self.request.dbsession, event_type_ids=_event_type_ids,
                                                                limit=_items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslOperationsEvents__count': items_count,
                'SslOperationsEvents': items_paged,
                'pager': pager,
                'enable_nginx': self.request.registry.settings['enable_nginx'],
                }

    @view_config(route_name='admin:operations:nginx:cache_flush', renderer=None)
    @view_config(route_name='admin:operations:nginx:cache_flush.json', renderer='json')
    def admin_nginx_cache_flush(self):
        self._ensure_nginx()
        success, dbEvent = lib_utils.nginx_flush_cache(self.request, self.request.dbsession)
        if self.request.matched_route.name == 'admin:operations:nginx:cache_flush.json':
            return {'result': 'success',
                    'operations_event': {'id': dbEvent.id,
                                         },
                    }
        return HTTPFound('%s/operations/nginx?operation=nginx_cache_flush&result=success&event.id=%s' % (self.request.registry.settings['admin_prefix'], dbEvent.id))
