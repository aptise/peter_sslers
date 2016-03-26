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
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdminOperations(Handler):

    @view_config(route_name='admin:operations', renderer=None)
    def operations(self):
        return HTTPFound('/.well-known/admin/operations/log')

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:log', renderer='/admin/operations-log.mako')
    @view_config(route_name='admin:operations:log_paginated', renderer='/admin/operations-log.mako')
    def operations_log(self):
        item_count = lib_db.get__LetsencryptOperationsEvent__count(DBSession)
        (pager, offset) = self._paginate(item_count, url_template='/.well-known/admin/operations/log/{0}')
        items_paged = lib_db.get__LetsencryptOperationsEvent__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptOperationsEvents__count': item_count,
                'LetsencryptOperationsEvents': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:ca_certificate_probes', renderer='/admin/operations-ca_certificate_probes.mako')
    @view_config(route_name='admin:operations:ca_certificate_probes_paginated', renderer='/admin/operations-ca_certificate_probes.mako')
    def ca_certificate_probes(self):
        item_count = lib_db.get__LetsencryptOperationsEvent__certificate_probe__count(DBSession)
        (pager, offset) = self._paginate(item_count, url_template='/.well-known/admin/operations/ca_certificate_probes/{0}')
        items_paged = lib_db.get__LetsencryptOperationsEvent__certificate_probe__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptOperationsEvents_count': item_count,
                'LetsencryptOperationsEvents': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:operations:ca_certificate_probes:probe', renderer=None)
    @view_config(route_name='admin:operations:ca_certificate_probes:probe:json', renderer='json')
    def ca_certificate_probes__probe(self):
        operations_event = lib_db.ca_certificate_probe(DBSession)

        if self.request.matched_route.name == 'admin:operations:ca_certificate_probes:probe:json':
            return {'result': 'success',
                    'operations_event': {'id': operations_event.id,
                                         'is_certificates_discovered': operations_event.event_payload_json['is_certificates_discovered'],
                                         'is_certificates_updated': operations_event.event_payload_json['is_certificates_updated'],
                                         },
                    }
        return HTTPFound("/.well-known/admin/operations/ca_certificate_probes?success=True&event.id=%s" % operations_event.id)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:update_recents', renderer=None)
    @view_config(route_name='admin:operations:update_recents:json', renderer='json')
    def operations_update_recents(self):
        operations_event = lib_db.operations_update_recents(DBSession)

        if self.request.matched_route.name == 'admin:operations:update_recents:json':
            return {'result': 'success',
                    'operations_event': operations_event.id,
                    }

        return HTTPFound("/.well-known/admin/operations/log?success=True&event.id=%s" % operations_event.id)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:deactivate_expired', renderer=None)
    @view_config(route_name='admin:operations:deactivate_expired:json', renderer='json')
    def operations_deactivate_expired(self):
        rval = {}

        # MUST run this first
        operations_event1 = lib_db.operations_update_recents(DBSession)

        operations_event2 = lib_db.operations_deactivate_expired(DBSession)
        count_deactivated_expired = operations_event2.event_payload_json['count_deactivated']
        rval['LetsencryptServerCertificate'] = {'expired': count_deactivated_expired, }

        # deactivate duplicate certificates
        operations_event3 = lib_db.operations_deactivate_duplicates(DBSession,
                                                                    ran_operations_update_recents=True,
                                                                    )
        count_deactivated_duplicated = operations_event2.event_payload_json['count_deactivated']
        rval['LetsencryptServerCertificate']['duplicates.deactivated'] = count_deactivated_duplicated
        DBSession.flush()

        rval['result'] = 'success'
        rval['operations_event'] = operations_event3.id

        if self.request.matched_route.name == 'admin:operations:deactivate_expired:json':
            return rval

        return HTTPFound('/.well-known/admin/operations/log?result=success&event.id=%s' % operations_event3.id)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _ensure_redis(self):
        if not self.request.registry.settings['enable_redis']:
            raise HTTPFound('/.well-known/admin?error=no_redis')

    @view_config(route_name='admin:operations:redis', renderer='/admin/operations-redis.mako')
    def admin_redis(self):
        self._ensure_redis()
        return {'project': 'pyramid_letsencrypt_admin',
                'enable_redis': self.request.registry.settings['enable_redis'],
                }

    @view_config(route_name='admin:operations:redis:prime', renderer=None)
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

        raise HTTPFound('/.well-known/admin/operations/redis?operation=prime&result=success')
