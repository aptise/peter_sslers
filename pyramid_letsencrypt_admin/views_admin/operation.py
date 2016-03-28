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

        return HTTPFound('/.well-known/admin/operations/log')

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:log', renderer='/admin/operations-log.mako')
    @view_config(route_name='admin:operations:log_paginated', renderer='/admin/operations-log.mako')
    def operations_log(self):
        _items_per_page = 10
        items_count = lib_db.get__LetsencryptOperationsEvent__count(DBSession)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/operations/log/{0}', items_per_page=_items_per_page)
        items_paged = lib_db.get__LetsencryptOperationsEvent__paginated(DBSession, limit=_items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptOperationsEvents__count': items_count,
                'LetsencryptOperationsEvents': items_paged,
                'pager': pager,
                'enable_redis': self.request.registry.settings['enable_redis'],
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:operations:ca_certificate_probes', renderer='/admin/operations-ca_certificate_probes.mako')
    @view_config(route_name='admin:operations:ca_certificate_probes_paginated', renderer='/admin/operations-ca_certificate_probes.mako')
    def ca_certificate_probes(self):
        items_count = lib_db.get__LetsencryptOperationsEvent__certificate_probe__count(DBSession)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/operations/ca_certificate_probes/{0}')
        items_paged = lib_db.get__LetsencryptOperationsEvent__certificate_probe__paginated(DBSession, limit=items_per_page, offset=offset)
        return {'project': 'pyramid_letsencrypt_admin',
                'LetsencryptOperationsEvents_count': items_count,
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

        prime_style = self.request.registry.settings['redis.prime_style']
        if prime_style != '1':
            raise ValueError("invalid `redis.prime_style`")

        redis_url = self.request.registry.settings['redis.url']
        redis_options = {}
        redis_client = lib_utils.get_default_connection(self.request, redis_url, **redis_options)

        timeouts = {'cacert': None,
                    'cert': None,
                    'pkey': None,
                    'domain': None,
                    }
        for _t in timeouts.keys():
            key_ini = 'redis.timeout.%s' % _t
            if key_ini in self.request.registry.settings:
                timeouts[_t] = int(self.request.registry.settings[key_ini])

        if prime_style == '1':
            """
            first priming style
            --
            our data should look like this
                r['d:foo.example.com'] = ('c:1', 'p:1', 'i:99')  # certid, pkeyid, chainid
                r['d:foo2.example.com'] = ('c:2', 'p:1', 'i:99')  # certid, pkeyid, chainid
                r['c:1'] = CERT.PEM  # (c)ert
                r['c:2'] = CERT.PEM
                r['p:2'] = PKEY.PEM  # (p)rivate
                r['i:99'] = CACERT.PEM  # (i)ntermediate cert

            to assemble the data for `foo.example.com`:

                * (c, p, i) = r.get('d:foo.example.com')
                ** returns ('c:1', 'p:1', 'i:99')
                * cert = r.get('c:1')
                * pkey = r.get('p:1')
                * chain = r.get('i:99')
                * fullchain = cert + "\n" + chain
            """
            # prime the CACertificates that are active
            offset = 0
            limit = 100
            while True:
                active_certs = lib_db.get__LetsencryptCACertificate__paginated(
                    DBSession,
                    offset=offset,
                    limit=limit,
                    active_only=True
                )
                if not active_certs:
                    # no certs
                    break
                for cert in active_certs:
                    key_redis = "i:%s" % cert.id
                    redis_client.set(key_redis, cert.cert_pem, timeouts['cacert'])
                if len(active_certs) < limit:
                    # no more
                    break
                offset += limit

            # prime PrivateKeys that are active
            offset = 0
            limit = 100
            while True:
                active_keys = lib_db.get__LetsencryptPrivateKey__paginated(
                    DBSession,
                    offset=offset,
                    limit=limit,
                    active_only=True
                )
                if not active_keys:
                    # no keys
                    break
                for key in active_keys:
                    key_redis = "p:%s" % key.id
                    redis_client.set(key_redis, key.key_pem, timeouts['pkey'])
                if len(active_keys) < limit:
                    # no more
                    break
                offset += limit

            # prime Domains
            offset = 0
            limit = 100
            while True:
                active_domains = lib_db.get__LetsencryptDomain__paginated(
                    DBSession,
                    offset=offset,
                    limit=limit,
                    active_only=True
                )
                if not active_domains:
                    # no domains
                    break
                for domain in active_domains:
                    # favor the multi:
                    cert = None
                    if domain.letsencrypt_server_certificate_id__latest_multi:
                        cert = domain.latest_certificate_multi
                    elif domain.letsencrypt_server_certificate_id__latest_single:
                        cert = domain.latest_certificate_single
                    else:
                        raise ValueError("this domain is not active: `%s`" % domain.domain_name)

                    # first do the domain
                    key_redis = "d:%s" % domain.domain_name
                    value_redis = ('c:%s' % cert.id,
                                   'p:%s' % cert.letsencrypt_private_key_id__signed_by,
                                   'i:%s' % cert.letsencrypt_ca_certificate_id__upchain,
                                   )
                    redis_client.set(key_redis, value_redis, timeouts['domain'])

                    # then do the cert
                    key_redis = "c:%s" % cert.id
                    # only send over the wire if it doesn't exist
                    if not redis_client.exists(key_redis):
                        redis_client.set(key_redis, cert.cert_pem, timeouts['cert'])

                if len(active_domains) < limit:
                    # no more
                    break
                offset += limit

            dbEvent = lib_db.create__LetsencryptOperationsEvent(DBSession,
                                                                LetsencryptOperationsEventType.redis_prime,
                                                                {'v': 1,
                                                                 }
                                                                )

        return HTTPFound('/.well-known/admin/operations/redis?operation=prime&result=success')
