# stdlib
import hashlib
import json
import logging
import re
import warnings

# pypi
try:
    from redis import Redis
except ImportError:
    pass
import requests

from .. import lib
from .. import models

# ==============================================================================


RE_domain = re.compile('^(?:[\w\-]+\.)+[\w]{2,5}$')


# ==============================================================================


class ApiContext(object):
    """
    A context object
    API Calls can rely on this object to assist in logging.

    This implements an interface that guarantees several properties.  Substitutes may be used-

    :timestamp: `datetime.datetime.utcnow()`
    :dbSession: - sqlalchemy `session` object
    :dbSessionLogger: - sqlalchemy `session` object with autocommit
    :dbOperationsEvent: - a topline SslOperationsEvent object for this request, if any
    """

    dbOperationsEvent = None
    dbSession = None
    dbSessionLogger = None
    timestamp = None

    def __init__(self, dbOperationsEvent=None, dbSession=None, dbSessionLogger=None, timestamp=None, ):
        self.dbOperationsEvent = dbOperationsEvent
        self.dbSession = dbSession
        self.dbSessionLogger = dbSessionLogger
        self.timestamp = timestamp


# ------------------------------------------------------------------------------


def new_event_payload_dict():
    return {'v': 1,
            }


# ------------------------------------------------------------------------------


def validate_domains(domain_names):
    for d in domain_names:
        if not RE_domain.match(d):
            raise ValueError("invalid name: `%s`", d)
    return True


def domains_from_list(domain_names):
    domain_names = [d for d in [d.strip().lower() for d in domain_names] if d]
    # make the list unique
    domain_names = list(set(domain_names))
    # validate the list
    validate_domains(domain_names)
    return domain_names


def domains_from_string(text):
    # generate list
    domain_names = text.split(',')
    return domains_from_list(domain_names)


def md5_text(text):
    return hashlib.md5(text).hexdigest()


def redis_default_connection(request,
                             url=None,
                             redis_client=Redis,
                             **redis_options):
    """
    # largely from `pyramid_redis_sessions/connection.py`

    Default Redis connection handler. Once a connection is established it is
    saved in `request.registry`.

    Parameters:

    ``request``
    The current pyramid request object

    ``url``
    An optional connection string that will be passed straight to
    `StrictRedis.from_url`. The connection string should be in the form:
        redis://username:password@localhost:6379/0

    ``settings``
    A dict of keyword args to be passed straight to `StrictRedis`

    Returns:

    An instance of `StrictRedis`
    """
    # attempt to get an existing connection from the registry
    redis = getattr(request.registry, '_redis_connection', None)

    # if we found an active connection, return it
    if redis is not None:
        return redis

    # otherwise create a new connection
    if url is not None:
        # remove defaults to avoid duplicating settings in the `url`
        redis_options.pop('password', None)
        redis_options.pop('host', None)
        redis_options.pop('port', None)
        redis_options.pop('db', None)
        # the StrictRedis.from_url option no longer takes a socket
        # argument. instead, sockets should be encoded in the URL if
        # used. example:
        #     unix://[:password]@/path/to/socket.sock?db=0
        redis_options.pop('unix_socket_path', None)
        # connection pools are also no longer a valid option for
        # loading via URL
        redis_options.pop('connection_pool', None)
        redis = redis_client.from_url(url, **redis_options)
    else:
        redis = redis_client(**redis_options)

    # save the new connection in the registry
    setattr(request.registry, '_redis_connection', redis)

    return redis


def new_nginx_session(request):
    sess = requests.Session()
    _auth = request.registry.settings.get('nginx.userpass')
    if _auth:
        sess.auth = tuple(_auth.split(':'))
    servers_allow_invalid = request.registry.settings.get('nginx.servers_pool_allow_invalid')
    if servers_allow_invalid:
        sess.verify = False
    return sess


def nginx_flush_cache(request, ctx):
    _reset_path = request.registry.settings['nginx.reset_path']
    timeout = request.registry.settings['nginx.timeout']
    sess = new_nginx_session(request)
    rval = {'errors': [], 'success': [], 'servers': {}, }
    for _server in request.registry.settings['nginx.servers_pool']:
        status = None
        try:
            reset_url = _server + _reset_path + '/all'
            response = sess.get(reset_url, timeout=timeout, verify=False)
            if response.status_code == 200:
                response_json = json.loads(response.content)
                status = response_json
                if response_json['result'] != 'success':
                    rval['errors'].append(_server)
                else:
                    rval['success'].append(_server)
            else:
                rval['errors'].append(_server)
                status = {'status': 'error',
                          'error': 'response',
                          'response': {'status_code': response.status_code,
                                       'text': response.content,
                                       }
                          }
        except Exception as e:
            rval['errors'].append(_server)
            status = {'status': 'error',
                      'error': 'Exception',
                      'Exception': "%s" % e.message,  # this could be an object
                      }
        rval['servers'][_server] = status
    dbEvent = lib.db.logger.log__SslOperationsEvent(ctx,
                                                    models.SslOperationsEventType.from_string('operations__nginx_cache_flush'),
                                                    )
    return True, dbEvent, rval


def nginx_status(request, ctx):
    """returns the status document for each server"""
    status_path = request.registry.settings['nginx.status_path']
    timeout = request.registry.settings['nginx.timeout']
    sess = new_nginx_session(request)
    rval = {'errors': [], 'success': [], 'servers': {}, }
    for _server in request.registry.settings['nginx.servers_pool']:
        status = None
        try:
            status_url = _server + status_path
            response = sess.get(status_url, timeout=timeout, verify=False)
            if response.status_code == 200:
                response_json = json.loads(response.content)
                status = response_json
                rval['success'].append(_server)
            else:
                rval['errors'].append(_server)
                status = {'status': 'error',
                          'error': 'response',
                          'response': {'status_code': response.status_code,
                                       'text': response.content,
                                       }
                          }
        except Exception as e:
            rval['errors'].append(_server)
            status = {'status': 'error',
                      'error': 'Exception',
                      'Exception': "%s" % e.message,  # this could be an object
                      }
        rval['servers'][_server] = status
    return rval


def nginx_expire_cache(request, ctx, dbDomains=None):
    if not dbDomains:
        raise ValueError("no domains submitted")
    domain_ids = {'success': set([]),
                  'failure': set([]),
                  }
    _reset_path = request.registry.settings['nginx.reset_path']
    timeout = request.registry.settings['nginx.timeout']
    sess = new_nginx_session(request)
    for _server in request.registry.settings['nginx.servers_pool']:
        for domain in dbDomains:
            try:
                reset_url = _server + _reset_path + '/domain/%s' % domain.domain_name
                response = sess.get(reset_url, timeout=timeout, verify=False)
                if response.status_code == 200:
                    response_json = json.loads(response.content)
                    if response_json['result'] == 'success':
                        domain_ids['success'].add(domain.id)
                    else:
                        # log the url?
                        domain_ids['failure'].add(domain.id)
                else:
                    # log the url?
                    domain_ids['failure'].add(domain.id)
            except Exception as e:
                # log the url?
                domain_ids['failure'].add(domain.id)

    event_payload_dict = new_event_payload_dict()
    event_payload_dict['ssl_domain_ids'] = {'success': list(domain_ids['success']),
                                            'failure': list(domain_ids['failure']),
                                            }
    dbEvent = lib.db.logger.log__SslOperationsEvent(ctx,
                                                    models.SslOperationsEventType.from_string('operations__nginx_cache_expire'),
                                                    event_payload_dict,
                                                    )
    return True, dbEvent


def redis_connection_from_registry(request):
    redis_url = request.registry.settings['redis.url']
    redis_options = {}
    redis_client = redis_default_connection(request, redis_url, **redis_options)
    return redis_client


def redis_prime_style(request):
    prime_style = request.registry.settings['redis.prime_style']
    if prime_style not in ('1', '2'):
        return False
    return prime_style


def redis_timeouts_from_registry(request):
    timeouts = {'cacert': None,
                'cert': None,
                'pkey': None,
                'domain': None,
                }
    for _t in timeouts.keys():
        key_ini = 'redis.timeout.%s' % _t
        if key_ini in request.registry.settings:
            timeouts[_t] = int(request.registry.settings[key_ini])
    return timeouts


def prime_redis_domain(request, dbDomain):
    """prime the domain for redis
       return True if primed
       return False if not
    """
    if not request.registry.settings['enable_redis']:
        # don't error out here
        return False

    prime_style = redis_prime_style(request)
    if not prime_style:
        return False
    redis_client = redis_connection_from_registry(request)
    redis_timeouts = redis_timeouts_from_registry(request)

    try:
        if prime_style == '1':
            try:
                dbServerCertificate = redis_prime_logic__style_1_Domain(redis_client, dbDomain, redis_timeouts)
                redis_prime_logic__style_1_PrivateKey(redis_client, dbServerCertificate.private_key, redis_timeouts)
                redis_prime_logic__style_1_CACertificate(redis_client, dbServerCertificate.certificate_upchain, redis_timeouts)
            except Exception as e:
                warnings.warn(e.message)
                return False
        elif prime_style == '2':
            is_primed = redis_prime_logic__style_2_domain(redis_client, dbDomain, redis_timeouts)

    except Exception as e:
        raise
        return False

    return True


def redis_prime_logic__style_1_Domain(redis_client, dbDomain, redis_timeouts):
    """
    primes the domain, returns the certificate
    r['d:foo.example.com'] = {'c': '1', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['d:foo2.example.com'] = {'c': '2', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['c1'] = CERT.PEM  # (c)ert
    r['c2'] = CERT.PEM
    """
    dbServerCertificate = None
    if dbDomain.ssl_server_certificate_id__latest_multi:
        dbServerCertificate = dbDomain.server_certificate__latest_multi
    elif dbDomain.ssl_server_certificate_id__latest_single:
        dbServerCertificate = dbDomain.server_certificate__latest_single
    else:
        raise ValueError("this domain does not have a certificate: `%s`" % dbDomain.domain_name)

    # first do the domain
    key_redis = "d:%s" % dbDomain.domain_name
    value_redis = {'c': '%s' % dbServerCertificate.id,
                   'p': '%s' % dbServerCertificate.ssl_private_key_id__signed_by,
                   'i': '%s' % dbServerCertificate.ssl_ca_certificate_id__upchain,
                   }
    redis_client.hmset(key_redis, value_redis)

    # then do the cert
    key_redis = "c%s" % dbServerCertificate.id
    # only send over the wire if it doesn't exist
    if not redis_client.exists(key_redis):
        value_redis = dbServerCertificate.cert_pem
        redis_client.set(key_redis, value_redis, redis_timeouts['cert'])

    return dbServerCertificate


def redis_prime_logic__style_1_PrivateKey(redis_client, dbPrivateKey, redis_timeouts):
    """
    r['p2'] = PKEY.PEM  # (p)rivate
    """
    key_redis = "p%s" % dbPrivateKey.id
    redis_client.set(key_redis, dbPrivateKey.key_pem, redis_timeouts['pkey'])
    return True


def redis_prime_logic__style_1_CACertificate(redis_client, dbCACertificate, redis_timeouts):
    """
    r['i99'] = CACERT.PEM  # (i)ntermediate cert
    """
    key_redis = "i%s" % dbCACertificate.id
    redis_client.set(key_redis, dbCACertificate.cert_pem, redis_timeouts['cacert'])
    return True


def redis_prime_logic__style_2_domain(redis_client, dbDomain, redis_timeouts):
    """returns the certificate
    """
    dbServerCertificate = None
    if dbDomain.ssl_server_certificate_id__latest_multi:
        dbServerCertificate = dbDomain.server_certificate__latest_multi
    elif dbDomain.ssl_server_certificate_id__latest_single:
        dbServerCertificate = dbDomain.server_certificate__latest_single
    else:
        raise ValueError("this domain is not active: `%s`" % dbDomain.domain_name)

    # the domain will hold the fullchain and private key
    key_redis = "%s" % dbDomain.domain_name
    value_redis = {'f': '%s' % dbServerCertificate.cert_fullchain_pem,
                   'p': '%s' % dbServerCertificate.private_key.key_pem,
                   }
    redis_client.hmset(key_redis, value_redis)
    return dbServerCertificate
