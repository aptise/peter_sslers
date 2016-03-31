# stdlib
import hashlib
import json

# pypi
try:
    from redis import Redis
except ImportError:
    pass
import requests

from .. import lib
from .. import models

# ==============================================================================


def md5_text(text):
    return hashlib.md5(text).hexdigest()


def get_default_connection(request,
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


def nginx_flush_cache(request, dbSession):
    _reset_path = request.registry.settings['nginx.reset_path']
    for _server in request.registry.settings['nginx.reset_servers']:
        reset_url = _server + _reset_path + '/all'
        response = requests.get(reset_url, verify=False)
        if response.status_code == 200:
            response_json = json.loads(response.content)
            if response_json['result'] != 'success':
                raise ValueError("could not flush cache: `%s`" % reset_url)
        else:
            raise ValueError("could not flush cache: `%s`" % reset_url)
    dbEvent = lib.db.create__LetsencryptOperationsEvent(dbSession,
                                                        models.LetsencryptOperationsEventType.nginx_cache_flush,
                                                        {'v': 1,
                                                         }
                                                        )
    return True, dbEvent


def nginx_expire_cache(request, dbSession, dbDomains=None):
    if not dbDomains:
        raise ValueError("no domains submitted")
    domain_ids = {'success': set([]),
                  'failure': set([]),
                  }
    _reset_path = request.registry.settings['nginx.reset_path']
    for _server in request.registry.settings['nginx.reset_servers']:
        for domain in dbDomains:
            reset_url = _server + _reset_path + '/domain/%s' % domain.domain_name
            response = requests.get(reset_url, verify=False)
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

    dbEvent = lib.db.create__LetsencryptOperationsEvent(dbSession,
                                                        models.LetsencryptOperationsEventType.nginx_cache_expire,
                                                        {'v': 1,
                                                         'domain_ids': {'success': list(domain_ids['success']),
                                                                        'failure': list(domain_ids['failure']),
                                                                        }
                                                         }
                                                        )
    return True, dbEvent
