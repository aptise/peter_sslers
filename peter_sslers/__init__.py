from pyramid.config import Configurator
from pyramid.tweens import EXCVIEW
from pyramid.events import BeforeRender
from sqlalchemy import engine_from_config

import logging
import datetime

from .lib import acme
from .lib import cert_utils
from .lib.config_utils import *
from .lib import utils

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def add_renderer_globals(event):
    """sticks the admin_prefix into the renderer's topline namespace"""
    event['admin_prefix'] = event['request'].registry.settings["admin_prefix"]
    event['admin_server'] = event['request'].admin_server


def db_cleanup__tween_factory(handler, registry):
    def db_cleanup__tween(request):
        try:
            if request.environ.get('paste.command_request', None):
                # turn off logging
                # logging.Logger.manager.loggerDict
                logging.basicConfig(level=logging.WARNING)
                for l in [l.strip() for l in "peter_sslers, sqlalchemy, requests, sqlalchemy.engine.base.Engine".split(',')]:
                    logging.getLogger(l).setLevel(logging.WARNING)
                    logging.getLogger(l).propagate = False
            response = handler(request)
            return response
        finally:
            request.dbsession.close()
    return db_cleanup__tween


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.include('pyramid_mako')
    # config.add_static_view('static', 'static', cache_max_age=3600)

    # Parse settings

    # do this before setting routes!
    admin_prefix = settings.get("admin_prefix", None)
    if admin_prefix is None:
        config.registry.settings["admin_prefix"] = "/.well-known/admin"

    # update the module data based on settings
    if 'openssl_path' in settings:
        cert_utils.openssl_path = settings["openssl_path"]
    if 'openssl_path_conf' in settings:
        cert_utils.openssl_path_conf = settings["openssl_path_conf"]
    if 'certificate_authority' in settings:
        acme.CERTIFICATE_AUTHORITY = settings["certificate_authority"]

    # will we redirect on error?
    set_bool_setting(config.registry.settings, 'exception_redirect')

    # this is an int
    set_int_setting(config.registry.settings, 'expiring_days', default=30)

    # will we redirect on error?
    _enable_redis = set_bool_setting(config.registry.settings, 'enable_redis')
    if _enable_redis:
        # try to load, otherwise error out
        import redis  # noqa
        if 'redis.prime_style' not in settings:
            raise ValueError("No `redis.prime_style` is configured")
        if settings['redis.prime_style'] not in ('1', '2'):
            raise ValueError("No `redis.prime_style` must be one of: (`1`, `2`)")

    # disable the ssl warning from requests?
    _disable_ssl_warning = set_bool_setting(config.registry.settings, 'requests.disable_ssl_warning')
    if _disable_ssl_warning:
        import requests.packages.urllib3
        requests.packages.urllib3.disable_warnings()

    _enable_nginx = False
    if 'nginx.reset_path' not in config.registry.settings:
        config.registry.settings['nginx.reset_path'] = '/.peter_sslers/nginx/shared_cache/expire'
    if 'nginx.status_path' not in config.registry.settings:
        config.registry.settings['nginx.status_path'] = '/.peter_sslers/nginx/shared_cache/status'
    if 'nginx.userpass' not in config.registry.settings:
        config.registry.settings['nginx.userpass'] = None
    if 'nginx.servers_pool' in config.registry.settings:
        config.registry.settings['nginx.servers_pool'] = [i.strip() for i in config.registry.settings['nginx.servers_pool'].split(',')]
        _enable_nginx = True
        set_bool_setting(config.registry.settings, 'nginx.servers_pool_allow_invalid')
    config.registry.settings['enable_nginx'] = _enable_nginx

    # let's extend the request too!
    config.add_request_method(lambda request: request.environ['HTTP_HOST'].split(':')[0], 'active_domain_name', reify=True)
    config.add_request_method(lambda request: request.registry.settings.get('admin_server', None) or request.environ['HTTP_HOST'], 'admin_server', reify=True)
    config.add_request_method(lambda request: datetime.datetime.utcnow(), 'a_timestamp', reify=True)
    config.add_request_method(lambda request: lib.utils.ApiContext(timestamp=request.a_timestamp, dbSession=request.dbsession), 'api_context', reify=True)

    # don't scan 'everything', only what is enabled
    # config.scan()

    config.add_tween('.db_cleanup__tween_factory', over=EXCVIEW)
    config.add_subscriber(add_renderer_globals, BeforeRender)

    # handle this before including the routes
    enable_views_admin = set_bool_setting(config.registry.settings, 'enable_views_admin')
    enable_views_public = set_bool_setting(config.registry.settings, 'enable_views_public')
    config.include(".routes")
    config.include(".models")

    return config.make_wsgi_app()
