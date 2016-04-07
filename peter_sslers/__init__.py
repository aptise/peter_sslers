from pyramid.config import Configurator
from pyramid.tweens import EXCVIEW
from sqlalchemy import engine_from_config

from .lib import acme
from .lib import cert_utils
from .lib.config_utils import *

from pyramid import request

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def db_cleanup__tween_factory(handler, registry):
    def db_cleanup__tween(request):
        try:
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

    # handle this before including the routes
    enable_views_admin = set_bool_setting(config.registry.settings, 'enable_views_admin')
    enable_views_public = set_bool_setting(config.registry.settings, 'enable_views_public')
    config.include("peter_sslers.routes")

    # Parse settings

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

    _enable_nginx = False
    if 'nginx.reset_servers' in config.registry.settings:
        config.registry.settings['nginx.reset_servers'] = [i.strip() for i in config.registry.settings['nginx.reset_servers'].split(',')]
        _enable_nginx = True
    if 'nginx.reset_path' not in config.registry.settings:
        config.registry.settings['nginx.reset_path'] = '/ngxadmin/shared_cache/expire'
    config.registry.settings['enable_nginx'] = _enable_nginx

    # let's extend the request too!
    config.add_request_method(lambda request: request.environ['HTTP_HOST'].split(':')[0], 'active_domain_name', reify=True)

    # don't scan 'everything', only what is enabled
    # config.scan()
    
    config.add_tween('peter_sslers.db_cleanup__tween_factory', over=EXCVIEW)
    

    return config.make_wsgi_app()
