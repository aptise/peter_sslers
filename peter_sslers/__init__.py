from pyramid.config import Configurator
from sqlalchemy import engine_from_config

from .models import (DBSession,
                     Base,
                     )

from .lib import acme


def set_bool_setting(settings, key):
    # make sure to pass in config.registry.settings
    _bool = False
    if (key in settings) and (settings[key].lower() in ('1', 'true', )):
        _bool = True
    settings[key] = _bool
    return _bool


def set_int_setting(settings, key, default=None):
    # make sure to pass in config.registry.settings
    value = default
    if key in settings:
        value = int(settings[key])
    else:
        value = int(default)
    settings[key] = value
    return value

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    engine = engine_from_config(settings, 'sqlalchemy.')
    DBSession.configure(bind=engine)
    Base.metadata.bind = engine
    config = Configurator(settings=settings)
    config.include('pyramid_mako')
    # config.add_static_view('static', 'static', cache_max_age=3600)

    enable_views_admin = set_bool_setting(config.registry.settings, 'enable_views_admin')
    enable_views_public = set_bool_setting(config.registry.settings, 'enable_views_public')

    # public
    if enable_views_public:
        # public url
        config.add_route('public_challenge', '/.well-known/acme-challenge/{challenge}')
        config.add_route('public_whoami', '/.well-known/whoami')

        config.scan("peter_sslers.views_public")

    # admin
    if enable_views_admin:

        config.add_static_view('/.well-known/admin/static', 'static', cache_max_age=3600)

        config.add_route('admin', '/.well-known/admin')
        config.add_route('admin_whoami', '/.well-known/admin/whoami')
        config.add_route('admin:help', '/.well-known/admin/help')

        config.add_route('admin:domains', '/.well-known/admin/domains')
        config.add_route('admin:domains_paginated', '/.well-known/admin/domains/{page:\d+}')
        config.add_route('admin:domains:expiring', '/.well-known/admin/domains/expiring')
        config.add_route('admin:domains:expiring_paginated', '/.well-known/admin/domains/expiring/{page:\d+}')

        config.add_route('admin:domain:focus', '/.well-known/admin/domain/{domain_identifier}')
        config.add_route('admin:domain:focus_name', '/.well-known/admin/domain/{domain_identifier}')
        config.add_route('admin:domain:focus:config_json', '/.well-known/admin/domain/{domain_identifier}/config.json')
        config.add_route('admin:domain:focus:nginx_cache_expire', '/.well-known/admin/domain/{domain_identifier}/nginx_cache_expire')
        config.add_route('admin:domain:focus:nginx_cache_expire:json', '/.well-known/admin/domain/{domain_identifier}/nginx_cache_expire.json')
        config.add_route('admin:domain:focus:certificates', '/.well-known/admin/domain/{domain_identifier}/certificates')
        config.add_route('admin:domain:focus:certificates_paginated', '/.well-known/admin/domain/{domain_identifier}/certificates/{page:\d+}')
        config.add_route('admin:domain:focus:certificate_requests', '/.well-known/admin/domain/{domain_identifier}/certificate_requests')
        config.add_route('admin:domain:focus:certificate_requests_paginated', '/.well-known/admin/domain/{domain_identifier}/certificate_requests/{page:\d+}')

        config.add_route('admin:search', '/.well-known/admin/search')

        config.add_route('admin:certificates', '/.well-known/admin/certificates')
        config.add_route('admin:certificates_paginated', '/.well-known/admin/certificates/{page:\d+}')
        config.add_route('admin:certificates:expiring', '/.well-known/admin/certificates/expiring')
        config.add_route('admin:certificates:expiring_paginated', '/.well-known/admin/certificates/expiring/{page:\d+}')

        config.add_route('admin:certificate:focus', '/.well-known/admin/certificate/{id:\d+}')
        config.add_route('admin:certificate:focus:config_json', '/.well-known/admin/certificate/{id:\d+}/config.json')
        config.add_route('admin:certificate:focus:chain:raw', '/.well-known/admin/certificate/{id:\d+}/chain.{format:(cer|crt|der|pem|pem.txt)}')
        config.add_route('admin:certificate:focus:fullchain:raw', '/.well-known/admin/certificate/{id:\d+}/fullchain.{format:(pem|pem.txt)}')
        config.add_route('admin:certificate:focus:privatekey:raw', '/.well-known/admin/certificate/{id:\d+}/privkey.{format:(key|pem|pem.txt)}')
        config.add_route('admin:certificate:focus:cert:raw', '/.well-known/admin/certificate/{id:\d+}/cert.{format:(crt|pem|pem.txt)}')
        config.add_route('admin:certificate:focus:nginx_cache_expire', '/.well-known/admin/certificate/{id:\d}/nginx_cache_expire')
        config.add_route('admin:certificate:focus:nginx_cache_expire:json', '/.well-known/admin/certificate/{id:\d}/nginx_cache_expire.json')
        config.add_route('admin:certificate:upload', '/.well-known/admin/certificate/upload')
        config.add_route('admin:certificate:upload:json', '/.well-known/admin/certificate/upload.json')

        config.add_route('admin:certificate_requests', '/.well-known/admin/certificate_requests')
        config.add_route('admin:certificate_requests_paginated', '/.well-known/admin/certificate_requests/{page:\d+}')
        config.add_route('admin:certificate_request:focus', '/.well-known/admin/certificate_request/{id:\d+}')
        config.add_route('admin:certificate_request:focus:raw', '/.well-known/admin/certificate_request/{id:\d+}/csr.{format:(pem|pem.txt|csr)}')
        config.add_route('admin:certificate_request:process', '/.well-known/admin/certificate_request/{id:\d+}/process')
        config.add_route('admin:certificate_request:deactivate', '/.well-known/admin/certificate_request/{id:\d+}/deactivate')
        config.add_route('admin:certificate_request:process:domain', '/.well-known/admin/certificate_request/{id:\d+}/process/domain/{domain_id:\d+}')

        # two types of CR handling
        config.add_route('admin:certificate_request:new:flow', '/.well-known/admin/certificate_request/new-flow')
        config.add_route('admin:certificate_request:new:full', '/.well-known/admin/certificate_request/new-full')

        # these are the recordkeeping
        config.add_route('admin:account_keys', '/.well-known/admin/account_keys')
        config.add_route('admin:account_keys_paginated', '/.well-known/admin/account_keys/{page:\d+}')
        config.add_route('admin:account_key:focus', '/.well-known/admin/account_key/{id:\d+}')
        config.add_route('admin:account_key:focus:raw', '/.well-known/admin/account_key/{id:\d+}/key.{format:(key|pem|pem.txt)}')
        config.add_route('admin:account_key:focus:certificate_requests', '/.well-known/admin/account_key/{id:\d+}/certificate_requests')
        config.add_route('admin:account_key:focus:certificate_requests_paginated', '/.well-known/admin/account_key/{id:\d+}/certificate_requests/{page:\d+}')
        config.add_route('admin:account_key:focus:certificates', '/.well-known/admin/account_key/{id:\d+}/certificates')
        config.add_route('admin:account_key:focus:certificates_paginated', '/.well-known/admin/account_key/{id:\d+}/certificates/{page:\d+}')
        config.add_route('admin:account_key:new', '/.well-known/admin/account_key/new')

        config.add_route('admin:private_keys', '/.well-known/admin/private_keys')
        config.add_route('admin:private_keys_paginated', '/.well-known/admin/private_keys/{page:\d+}')
        config.add_route('admin:private_key:focus', '/.well-known/admin/private_key/{id:\d+}')
        config.add_route('admin:private_key:focus:raw', '/.well-known/admin/private_key/{id:\d+}/key.{format:(key|pem|pem.txt)}')
        config.add_route('admin:private_key:focus:certificates', '/.well-known/admin/private_key/{id:\d+}/certificates')
        config.add_route('admin:private_key:focus:certificates_paginated', '/.well-known/admin/private_key/{id:\d+}/certificates/{page:\d+}')
        config.add_route('admin:private_key:focus:certificate_requests', '/.well-known/admin/private_key/{id:\d+}/certificate_requests')
        config.add_route('admin:private_key:focus:certificate_requests_paginated', '/.well-known/admin/private_key/{id:\d+}/certificate_requests/{page:\d+}')
        config.add_route('admin:private_key:new', '/.well-known/admin/private_key/new')

        config.add_route('admin:ca_certificates', '/.well-known/admin/ca_certificates')
        config.add_route('admin:ca_certificates_paginated', '/.well-known/admin/ca_certificates/{page:\d+}')
        config.add_route('admin:ca_certificate:focus', '/.well-known/admin/ca_certificate/{id:\d+}')
        config.add_route('admin:ca_certificate:focus:raw', '/.well-known/admin/ca_certificate/{id:\d+}/chain.{format:(cer|crt|der|pem|pem.txt)}')
        config.add_route('admin:ca_certificate:focus:signed_certificates', '/.well-known/admin/ca_certificate/{id:\d+}/signed_certificates')
        config.add_route('admin:ca_certificate:focus:signed_certificates_paginated', '/.well-known/admin/ca_certificate/{id:\d+}/signed_certificates/{page:\d}')

        config.add_route('admin:ca_certificate:upload', '/.well-known/admin/ca_certificate/upload')
        config.add_route('admin:ca_certificate:upload:json', '/.well-known/admin/ca_certificate/upload.json')

        config.add_route('admin:ca_certificate:upload_bundle', '/.well-known/admin/ca_certificate/upload_bundle')
        config.add_route('admin:ca_certificate:upload_bundle:json', '/.well-known/admin/ca_certificate/upload_bundle.json')

        # sync events
        config.add_route('admin:operations', '/.well-known/admin/operations')

        config.add_route('admin:operations:log', '/.well-known/admin/operations/log')
        config.add_route('admin:operations:log_paginated', '/.well-known/admin/operations/log/{page:\d}')

        config.add_route('admin:operations:ca_certificate_probes', '/.well-known/admin/operations/ca_certificate_probes')
        config.add_route('admin:operations:ca_certificate_probes_paginated', '/.well-admin/operations/ca_certificate_probes/{page:\d}')

        config.add_route('admin:operations:ca_certificate_probes:probe', '/.well-known/admin/operations/ca_certificate_probes/probe')
        config.add_route('admin:operations:ca_certificate_probes:probe:json', '/.well-known/admin/operations/ca_certificate_probes/probe.json')

        config.add_route('admin:operations:update_recents', '/.well-known/admin/operations/update_recents')
        config.add_route('admin:operations:update_recents:json', '/.well-known/admin/operations/update_recents.json')

        config.add_route('admin:operations:deactivate_expired', '/.well-known/admin/operations/deactivate_expired')
        config.add_route('admin:operations:deactivate_expired:json', '/.well-known/admin/operations/deactivate_expired.json')

        config.add_route('admin:operations:nginx', '/.well-known/admin/operations/nginx')
        config.add_route('admin:operations:nginx_paginated', '/.well-known/admin/operations/nginx/{page:\d}')
        config.add_route('admin:operations:nginx:cache_flush', '/.well-known/admin/operations/nginx/cache_flush')
        config.add_route('admin:operations:nginx:cache_flush:json', '/.well-known/admin/operations/nginx/cache_flush.json')

        config.add_route('admin:operations:redis', '/.well-known/admin/operations/redis')
        config.add_route('admin:operations:redis_paginated', '/.well-known/admin/operations/redis/{page:\d}')
        config.add_route('admin:operations:redis:prime', '/.well-known/admin/operations/redis/prime')
        config.add_route('admin:operations:redis:prime:json', '/.well-known/admin/operations/redis/prime.json')

        config.scan("peter_sslers.views_admin")

    # Parse settings

    # update the module data based on settings
    if 'openssl_path' in settings:
        acme.openssl_path = settings["openssl_path"]
    if 'openssl_path_conf' in settings:
        acme.openssl_path_conf = settings["openssl_path_conf"]
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
        _enable_nginx =True
    if 'nginx.reset_path' not in config.registry.settings:
        config.registry.settings['nginx.reset_path'] = '/ngxadmin/shared_cache/expire'
    config.registry.settings['enable_nginx'] = _enable_nginx

    # let's extend the request too!
    config.add_request_method(lambda request: request.environ['HTTP_HOST'].split(':')[0], 'active_domain_name', reify=True)

    # don't scan 'everything', only what is enabled
    # config.scan()

    return config.make_wsgi_app()
