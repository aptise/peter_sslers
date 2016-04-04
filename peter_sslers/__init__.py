from pyramid.config import Configurator
from sqlalchemy import engine_from_config

from .models import (DBSession,
                     Base,
                     )

from .lib import acme
from .lib import cert_utils


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

    # pyramid_route_7 lets us default repeatable macros for our routes
    config.include("pyramid_route_7")
    config.add_route_7_kvpattern('id', '\d+')
    config.add_route_7_kvpattern('page', '\d+')

    # public
    if enable_views_public:
        # public url
        config.add_route_7('public_challenge', '/.well-known/acme-challenge/{challenge}')
        config.add_route_7('public_whoami', '/.well-known/public/whoami')

        config.scan("peter_sslers.views_public")

    # admin
    if enable_views_admin:

        config.add_static_view('/.well-known/admin/static', 'static', cache_max_age=3600)

        config.add_route_7('admin', '/.well-known/admin')
        config.add_route_7('admin_whoami', '/.well-known/admin/whoami')
        config.add_route_7('admin:help', '/.well-known/admin/help')

        config.add_route_7('admin:domains', '/.well-known/admin/domains')
        config.add_route_7('admin:domains_paginated', '/.well-known/admin/domains/{@page}')
        config.add_route_7('admin:domains:expiring', '/.well-known/admin/domains/expiring')
        config.add_route_7('admin:domains:expiring_paginated', '/.well-known/admin/domains/expiring/{@page}')

        config.add_route_7('admin:domain:focus', '/.well-known/admin/domain/{domain_identifier}')
        config.add_route_7('admin:domain:focus_name', '/.well-known/admin/domain/{domain_identifier}')
        config.add_route_7('admin:domain:focus:config_json', '/.well-known/admin/domain/{domain_identifier}/config.json')
        config.add_route_7('admin:domain:focus:nginx_cache_expire', '/.well-known/admin/domain/{domain_identifier}/nginx-cache-expire')
        config.add_route_7('admin:domain:focus:nginx_cache_expire:json', '/.well-known/admin/domain/{domain_identifier}/nginx-cache-expire.json')
        config.add_route_7('admin:domain:focus:certificates', '/.well-known/admin/domain/{domain_identifier}/certificates')
        config.add_route_7('admin:domain:focus:certificates_paginated', '/.well-known/admin/domain/{domain_identifier}/certificates/{@page}')
        config.add_route_7('admin:domain:focus:certificate_requests', '/.well-known/admin/domain/{domain_identifier}/certificate-requests')
        config.add_route_7('admin:domain:focus:certificate_requests_paginated', '/.well-known/admin/domain/{domain_identifier}/certificate-requests/{@page}')
        config.add_route_7('admin:domain:focus:calendar', '/.well-known/admin/domain/{domain_identifier}/calendar')
        config.add_route_7('admin:domain:focus:unique_fqdn_sets', '/.well-known/admin/domain/{domain_identifier}/unique-fqdn-sets')
        config.add_route_7('admin:domain:focus:unique_fqdn_sets_paginated', '/.well-known/admin/domain/{domain_identifier}/unique-fqdn-sets/{@page}')

        config.add_route_7('admin:search', '/.well-known/admin/search')

        config.add_route_7('admin:unique_fqdn_sets', '/.well-known/admin/unique-fqdn-sets')
        config.add_route_7('admin:unique_fqdn_sets_paginated', '/.well-known/admin/unique-fqdn-sets/{@page}')
        config.add_route_7('admin:unique_fqdn_set:focus', '/.well-known/admin/unique-fqdn-set/{@id}')
        config.add_route_7('admin:unique_fqdn_set:focus:calendar', '/.well-known/admin/unique-fqdn-set/{@id}/calendar')
        config.add_route_7('admin:unique_fqdn_set:focus:certificates', '/.well-known/admin/unique-fqdn-set/{@id}/certificates')
        config.add_route_7('admin:unique_fqdn_set:focus:certificates_paginated', '/.well-known/admin/unique-fqdn-set/{@id}/certificates/{@page}')
        config.add_route_7('admin:unique_fqdn_set:focus:certificate_requests', '/.well-known/admin/unique-fqdn-set/{@id}/certificate-requests')
        config.add_route_7('admin:unique_fqdn_set:focus:certificate_requests_paginated', '/.well-known/admin/unique-fqdn-set/{@id}/certificate-requests/{@page}')

        config.add_route_7('admin:certificates', '/.well-known/admin/certificates')
        config.add_route_7('admin:certificates_paginated', '/.well-known/admin/certificates/{@page}')
        config.add_route_7('admin:certificates:expiring', '/.well-known/admin/certificates/expiring')
        config.add_route_7('admin:certificates:expiring_paginated', '/.well-known/admin/certificates/expiring/{@page}')

        config.add_route_7('admin:certificate:focus', '/.well-known/admin/certificate/{@id}')
        config.add_route_7('admin:certificate:focus:config_json', '/.well-known/admin/certificate/{@id}/config.json')
        config.add_route_7('admin:certificate:focus:chain:raw', '/.well-known/admin/certificate/{@id}/chain.{format:(cer|crt|der|pem|pem.txt)}')
        config.add_route_7('admin:certificate:focus:fullchain:raw', '/.well-known/admin/certificate/{@id}/fullchain.{format:(pem|pem.txt)}')
        config.add_route_7('admin:certificate:focus:privatekey:raw', '/.well-known/admin/certificate/{@id}/privkey.{format:(key|pem|pem.txt)}')
        config.add_route_7('admin:certificate:focus:cert:raw', '/.well-known/admin/certificate/{@id}/cert.{format:(crt|pem|pem.txt)}')
        config.add_route_7('admin:certificate:focus:nginx_cache_expire', '/.well-known/admin/certificate/{id:\d}/nginx-cache-expire')
        config.add_route_7('admin:certificate:focus:nginx_cache_expire:json', '/.well-known/admin/certificate/{id:\d}/nginx-cache-expire.json')
        config.add_route_7('admin:certificate:focus:parse.json', '/.well-known/admin/certificate/{@id}/parse.json')
        config.add_route_7('admin:certificate:focus:renew:quick', '/.well-known/admin/certificate/{@id}/renew/quick')
        config.add_route_7('admin:certificate:focus:renew:quick:json', '/.well-known/admin/certificate/{@id}/renew/quick.json')
        config.add_route_7('admin:certificate:focus:renew:custom', '/.well-known/admin/certificate/{@id}/renew/custom')
        config.add_route_7('admin:certificate:focus:renew:custom:json', '/.well-known/admin/certificate/{@id}/renew/custom.json')
        config.add_route_7('admin:certificate:upload', '/.well-known/admin/certificate/upload')
        config.add_route_7('admin:certificate:upload:json', '/.well-known/admin/certificate/upload.json')

        config.add_route_7('admin:certificate_requests', '/.well-known/admin/certificate-requests')
        config.add_route_7('admin:certificate_requests_paginated', '/.well-known/admin/certificate-requests/{@page}')
        config.add_route_7('admin:certificate_request:focus', '/.well-known/admin/certificate-request/{@id}')
        config.add_route_7('admin:certificate_request:focus:raw', '/.well-known/admin/certificate-request/{@id}/csr.{format:(pem|pem.txt|csr)}')
        config.add_route_7('admin:certificate_request:process', '/.well-known/admin/certificate-request/{@id}/process')
        config.add_route_7('admin:certificate_request:deactivate', '/.well-known/admin/certificate-request/{@id}/deactivate')
        config.add_route_7('admin:certificate_request:process:domain', '/.well-known/admin/certificate-request/{@id}/process/domain/{domain_id:\d+}')

        # two types of CR handling
        config.add_route_7('admin:certificate_request:new:flow', '/.well-known/admin/certificate-request/new-flow')
        config.add_route_7('admin:certificate_request:new:full', '/.well-known/admin/certificate-request/new-full')

        # these are the recordkeeping
        config.add_route_7('admin:account_keys', '/.well-known/admin/account-keys')
        config.add_route_7('admin:account_keys_paginated', '/.well-known/admin/account-keys/{@page}')
        config.add_route_7('admin:account_key:focus', '/.well-known/admin/account-key/{@id}')
        config.add_route_7('admin:account_key:focus:raw', '/.well-known/admin/account-key/{@id}/key.{format:(key|pem|pem.txt)}')
        config.add_route_7('admin:account_key:focus:parse.json', '/.well-known/admin/account-key/{@id}/parse.json')
        config.add_route_7('admin:account_key:focus:certificate_requests', '/.well-known/admin/account-key/{@id}/certificate-requests')
        config.add_route_7('admin:account_key:focus:certificate_requests_paginated', '/.well-known/admin/account-key/{@id}/certificate-requests/{@page}')
        config.add_route_7('admin:account_key:focus:certificates', '/.well-known/admin/account-key/{@id}/certificates')
        config.add_route_7('admin:account_key:focus:certificates_paginated', '/.well-known/admin/account-key/{@id}/certificates/{@page}')
        config.add_route_7('admin:account_key:focus:authenticate', '/.well-known/admin/account-key/{@id}/authenticate')
        config.add_route_7('admin:account_key:new', '/.well-known/admin/account-key/new')

        config.add_route_7('admin:private_keys', '/.well-known/admin/private-keys')
        config.add_route_7('admin:private_keys_paginated', '/.well-known/admin/private-keys/{@page}')
        config.add_route_7('admin:private_key:focus', '/.well-known/admin/private-key/{@id}')
        config.add_route_7('admin:private_key:focus:parse.json', '/.well-known/admin/private-key/{@id}/parse.json')
        config.add_route_7('admin:private_key:focus:raw', '/.well-known/admin/private-key/{@id}/key.{format:(key|pem|pem.txt)}')
        config.add_route_7('admin:private_key:focus:certificates', '/.well-known/admin/private-key/{@id}/certificates')
        config.add_route_7('admin:private_key:focus:certificates_paginated', '/.well-known/admin/private-key/{@id}/certificates/{@page}')
        config.add_route_7('admin:private_key:focus:certificate_requests', '/.well-known/admin/private-key/{@id}/certificate-requests')
        config.add_route_7('admin:private_key:focus:certificate_requests_paginated', '/.well-known/admin/private-key/{@id}/certificate-requests/{@page}')
        config.add_route_7('admin:private_key:new', '/.well-known/admin/private-key/new')

        config.add_route_7('admin:ca_certificates', '/.well-known/admin/ca-certificates')
        config.add_route_7('admin:ca_certificates_paginated', '/.well-known/admin/ca-certificates/{@page}')
        config.add_route_7('admin:ca_certificate:focus', '/.well-known/admin/ca-certificate/{@id}')
        config.add_route_7('admin:ca_certificate:focus:parse.json', '/.well-known/admin/ca-certificate/{@id}/parse.json')
        config.add_route_7('admin:ca_certificate:focus:raw', '/.well-known/admin/ca-certificate/{@id}/chain.{format:(cer|crt|der|pem|pem.txt)}')
        config.add_route_7('admin:ca_certificate:focus:signed_certificates', '/.well-known/admin/ca-certificate/{@id}/signed_certificates')
        config.add_route_7('admin:ca_certificate:focus:signed_certificates_paginated', '/.well-known/admin/ca-certificate/{@id}/signed_certificates/{@page}')

        config.add_route_7('admin:ca_certificate:upload', '/.well-known/admin/ca-certificate/upload')
        config.add_route_7('admin:ca_certificate:upload:json', '/.well-known/admin/ca-certificate/upload.json')

        config.add_route_7('admin:ca_certificate:upload_bundle', '/.well-known/admin/ca-certificate/upload-bundle')
        config.add_route_7('admin:ca_certificate:upload_bundle:json', '/.well-known/admin/ca-certificate/upload-bundle.json')

        # sync events
        config.add_route_7('admin:operations', '/.well-known/admin/operations')

        config.add_route_7('admin:operations:log', '/.well-known/admin/operations/log')
        config.add_route_7('admin:operations:log_paginated', '/.well-known/admin/operations/log/{@page}')

        config.add_route_7('admin:operations:ca_certificate_probes', '/.well-known/admin/operations/ca-certificate-probes')
        config.add_route_7('admin:operations:ca_certificate_probes_paginated', '/.well-admin/operations/ca-certificate-probes/{@page}')

        config.add_route_7('admin:operations:ca_certificate_probes:probe', '/.well-known/admin/operations/ca-certificate-probes/probe')
        config.add_route_7('admin:operations:ca_certificate_probes:probe:json', '/.well-known/admin/operations/ca-certificate-probes/probe.json')

        config.add_route_7('admin:operations:update_recents', '/.well-known/admin/operations/update-recents')
        config.add_route_7('admin:operations:update_recents:json', '/.well-known/admin/operations/update-recents.json')

        config.add_route_7('admin:operations:deactivate_expired', '/.well-known/admin/operations/deactivate-expired')
        config.add_route_7('admin:operations:deactivate_expired:json', '/.well-known/admin/operations/deactivate-expired.json')

        config.add_route_7('admin:operations:nginx', '/.well-known/admin/operations/nginx')
        config.add_route_7('admin:operations:nginx_paginated', '/.well-known/admin/operations/nginx/{@page}')
        config.add_route_7('admin:operations:nginx:cache_flush', '/.well-known/admin/operations/nginx/cache-flush')
        config.add_route_7('admin:operations:nginx:cache_flush:json', '/.well-known/admin/operations/nginx/cache-flush.json')

        config.add_route_7('admin:operations:redis', '/.well-known/admin/operations/redis')
        config.add_route_7('admin:operations:redis_paginated', '/.well-known/admin/operations/redis/{@page}')
        config.add_route_7('admin:operations:redis:prime', '/.well-known/admin/operations/redis/prime')
        config.add_route_7('admin:operations:redis:prime:json', '/.well-known/admin/operations/redis/prime.json')

        config.scan("peter_sslers.views_admin")

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

    return config.make_wsgi_app()
