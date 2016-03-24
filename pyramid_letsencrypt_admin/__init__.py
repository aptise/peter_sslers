from pyramid.config import Configurator
from sqlalchemy import engine_from_config

from .models import (DBSession,
                     Base,
                     )

from .lib import acme


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    engine = engine_from_config(settings, 'sqlalchemy.')
    DBSession.configure(bind=engine)
    Base.metadata.bind = engine
    config = Configurator(settings=settings)
    config.include('pyramid_mako')
    config.add_static_view('static', 'static', cache_max_age=3600)

    # public url
    config.add_route('public_challenge', '/.well-known/acme-challenge/{challenge}')
    config.add_route('public_whoami', '/.well-known/whoami')

    # admin
    config.add_route('admin', '/.well-known/admin')

    config.add_route('admin:domains', '/.well-known/admin/domains')
    config.add_route('admin:domains_paginated', '/.well-known/admin/domains/{page:\d+}')
    config.add_route('admin:domain:focus', '/.well-known/admin/domain/{id:\d+}')

    config.add_route('admin:certificates', '/.well-known/admin/certificates')
    config.add_route('admin:certificates_paginated', '/.well-known/admin/certificates/{page:\d+}')
    config.add_route('admin:certificate:focus', '/.well-known/admin/certificate/{id:\d+}')
    config.add_route('admin:certificate:focus:chain:raw', '/.well-known/admin/certificate/{id:\d+}/chain.{format:(der|pem|pem.txt)}')
    config.add_route('admin:certificate:focus:fullchain:raw', '/.well-known/admin/certificate/{id:\d+}/fullchain.{format:(der|pem|pem.txt)}')
    config.add_route('admin:certificate:focus:privatekey:raw', '/.well-known/admin/certificate/{id:\d+}/privatekey.{format:(der|pem|pem.txt)}')
    config.add_route('admin:certificate:focus:cert:raw', '/.well-known/admin/certificate/{id:\d+}/cert.{format:(crt|pem|pem.txt)}')
    config.add_route('admin:certificate:upload', '/.well-known/admin/certificate/upload')

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

    config.add_route('admin:domain_keys', '/.well-known/admin/domain_keys')
    config.add_route('admin:domain_keys_paginated', '/.well-known/admin/domain_keys/{page:\d+}')
    config.add_route('admin:domain_key:focus', '/.well-known/admin/domain_key/{id:\d+}')
    config.add_route('admin:domain_key:focus:raw', '/.well-known/admin/domain_key/{id:\d+}/key.{format:(key|pem|pem.txt)}')
    config.add_route('admin:domain_key:new', '/.well-known/admin/domain_key/new')

    config.add_route('admin:ca_certificates', '/.well-known/admin/ca_certificates')
    config.add_route('admin:ca_certificates_paginated', '/.well-known/admin/ca_certificates/{page:\d+}')
    config.add_route('admin:ca_certificate:focus', '/.well-known/admin/ca_certificate/{id:\d+}')
    config.add_route('admin:ca_certificate:focus:raw', '/.well-known/admin/ca_certificate/{id:\d+}/chain.{format:(cer|der|pem|pem.txt)}')
    config.add_route('admin:ca_certificate:focus:signed_certificates', '/.well-known/admin/ca_certificate/{id:\d+}/signed_certificates')
    config.add_route('admin:ca_certificate:focus:signed_certificates_paginated', '/.well-known/admin/ca_certificate/{id:\d+}/signed_certificates/{page:\d}')

    # testing
    config.add_route('admin:inject_sample', '/.well-known/admin/inject_sample')

    # update the module data based on settings
    if 'openssl' in settings:
        acme.openssl_path = settings["openssl"]
    if 'openssl_path_conf' in settings:
        acme.openssl_path_conf = settings["openssl_path_conf"]
    if 'certificate_authority' in settings:
        acme.CERTIFICATE_AUTHORITY = settings["certificate_authority"]

    # will we redirect on error?
    _redirect = False
    if 'exception_redirect' in settings:
        if settings["exception_redirect"].lower() in ('1', 'true'):
            _redirect = True
    settings["exception_redirect"] = _redirect

    config.scan()
    return config.make_wsgi_app()
