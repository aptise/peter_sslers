# this is used to drive documentation
documentation_grid = {
    "Enabled Options": {
        "enable_nginx": {
            "docstring": "Enables integration with Nginx webserver. This is automatically set if any nginx options are set.",
            "show_on_settings": True,
        },
        "enable_redis": {
            "docstring": "Enables integration with Redis cache.",
            "show_on_settings": True,
        },
        "enable_views_admin": {
            "docstring": "If `True`, then admin views are enabled. Otherwise they are disabled.",
            "show_on_settings": True,
        },
        "enable_views_public": {
            "docstring": "If `True`, then public views are enabled. Otherwise they are disabled.",
            "show_on_settings": True,
        },
        "block_competing_challenges": {
            "docstring": "If `True`, then a `Domain` can only have one challenge at a time.",
            "show_on_settings": True,
        },
    },
    "Views Configuration": {
        "admin_prefix": {
            "docstring": "The URL prefix which the admin tool will appear under.",
            "default": "`/.well-known/peter_sslers`",
            "show_on_settings": True,
        },
        "api_host": {
            "docstring": "A custom host this is served under. If omitted, this will default to the environment scheme+host.",
            "show_on_settings": True,
        },
        "exception_redirect": {
            "docstring": "If `True`, some views will redirect to a nice error page. If `False`, a raw exception will be raised.",
            "default": "`None`",
            "show_on_settings": True,
        },
    },
    "Certificate Configuration": {
        "certificate_authority": {
            "docstring": "The url of the ACME certificate authority or the string 'custom' (or 'pebble').",
            "default": "`https://acme-staging.api.letsencrypt.org`",
            "default-notes": "The default is set in `lib.acme_v2`.",
            "show_on_settings": True,
        },
        "certificate_authority_testing": {
            "docstring": "True/False if the CA is testing. This will disable SSL verification if True.",
            "default": "",
            "default-notes": "The default is set in `lib.acme_v2`.",
            "show_on_settings": True,
        },
        "certificate_authority_agreement": {
            "docstring": "The URL of the TOS agreement for the Certificate Authority.",
            "default": "None",
            "default-notes": "The default is set in `lib.acme_v2`. You MUST set this in settings to opt-in with a valid agreement. such as: `certificate_authority_agreement=https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf`",
            "show_on_settings": True,
        },
        "certificate_authority_endpoint": {
            "docstring": "The URL of the endpoint if `certificate_authority='custom'`.",
            "default": "None",
            "default-notes": "Acme v1. This must be supplied if the `certificate_authority` is set to `custom` or `pebble`.",
            "show_on_settings": True,
        },
        "certificate_authority_directory": {
            "docstring": "The URL of the endpoint directory if `certificate_authority='custom'`.",
            "default": "None",
            "default-notes": "Acme v2. This must be supplied if the `certificate_authority` is set to `custom` or `pebble`.",
            "show_on_settings": True,
        },
        "expiring_days": {
            "docstring": "The number of days remaining on a certificate before it is due for renewal.",
            "default": "`30`",
            "show_on_settings": True,
        },
        "openssl_path": {
            "docstring": "The path to the OpenSSL binary. PeterSSLers uses the system OpenSSL as backup.",
            "default": "`openssl`",
            "default-notes": "The default is set in `lib.cert_utils`.",
            "show_on_settings": True,
        },
        "openssl_path_conf": {
            "docstring": "The path to the OpenSSL configruation. PeterSSLers uses the system OpenSSL as backup.",
            "default": "`/etc/ssl/openssl.cnf`",
            "default-notes": "The default is set in `lib.cert_utils`.",
            "show_on_settings": True,
        },
        "queue_domains_max_per_cert": {
            "docstring": "Max domains per cert when dealing with the queued-domains",
            "default": "`100`",
            "default-notes": "LetsEncrypt has a max of 100.",
            "show_on_settings": True,
        },
        "queue_domains_min_per_cert": {
            "docstring": "Min domains per cert when dealing with the queued-domains",
            "default": "`1`",
            "default-notes": "",
            "show_on_settings": True,
        },
        "cleanup_pending_authorizations": {
            "docstring": "If an AcmeChallenge fails when processing an AcmeOrder, should the remaining AcmeAuthorizations be deactivated?",
            "default": "`True`",
            "default-notes": "",
            "show_on_settings": True,
        },
    },
    "NGINX Configuration": {
        ".section_requires": "enable_nginx",
        "nginx.reset_path": {
            "docstring": "The path on the enabled Nginx server providing an `expire` endpoint.",
            "default": "`/.peter_sslers/nginx/shared_cache/expire`",
            "show_on_settings": True,
        },
        "nginx.status_path": {
            "docstring": "The path on the enabled Nginx server providing a `status` endpoint.",
            "default": "`/.peter_sslers/nginx/shared_cache/status`",
            "show_on_settings": True,
        },
        "nginx.servers_pool": {
            "docstring": "A comma separated list of Nginx servers.",
            "show_on_settings": True,
        },
        "nginx.servers_pool_allow_invalid": {
            "docstring": "This controls SSL verification against the Nginx servers.",
            "show_on_settings": True,
        },
        "nginx.timeout": {
            "docstring": "A number of seconds to wait before timing out when querying the Nginx server.",
            "default": "`1`",
            "show_on_settings": True,
        },
        "nginx.userpass": {
            "docstring": "The `username:password` combination used for simple HTTP auth against the Nginx endpoints.",
            "show_on_settings": True,
        },
    },
    "Redis Configuration": {
        ".section_requires": "enable_redis",
        "redis.prime_style": {
            "docstring": "The style of Redis caching that to be used. Must be one of: 1, 2.",
            "show_on_settings": True,
        },
        "redis.url": {
            "docstring": "The URL of the Redis server.",
            "show_on_settings": True,
        },
    },
    "SqlAlchemy Configuration": {
        "sqlalchemy.url": {"docstring": "The SqlAlchemy URL", "show_on_settings": True}
    },
}
