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
    },
    "Certificate Configuration": {
        "default_backup": {
            "docstring": "What should the default backup server be on forms? Must be `none` or `global`.",
            "default": "`none`",
            "show_on_settings": True,
        },
        "expiring_days": {
            "docstring": "The number of days remaining on a certificate before it is due for renewal.",
            "default": "`30`",
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
            "docstring": "This disables SSL verification against the Nginx servers; alternatively set `ca_bundle_pem`",
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
        "nginx.ca_bundle_pem": {
            "docstring": "A path to a PEM encoded list of Root Certificates used by the `nginx.servers_pool` if connecting via https.",
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
    "SQLAlchemy Configuration": {
        "sqlalchemy.url": {"docstring": "The SQLAlchemy URL", "show_on_settings": True}
    },
    "Experimental Configuration": {
        "acme_dns_support": {
            "docstring": "Default of `basic`, can be set to `experimental` but should not be.",
            "show_on_settings": False,
        }
    },
}
