# this is used to drive documentation
configuration_options = {
 'Enabled Options': {
	'enable_nginx': {'docstring': 'Enables integration with Nginx webserver. This is automatically set if any nginx options are set.'},
	'enable_redis': {'docstring': 'Enables integration with Redis cache.'},
	'enable_views_admin': {'docstring': 'If `True`, then admin views are enabled. Otherwise they are disabled.'},
	'enable_views_public': {'docstring': 'If `True`, then public views are enabled. Otherwise they are disabled.'}
 },
'Views Configuration': {
	'admin_prefix': {'docstring': 'The URL prefix which the admin tool will appear under.',
	 				 'default': '`/.well-known/admin`'
	 				 },
	'api_host': {'docstring': 'A custom host this is served under. If omitted, this will default to the environment scheme+host.'},
	'exception_redirect': {'docstring': 'If `True`, some views will redirect to a nice error page. If `False`, a raw exception will be raised.',
						   'default': 'None'
						   }
 },
'Certifcate Configuration': {
	'certificate_authority': {'docstring': '.',
	                          'default': '`https://acme-staging.api.letsencrypt.org`',
					          'default-notes': 'The default is set in `lib.acme`.'
	                          },
	'certificate_authority_agreement': {'docstring': '.',
	                          'default': '`https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf`',
					          'default-notes': 'The default is set in `lib.acme`.'
	                          },
	'expiring_days': {'docstring': 'The number of days remaining on a certificate before it is due for renewal.',
					  'default': 30
					  },
	'openssl_path': {'docstring': 'The path to the OpenSSL binary. PeterSSLers uses the system OpenSSL.',
					 'default': '`openssl`',
					 'default-notes': 'The default is set in `lib.cert_utils`.'
					 },
	'openssl_path_conf': {'docstring': 'The path to the OpenSSL configruation. PeterSSLers uses the system OpenSSL.',
						  'default': '`/etc/ssl/openssl.cnf`',
	  					  'default-notes': 'The default is set in `lib.cert_utils`.'
						  }
	},
'NGINX Configuration': {
	'.section_requires': 'enable_nginx',
	'nginx.reset_path': {'docstring': 'The path on the enabled Nginx server providing an `expire` endpoint.',
						 'default': '`/.peter_sslers/nginx/shared_cache/expire`'
						 },
	'nginx.status_path': {'docstring': 'The path on the enabled Nginx server providing a `status` endpoint.',
						 'default': '`/.peter_sslers/nginx/shared_cache/status`'
						 },
	'nginx.servers_pool': {'docstring': 'A comma separated list of Nginx servers.'},
	'nginx.servers_pool_allow_invalid': {'docstring': 'This controls SSL verification against the Nginx servers.'},
	'nginx.timeout': {'docstring': 'A number of seconds to wait before timing out when querying the Nginx server.',
					  'default': '`1`'
					  },
	'nginx.userpass': {'docstring': 'The `username:password` combination used for simple HTTP auth against the Nginx endpoints.'}
    },
'Redis Configuration': {
	'.section_requires': 'enable_redis',
	'redis.prime_style': {'docstring': 'The style of Redis caching that to be used. Must be one of: 1, 2.',
	                      },
	'redis.url': {'docstring': 'The URL of the Redis server.',
	              }
    },
'SqlAlchemy Configuration': {
	'sqlalchemy.url': {'docstring': 'The SqlAlchemy URL'}
  }
}