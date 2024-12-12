* [Previous - Installation](https://github.com/aptise/peter_sslers/tree/main/docs/Installation.md)
* [Next - General_Management_Concepts](https://github.com/aptise/peter_sslers/tree/main/docs/General_Management_Concepts.md)

# Configuration Options

Your `environment.ini` exposes a few configuration options.

These are documented at-length on the in-app settings page.

* `openssl_path` - the full path to your openssl binary (default `openssl`)
* `openssl_path_conf` - the full path to your openssl binary (default `/etc/ssl/openssl.cnf`)

* `certificate_authority` - the LetsEncrypt CertificateAuthority. by default we
  use their staging URL. you will have to manually put in the real URL as defined on
  their docs. You can also use the string "pebble" or "custom" to enable local testing.
* `certificate_authority_agreement` - the LetsEncrypt agreement URL used when
  creating new accounts. Everything will probably fail if you don't include this argument.
* `certificate_authority_endpoint` - ACME v1; if `certificate_authority=custom` or
  `certificate_authority=pebble`, you must supply a url for the endpoint
* `certificate_authority_directory` - ACME v2; if `certificate_authority=custom` or
  `certificate_authority=pebble`, you must supply a url for the directory endpoint

* `cleanup_pending_authorizations` - boolean, default True. if an AcmeChallenge
  fails when processing an AcmeOrder, should the remaining AcmeAuthorizations be deactivated?

* `enable_views_public` - boolean, should we enable the public views?
* `enable_views_admin` - boolean, should we enable the admin views?
* `enable_acme_flow` - boolean, should we enable the ACME-flow tool?

* `redis.url` - URL of `Redis` (includes port)
* `redis.prime_style` - MUST be "1" or "2"; see `Redis` Prime section below.
* `redis.timeout.certca` - INT seconds (default None)
* `redis.timeout.cert` - INT seconds (default None)
* `redis.timeout.pkey` - INT seconds (default None)
* `redis.timeout.domain` - INT seconds (default None)

* `nginx.servers_pool` - comma(,) separated list of servers with an expiry route;
  see `Redis` Prime section below
* `nginx.userpass` - http authhentication (username:password) which will be provided
  to each server in `nginx.servers_pool`
* `nginx.reset_path` - defaults to `/.peter_sslers/nginx/shared_cache/expire`
* `nginx.status_path` - defaults to `/.peter_sslers/nginx/shared_cache/status`
* `requests.disable_ssl_warning` - will disable the ssl warnings from the requests
  library

* `admin_server` (optional) defaults to `HTTP_HOST`
* `admin_prefix` (optional) prefix for the admin tool. defaults to `/.well-known/peter_sslers`
* `admin_url` (optional) used for display in instructions. If omitted,
  scheme+server+prefix will be used.

If you have a custom openssl install, you probably want these settings

    openssl_path = /usr/local/bin/openssl
    openssl_path_conf = /usr/local/ssl/openssl.cnf

These options are used by the server AND by the test suite.
