* [Previous - Installation](https://github.com/aptise/peter_sslers/tree/main/docs/Installation.md)
* [Next - General_Management_Concepts](https://github.com/aptise/peter_sslers/tree/main/docs/General_Management_Concepts.md)

# Configuration Options

Your `environment.ini` exposes a few configuration options.

These are documented at-length on the in-app settings page.

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
* `nginx.ca_bundle_pem` - path to a pem encoded list of root certificates used by the nginx server

* `precheck_acme_challenges` - comma separated list of acme_challenges to precheck; e.g. 

    precheck_acme_challenges = http-01
    precheck_acme_challenges = http-01, dns-01
    
    A precheck will keep a challenge from triggering, so it can be fixed within the same order.


* `requests.disable_ssl_warning` - will disable the ssl warnings from the requests
  library

* `admin_server` (optional) defaults to `HTTP_HOST`
* `admin_prefix` (optional) prefix for the admin tool. defaults to `/.well-known/peter_sslers`
* `admin_url` (optional) used for display in instructions. If omitted,
  scheme+server+prefix will be used.
* `http_port.renewals` (optional) Default: 7202; the port used to answer
  http-01 challenges; traffic must be proxied to it from port 80.

These options are used by the server AND by the test suite.
