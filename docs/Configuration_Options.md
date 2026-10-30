* [Previous - Installation](https://github.com/aptise/peter_sslers/blob/main/docs/Installation.md)
* [Next - General_Management_Concepts](https://github.com/aptise/peter_sslers/blob/main/docs/General_Management_Concepts.md)

# Configuration Options

Your `{ENVIRONMENT}/config.ini` exposes a few configuration options.

These are documented at-length on the in-app settings page.

* `cleanup_pending_authorizations` - boolean, default True. if an AcmeChallenge
  fails when processing an AcmeOrder, should the remaining AcmeAuthorizations be deactivated?
  This is a global default; an ACME Server can be configured to disregard this setting.

* `enable_views_public` - boolean, should we enable the public views?
* `enable_views_admin` - boolean, should we enable the admin views?

* `redis.url` - URL of `Redis` (includes port)
* `redis.prime_style` - MUST be "1" or "2"; see `Redis` Prime section below.
* `redis.timeout.certcachain` - INT seconds (default None)
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

### Redis and Valkey certificate caches

Use the existing `redis.*` settings for either server. Valkey uses the same
`redis://` connection URL and Python Redis client; no separate client package
or `valkey.*` settings are needed for the certificate cache.

`redis.timeout.domain` applies to domain hashes in both prime styles. Re-priming
updates the payload and lifetime together. An unset timeout makes the hash
persistent, including clearing a previous expiration. This TTL controls the
backend cache entry, not certificate validity or OpenResty worker-cache lifetime.

The isolated backend checks run against both executables when installed:

```sh
python -m pytest tests/test_cache_backends.py -q
```

Each test starts a private server on a temporary Unix socket, with TCP and disk
persistence disabled. Missing executables are reported as skipped tests.

Cache TTL settings (`redis.timeout.cert`, `redis.timeout.certcachain`,
`redis.timeout.pkey`, and `redis.timeout.domain`) must be positive integer seconds
when supplied. Omit a setting for persistent entries. Invalid values now fail at
startup rather than during a cache write.

Cache clients default to a 3.05-second connection timeout and a 10-second socket
timeout. Deployments can override these through URL query parameters, for example
`redis://localhost:6379/0?socket_connect_timeout=2&socket_timeout=5`.

### Nginx cache-control outcomes

Cache flush and expiry operations report failure if any configured server fails.
Per-domain expiry event records list a domain as successful only when no server
failed it. Empty server pools are configuration errors for these operations.
Clients should check the JSON `result` field and the per-server details even
when the API returns HTTP 200. CLI cache-control output also reflects failures.

The comma-separated `nginx.servers_pool` ignores blank entries and duplicate
servers while retaining configured order. In `nginx.userpass`, the first colon
separates username and password; further colons belong to the password.
