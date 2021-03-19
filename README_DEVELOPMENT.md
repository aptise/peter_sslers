README DEVELOPMENT
================================

For (most) testing and (all) development you need to follow a few initial steps.

1. Configure the `environment.ini` to use a custom CA

It should look something like this:

    certificate_authority = pebble
    certificate_authority_directory = https://0.0.0.0:14000/dir
    certificate_authority_protocol = acme-v2
    certificate_authority_testing = True

This above enables the AcmeProvider for a 'custom' CA and injects the protocol
and endpoint into it. It also enables the "TESTING" flag, which disables SSL
checking on ACME payloads.

When you start the server a new AcmeAccountProvider will be created for
your CertificateAuthority:

    http://127.0.0.1:7201/.well-known/admin/acme-account-providers

2.  Create/Upload a new account key for the 'custom' AcmeProvider.

    http://127.0.0.1:7201/.well-known/admin/acme-account-key/new


3. Run a custom CA for testing

## ACME v2 Testing

You can test against the Pebble project, which is an existing ACME-v2 test server
maintained by LetsEncrypt.

### Install pebble

Follow the instructions on https://github.com/letsencrypt/pebble ;
this will require you to install `go`.

> 1. [Set up Go](https://golang.org/doc/install) and your `$GOPATH`
> 2. `go get -u github.com/letsencrypt/pebble/...`
> 3. `cd $GOPATH/src/github.com/letsencrypt/pebble && go install ./...`
> 4. `pebble -h`

As a precaution, copy the pebble config file:

    cp ./test/config/pebble-config.json ./test/config/pebble-config.dist.json

The edit it to see the configuration

    vi ./test/config/pebble-config.json

Which should look something like this...

    "pebble": {
      "listenAddress": "0.0.0.0:14000",
      "managementListenAddress": "0.0.0.0:15000",
      "certificate": "test/certs/localhost/cert.pem",
      "privateKey": "test/certs/localhost/key.pem",
      "httpPort": 5002,
      "tlsPort": 5001,
      "ocspResponderURL": "",
      "externalAccountBindingRequired": false
    }


Good to go?  Ok, run pebble!

    cd $GOPATH/src/github.com/letsencrypt/pebble
    PEBBLE_ALTERNATE_ROOTS=2 pebble -config ./test/config/pebble-config.json

To have all challenge POST requests succeed without performing any validation run:

    cd $GOPATH/src/github.com/letsencrypt/pebble
    PEBBLE_VA_ALWAYS_VALID=1 \
		PEBBLE_AUTHZREUSE=100 \
		PEBBLE_VA_NOSLEEP=1 \
		PEBBLE_ALTERNATE_ROOTS=2 \
		PEBBLE_CHAIN_LENGTH=3 \
		pebble -config ./test/config/pebble-config.json

Pebble serves a single chain by default. PEBBLE_CHAIN_LENGTH


## Integrated Testing

The tools directory has a list of nginx files (`tools/nginx_conf`) .

The `/tools/lazy.conf` configuration file has a catch-all route to proxy everything
to the Pyramid app.

If you set up some domains pointing to localhost (such as `dev.aptise.com` which
has a public dns record to `127.0.0.1` you don't need to do any fancy iptables stuff.

The testing environment will wrap certain tests with spinning up a dedicated instance
of Redis and/or Pebble for each test. This strategy is necessary to ensure there
is no stale data in these platforms.


## ACME-DNS Testing

The testing suite can not reliably spin-up `acme-dns``, so it must run in it's
own process.

Use the test-config file:

    sudo acme-dns -c ./tests/test_configuration/acme-dns.config


## ACME v1 Testing

ACME v1 is no longer supported in peter_sslers.


## Repository Styleguide

* Database operations are consolidated into `/lib/db` and should not happen in the
  web-application views. This is to foster development of non-web-application work.


## Unit Tests

The unit tests have several suites:

* FunctionalTests - designed to test the Pyramid Server and routes.
  Some items will communicate with a Pebble Certificate Authority
* IntegratedTests- designed to test validation by upstream servers.
  Some items will communicate with a Pebble Certificate Authority

The testing tool spins up a dedicated Pebble instance for each test.

If there is an error, tests and code should be constructed with the following querystring:

    ?result=error&error={ERROR}[&operation={OPERATION}[&action={ACTION}]]

please note the order:

    result, error, operation, action

Unit tests will use the `test.ini` file for configuration.

Instead of editing this file, you can overwrite it with an environment variable:

    export SSL_TEST_INI="test_local.ini"


## check nginx/openresty routes

First check two general-purpose routes:

    curl https://peter:sslers@127.0.0.1/.peter_sslers/nginx/shared_cache/status -k
    curl https://peter:sslers@127.0.0.1/.peter_sslers/nginx/shared_cache/expire/all -k

The payloads should contain:

    "server": "peter_sslers:openresty"
    "result": "success"

Then check the expire route:

    curl https://peter:sslers@127.0.0.1/.peter_sslers/nginx/shared_cache/expire -k

Tt should error:

    "server": "peter_sslers:openresty"
    "result": "error"

But change it to a Domain:

    curl https://peter:sslers@127.0.0.1/.peter_sslers/nginx/shared_cache/expire/domain/example.com -k

It should succeed:

    "server": "peter_sslers:openresty"
    "result": "success"
    "expired": "domain"
    "domain": "example.com"


### Sample Domains - testing suites

The testing suites require the following domains to point to localhost:

{{SEE cat ./tests/test_configuration/hosts.txt}}

run after editing:

    osx:
        dscacheutil -flushcache
    ubuntu:
        systemd-resolve --flush-caches

## sample domains

The following domains are also recommended for development testing:

	a.example.com, b.example.com, c.example.com, d.example.com, e.example.com, f.example.com, g.example.com, h.example.com, i.example.com, j.example.com, k.example.com, l.example.com, m.example.com, n.example.com, o.example.com, p.example.com, q.example.com, r.example.com, s.example.com, t.example.com, u.example.com, v.example.com, w.example.com, x.example.com, y.example.com, z.example.com


# CI Setup Benchmarks

## Installing Go

Go is already installed, however if we need to do a new version...

* snap 15s

    sudo snap install --classic go

* ubuntu packages 32s

    sudo add-apt-repository ppa:longsleep/golang-backports
    sudo apt update
    sudo apt install golang-go


# useful queries

## grab acme-dns info

    select d.id, d.domain_name, a.username, a.password, a.fulldomain, a.subdomain
    from acme_dns_server_account a
    join domain d on a.domain_id = d.id
    ;



