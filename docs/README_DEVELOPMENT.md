README DEVELOPMENT
================================

## prep the data dir

    mkdir data_development
    cp example_configs/development.ini data_development/config.ini
    cp tests/test_configuration/pebble/test/certs/pebble.minica.pem data_development/nginx_ca_bundle.pem


## install with testing extras

Instead of a normal pip install...

    pip install -e .

Make sure to install the testing extras

    pip install -e .[testing]

## Server Configuration

Edit your hosts

    vi /etc/hosts

Ensure we can reach ourselves

    127.0.0.1   peter-sslers.example.com

## Testing Configuration

For (most) testing and (all) development you need to follow a few initial steps.

1. Configure the `data_development/config.ini` to use a custom CA

It should look something like this:

    certificate_authority = pebble
    certificate_authority_directory = https://127.0.0.1:14000/dir
    certificate_authority_protocol = acme-v2
    certificate_authority_testing = True

This above enables the AcmeProvider for a 'custom' CA and injects the protocol
and endpoint into it. It also enables the "TESTING" flag, which disables SSL
checking on ACME payloads.

When you start the server a new AcmeServer will be created for
your CertificateAuthority:

    http://127.0.0.1:7201/.well-known/peter_sslers/acme-servers

2.  Create/Upload a new account key for the 'custom' AcmeProvider.

    http://127.0.0.1:7201/.well-known/peter_sslers/acme-account-key/new


3. Run a custom CA for testing

## ACME v2 Testing

You can test against the Pebble project, which is an existing ACME-v2 test server
maintained by LetsEncrypt.

### Install pebble

Follow the instructions on https://github.com/letsencrypt/pebble?tab=readme-ov-file#install ;
this will require you to install `go`.

> 1. Set up Go [from binaries](https://golang.org/doc/install) or [from source](https://go.dev/doc/install/source) and your `$GOPATH`
> 2. `git clone https://github.com/letsencrypt/pebble/`
> 3. `cd pebble`
> 4. `go install ./cmd/pebble`

As a precaution, copy the pebble config file. On the root project directory:

    cp ./tests/test_configuration/pebble/test/config/pebble-config.json ./tests/test_configuration/pebble/test/config/pebble-config.json

The edit it to see the configuration

    vi ./tests/test_configuration/pebble/test/config/pebble-config.json

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


Good to go?  You can run pebble in a mode where it attempts to validate challenges...

    PEBBLE_VA_ALWAYS_VALID=0 \
        PEBBLE_AUTHZREUSE=100 \
        PEBBLE_VA_NOSLEEP=1 \
        PEBBLE_ALTERNATE_ROOTS=2 \
        PEBBLE_CHAIN_LENGTH=3 \
        pebble --config  ./tests/test_configuration/pebble/test/config/pebble-config.json

but for development it is often preferred to have all challenge POST requests succeed
without actually performing any validation, via::

    PEBBLE_VA_ALWAYS_VALID=1 \
        PEBBLE_AUTHZREUSE=100 \
        PEBBLE_VA_NOSLEEP=1 \
        PEBBLE_ALTERNATE_ROOTS=2 \
        PEBBLE_CHAIN_LENGTH=3 \
        pebble -config ./tests/test_configuration/pebble/test/config/pebble-config.json

A second testserver is used as well for backup certificates:

    PEBBLE_VA_ALWAYS_VALID=1 \
        PEBBLE_AUTHZREUSE=100 \
        PEBBLE_VA_NOSLEEP=1 \
        PEBBLE_ALTERNATE_ROOTS=2 \
        PEBBLE_CHAIN_LENGTH=3 \
        pebble -config ./tests/test_configuration/pebble/test-alt/config/pebble-config.json


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


## Testing Database

Tests will create/use a database file named `ssl_minnow_test.sqlite`

To streamline overhead, the tests will create and utilize database snapshots:

    `ssl_minnow_test.sqlite-AppTest`
    `ssl_minnow_test.sqlite-AppTestCore`

To ensure fresh tests, all 3 files can be removed:

    `ssl_minnow_test.sqlite`
    `ssl_minnow_test.sqlite-AppTest`
    `ssl_minnow_test.sqlite-AppTestCore`

The tests can be fragile; if one test fails then subsequent tests can cause failures.

It is recommended to delete the test databases after a failure and when dealing with regressions.

## ACME-DNS Testing

The testing suite can not reliably spin-up `acme-dns`, so it must run in it's
own process.

Use the test-config file:

    sudo acme-dns -c ./tests/test_configuration/acme-dns--local.config


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

Unit tests will use the `data_testing/config.ini` file for configuration.

Instead of editing this file, you can overwrite it with an environment variable:

    export SSL_TEST_INI="data_testing/test_local.ini"

Config file inheritance can be a bit wonky, so it is best to recreate the entire
config file instead of inheriting to change values.


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



# Application Design

The application design of PeterSSLers is designed to be extensible and reusable,
so the library can be used for both commandline work and web based tools.

* `/lib` - main library functions
* `/lib/db` - All database manipulation happens here, so it can be leveraged
outside of the web context
* `/model` - SQLAlchemy Model
* `/web` - A Pyramid Application

With the exception of the testing system, no SqlAlchemy code should exist in the
web section.



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


## Support for CAs with non-public roots

If a CA has a non-public root, for example a Private CA or testing CA, TLS support
is achieved by setting a `server_ca_cert_bundle` value on the database record.

This can be provided in the initial configuration, or adjusted via commandline tools.


## Useful Tests

order one cert and process it at once, through acme-order/new-freeform

    pytest tests/test_pyramid_app.py::IntegratedTests_AcmeServer_AcmeOrder::test_AcmeOrder_process_single_html
    
    
    
        

