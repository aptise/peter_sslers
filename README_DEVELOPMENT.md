README DEVELOPMENT
================================

For (most) testing and (all) development you need to follow a few initial steps.

1. Configure the `environment.ini` to use a custom CA

It should look something like this:

	certificate_authority = pebble
	certificate_authority_directory = https://0.0.0.0:14000/dir
	certificate_authority_protocol = acme-v2
	certificate_authority_testing = True

This above enables the acme-provider for a 'custom' CA and injects the protocol and endpoint into it.
It also enables the "TESTING" flag, which disables SSL checking on acme payloads.

When you start the server a new AcmeAccountProvider will be created for your CertificateAuthority:

	http://127.0.0.1:7201/.well-known/admin/acme-account-providers

2.  Create/Upload a new account key for the 'custom' acme-provider.

	http://127.0.0.1:7201/.well-known/admin/acme-account-key/new


3. Run a custom CA for testing

## ACME v2 Testing

You can test against the Pebble project, which is an existing acme-v2 test server maintained by LetsEncrypt.

Install pebble

Follow the instructions on https://github.com/letsencrypt/pebble ; this will require you to install `go`.

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
	PEBBLE_VA_ALWAYS_VALID=1 PEBBLE_AUTHZREUSE=100 PEBBLE_VA_NOSLEEP=1 PEBBLE_ALTERNATE_ROOTS=2 pebble -config ./test/config/pebble-config.json

## Integrated Testing

The tools directory has a list of nginx files (`tools/nginx_conf`) .

The `/tools/lazy.conf` configuration file has a catch-all route to proxy everything to the Pyramid app. 

If you set up some domains pointing to localhost (such as `dev.aptise.com` which has a public dns record to `127.0.0.1` you don't need to do any fancy iptables stuff.

The testing environment will wrap certain tests with spinning up a dedicated instance of Redis and/or Pebble for each test. This strategy is necessary to ensure there is no stale data in these platforms.


## ACME v1 Testing

ACME v1 is no longer supported in peter_sslers.


## Repository Styleguide

* Database operations are consolidated into `/lib/db` and should not happen in the web-application views. this is to foster development of non-web-application work.


## Unit Tests

The unit tests have several suites:

* FunctionalTests - designed to test the Pyramid Server and routes. Some items will communicate with a Pebble Certificate Authority
* IntegratedTests- designed to test validation by upstream servers . Some items will communicate with a Pebble Certificate Authority

The testing tool spins up a dedicated Pebble instance for each test.

If there is an error, tests and code should be constructed with the following querystring:

	?result=error&error={ERROR}[&operation={OPERATION}[&action={ACTION}]]

please note the order:

	result, error, operation, action
	

## check nginx routes

sudo curl https://peter:sslers@localhost/.peter_sslers/nginx/shared_cache/status -k 
sudo curl https://peter:sslers@localhost/.peter_sslers/nginx/shared_cache/expire -k 

the payloads should contain:

	"server": "peter_sslers:openresty"



### sample domains - testing suites

The testing suites require the following domains to point to localhost:

	# run after editing: dscacheutil -flushcache
	127.0.0.1 peter-sslers.example.com
	127.0.0.1 always-fail.example.com

	127.0.0.1 test-AcmeOrder-multiple-domains-1.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-2.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-3.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-4.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-5.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-6.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-7.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-8.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-9.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-10.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-11.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-12.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-13.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-14.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-15.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-16.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-17.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-18.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-19.example.com
	127.0.0.1 test-AcmeOrder-multiple-domains-20.example.com

	127.0.0.1 test-AcmeOrder-cleanup-1.example.com
	127.0.0.1 test-AcmeOrder-cleanup-2.example.com
	127.0.0.1 test-AcmeOrder-cleanup-3.example.com
	127.0.0.1 test-AcmeOrder-cleanup-4.example.com
	127.0.0.1 test-AcmeOrder-cleanup-5.example.com
	127.0.0.1 test-AcmeOrder-cleanup-6.example.com
	127.0.0.1 test-AcmeOrder-cleanup-7.example.com
	127.0.0.1 test-AcmeOrder-cleanup-8.example.com
	127.0.0.1 test-AcmeOrder-cleanup-9.example.com
	127.0.0.1 test-AcmeOrder-cleanup-10.example.com
	127.0.0.1 test-AcmeOrder-cleanup-1.example.com
	127.0.0.1 test-AcmeOrder-cleanup-11.example.com
	127.0.0.1 test-AcmeOrder-cleanup-12.example.com
	127.0.0.1 test-AcmeOrder-cleanup-13.example.com
	127.0.0.1 test-AcmeOrder-cleanup-14.example.com
	127.0.0.1 test-AcmeOrder-cleanup-15.example.com
	127.0.0.1 test-AcmeOrder-cleanup-16.example.com
	127.0.0.1 test-AcmeOrder-cleanup-17.example.com
	127.0.0.1 test-AcmeOrder-cleanup-18.example.com
	127.0.0.1 test-AcmeOrder-cleanup-19.example.com
	127.0.0.1 test-AcmeOrder-cleanup-20.example.com

	127.0.0.1 test-AcmeOrder-nocleanup-1.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-2.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-3.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-4.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-5.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-6.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-7.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-8.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-9.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-10.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-11.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-12.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-13.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-14.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-15.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-16.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-17.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-18.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-19.example.com
	127.0.0.1 test-AcmeOrder-nocleanup-20.example.com

	127.0.0.1 test_domain_certificate_if_needed-1.example.com
	127.0.0.1 test_domain_certificate_if_needed-2.example.com

	127.0.0.1 test-domain-autocert-1.example.com
	127.0.0.1 test-domain-autocert-2.example.com
	127.0.0.1 test-domain-autocert-3.example.com
	127.0.0.1 test-domain-autocert-4.example.com
	127.0.0.1 test-domain-autocert-5.example.com

	127.0.0.1 test_redis-1.example.com


## sample domains

a.example.com, b.example.com, c.example.com, d.example.com, e.example.com, f.example.com, g.example.com, h.example.com, i.example.com, j.example.com, k.example.com, l.example.com, m.example.com, n.example.com, o.example.com, p.example.com, q.example.com, r.example.com, s.example.com, t.example.com, u.example.com, v.example.com, w.example.com, x.example.com, y.example.com, z.example.com



