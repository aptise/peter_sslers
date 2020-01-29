README DEVELOPMENT
================================

For (most) testing and (all) development you need to follow a few initial steps.

1. Configure the `environment.ini` to use a custom CA

It should look something like this:

	certificate_authority = custom  # "custom" or "pebble"
	certificate_authority_testing = True
	certificate_authority_endpoint = http://127.0.0.1:14000
	certificate_authority_directory = http://127.0.0.1:14000/dir
	certificate_authority_protocol = acme-v2

This above enables the acme-provider for a 'custom' CA and injects the protocol and endpoint into it.
It also enables the "TESTING" flag, which disables SSL checking on acme payloads.

2.  Create/Upload a new account key for the 'custom' acme-provider.

3. Run a custom CA for testing

## ACME v2 Testing

You can test against the Pebble project, which is an existing acme-v2 test server maintained by letsencrypt.

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

    pebble -config ./test/config/pebble-config.json

To have all challenge POST requests succeed without performing any validation run:

	PEBBLE_VA_ALWAYS_VALID=1 pebble

## ACME v1 Testing

ACME v1 is no longer supported in peter_sslers.
