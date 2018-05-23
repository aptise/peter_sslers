README DEVELOPMENT
================================

For (most) testing and (all) development you need to follow a few initial steps.

1. Configure the `environment.ini` to use a custom CA

It should look something like this:

	certificate_authority = custom 
	certificate_authority_testing = True
	certificate_authority_endpoint = http://127.0.0.1:7202
	certificate_authority_protocol = acme-v1

This above enables the acme-provider for a 'custom' CA and injects the protocol and endpoint into it.
It also enables the "TESTING" flag, which disables SSL checking on acme payloads.

2.  Create/Upload a new account key for the 'custom' acme-provider.

3. Run a custom CA for testing

This is slightly different for acme v1 and acme v2

## Acme v1

Use tools/fake_boulder.py to spin up a fake acme-v1 server.
The script has documentation in it, regarding how to set things up.
At this time this README was written, fake_boulder.py handles uses openssl's "ca" mode to sign certificates.
This requires environment variabels to be set, and  will write copies of the generated certificates.



## Acme v2

You can test against the Pebble project, which is an existing acme-v2 test server

Install pebble

	https://github.com/letsencrypt/pebble
	install go
	export GOPATH=/Users/{username}/go
	export PATH="$PATH:/Users/{username}/go/bin"

Run pebble to always validate

	PEBBLE_VA_ALWAYS_VALID=1 pebble

