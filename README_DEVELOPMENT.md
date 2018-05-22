README DEVELOPMENT
================================


What does the dev.ini look like?

	certificate_authority = custom
	certificate_authority_testing = True
	certificate_authority_endpoint = http://127.0.0.1:7202
	certificate_authority_protocol = acme-v1


CREATE A CUSTOM ACCOUNT_KEY


Acme v1

	use tools/fake_boulder.py to spin up a fake acme-v1 server
	it requires a directory of fake certs

Acme v2

	Test against Pebble

	Install pebble

		https://github.com/letsencrypt/pebble
		install go
		export GOPATH=/Users/{username}/go
		export PATH="$PATH:/Users/{username}/go/bin"

	Run pebble to always validate

		PEBBLE_VA_ALWAYS_VALID=1 pebble

