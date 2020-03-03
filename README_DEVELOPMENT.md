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

	cd $GOPATH/src/github.com/letsencrypt/pebble
    pebble -config ./test/config/pebble-config.json

To have all challenge POST requests succeed without performing any validation run:

	cd $GOPATH/src/github.com/letsencrypt/pebble
	PEBBLE_VA_ALWAYS_VALID=1 PEBBLE_AUTHZREUSE=100 PEBBLE_VA_NOSLEEP=1 pebble -config ./test/config/pebble-config.json

## Integrated Testing

The tools directory has a list of nginx files (`tools/nginx_conf`) .

The `/tools/lazy.conf` configuration file has a catch-all route to proxy everything to the Pyramid app. 

If you set up some domains pointing to localhost (such as `dev.aptise.com` which has a public dns record to `127.0.0.1` you don't need to do any fancy iptables stuff.


## ACME v1 Testing

ACME v1 is no longer supported in peter_sslers.



a.example.com, b.example.com, c.example.com, d.example.com, e.example.com, f.example.com, g.example.com, h.example.com, i.example.com, j.example.com, k.example.com, l.example.com, m.example.com, n.example.com, o.example.com, p.example.com, q.example.com, r.example.com, s.example.com, t.example.com, u.example.com, v.example.com, w.example.com, x.example.com, y.example.com, z.example.com
