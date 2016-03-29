pyramid_letsencrypt_admin README
==================

`pyramid_letsencrypt_admin` is a tool designed to help EXPERIENCED DEVOPS people to manage SSL Certificate deployment on large systems. This package offers a lightweight database backed "webserver" that can handle the LetsEncrypt issuance process, import any existing ssl certificates, and easily provision them to servers. This tool has absolutely no security measures and should only be used by people who understand that (that should be a self-selecting group, because many people won't want this).  This package offers several commandline tools, so spinning it up in "webserver" mode may not be necessary.

# An important WARNING:

* This package DOES NOT USE/KNOW/CARE ABOUT SECURITY.
* This package manages PRIVATE SSL KEYS and makes them readable.
* If you do not known / are not really awesome with basic network security PLEASE DO NOT USE THIS.

# What this package does:

The package offers lightweight tools to centrally manage SSL Certificate data in a SQL database of your choice.

SqlAlchemy is the DB library, so virtually any database can be used (sqlite, postgres, mysql, oracle, mssql, etc). sqlite is the default.  sqlite is actually kind of great, because it can be sftpd onto different machines for local use.

You can manage certificates in a few ways:

## Input

1. An admin dashboard allows you to upload certificates (in a triplet of Cert, Signing Key, CA-Chain)
2. An admin dashboard allows you to initiate LetsEncrypt certificate signing. Upload a list of domains, your LetsEncrypt account key, and private key used for signing/serving, and the system will generate the CSR and perform all the verifications.
3. An admin dashboard allows you to proxy the acme-challenges that LetsEncrypt issues for manual verification

## Output

1. All the keys & certs are viewable in a wonderfully connected RDMBS browser.
2. Any keys/certs/chains can be queried in PEM & DER formats.
3. All the certificates are checked to track their validity dates, so you can search and re-issue

## Management

* Everything is in the RDBMS and de-duped.
* chains are built on-the-fly.
* a growing API powers most functionality
* public and admin routes can be isolated in the app & firewall, so you can just turn this on/off as needed
* query to see when things expire
* if sqlite is your backend, you can just run this for signing and deployment; then handle everything else offline.

# Installation

This is pretty much ready to go for development use.

you should create a virtualenv though.

	mkdir certificate_admin
	cd certificate_admin
	git checkout https://github.com/jvanasco/pyramid_letsencrypt_admin.git
	virtualenv pyramid_letsencrypt_admin-venv
	source pyramid_letsencrypt_admin-venv/bin/activate
	cd pyramid_letsencrypt_admin
	python setup.py develop
	initialize_pyramid_letsencrypt_admin_db development.ini
	pserve --reload development.ini
	
some tools are provided, see below, to automatically import existing certificates and chains

# Implementation Details

The webserver exposes the following routes/directories:

* `/.well-known/acme-challenge` - directory
* `/.well-known/whoami` - URL prints host
* `/.well-known/admin` - admin tool THIS EXPLORES PRIVATE KEYS ON PURPOSE

# Just a friendly reminder:

THE ADMIN TOOL SHOULD NOT BE PUBLICLY ACCESSIBLE.
YOU SHOULD ONLY RUN IT ON YOUR PRIVATE NETWORK

# why/how?

The purpose of this package is to enable certificate management in systems where one or more of the following apply:

* you have a lot of domains
* you have a lot of machines
* your domains resolve to more than one IP address

Imagine you want to issue a certificate for 100 domains, which could be served from any one of 5 machines (load balancers or round-robin dns) and the certificates need to be deployable to all 5 machines.

To solve this you can:

* proxy external ` /.well-known/acme-challenge/` to one or more machines running this tool (they just need to share a common datastore)
* make ` /.well-known/admin` only usable within your LAN or NEVER USABLE
* on a machine within your LAN, you can query for the latest certs for domain(s) using simple `curl` commands

In a more advanced implementation (such as what this was designed to manage) the certificates need to be loaded into a `Redis` server for use by an `openresty`/`nginx` webserver/gateway that will dynamically handle ssl certificates.

This package does all the annoying openssl work in terms of building chains and converting formats *You just tell it what domains you need certificates for and in which format and THERE YOU GO.*

# notes

## Certificate/Key Translations

Certificates and Keys are stored in the PEM format, but can be downloaded in the DER format if needed.

There are several ways to download each file. Different file suffix will change the format and headers.

### CA Certificate

	could be `cert` or `chain`

	cert.pem 		PEM		application/x-pem-file
	cert.pem.txt	PEM		text/plain
	cert.cer 		DER		application/pkix-cert
	cert.der 		DER		application/x-x509-ca-cert
	cert.crt 		DER		application/x-x509-ca-cert

### Signed Certificate

	cert.pem 		PEM		application/x-pem-file
	cert.pem.txt	PEM		text/plain
	cert.crt 		DER		application/x-x509-server-cert

### Certificate Request

	csr.pem 		PEM		application/x-pem-file
	csr.pem.txt		PEM		text/plain
	csr.csr 		PEM		application/pkcs10

## Account/Domain Keys

	key.pem 		PEM		application/x-pem-file
	key.pem.txt		PEM		text/plain
	key.key 		DER		application/pkcs8

## Account/Domain Keys

	key.pem 		PEM		application/x-pem-file
	key.pem.txt		PEM		text/plain
	key.key 		DER		application/pkcs8


# Configuration options

Your `environment.ini` exposes a few configuration options:

* `exception_redirect` - boolean, should we redirect on certain exceptions or raise?
* `openssl_path` - the full path to your openssl binary (default `openssl`)
* `openssl_path_conf` - the full path to your openssl binary (default `/etc/ssl/openssl.cnf`)
* `certificate_authority` - the LetsEncrypt certificate authority. default is their staging. you'll have to manually put in the production.

* `enable_views_public` - boolean, should we enable the public views?
* `enable_views_admin` - boolean, should we enable the admin views?

* `redis.url` - URL of redis (includes port)
* `redis.prime_style` - MUST be "1" or "2"; see Redis Prime section below.
* `redis.timeout.cacert` - INT seconds (default None)
* `redis.timeout.cert` - INT seconds (default None)
* `redis.timeout.pkey` - INT seconds (default None)
* `redis.timeout.domain` - INT seconds (default None)


# tools

## invoke script

there is an `invoke` script in the `tools` directory that can be used to automate certain tasks.

right now the invoke script offers:

`import_letsencrypt_certs_archive` given a directory of your local LetsEncrypt archive (which has versioned certs), it will import them all into a server of your choice.


## commandline interface

You can interact with this project via a commandline interface in several ways.

* run a webserver instance and query JSON urls
* run explicit routes via `prequest`. this allows you to do admin tasks without spinnig up a server

## openresty/nginx lua script

`tools.ssl_lookup.lua` is an script that can be used in an openresty/nginx environment to select a SSL cert

It supports both prime 1 & prime 2 cache types, but you'll need to manually edit it (or PR a better solution)

look for this line:

	-- actually query redis
	cert, key = prime_2__query_redis(redcon, server_name)

and just change it to 

	cert, key = prime_1__query_redis(redcon, server_name)

It is also hardcoded to use db9 in redis.  if you want another option, edit or PR

	ngx.log(ngx.ERR, "changing to db 9: ", times)
	redcon:select(9)

This approach makes aggressive use of caching in the nginx workers (via a shared dict) and redis; and caches both hits and misses.

The nginx worker dicts are shared across reloads (`kill -HUP {PID}`); so if a bad value gets in there you must restart or wait for the timeout.

The logic in pseudocode:

	# grab certs
	(key, fullchain) = cert_cache.get(domain)
	if all((key, fullchain)):
		if (key == 'x') or (fullchain == 'x'):
			# default cert is still active
			return
	else:
		(key, fullchain) = redis.get(domain)
		# redis is a write-through cache
		if all((key, fullchain)):
			cert_cache.set(domain, key, fullchain)
		else:
			# mark domain invalid		
			cert_cache.set(domain, 'x', 'x')
			# default cert is still active
			return
	ssl.clear_certs()
	ssl.set_der_cert(cert)
	ssl.set_der_priv_key(key)


### prequest

`$VENV/bin/prequest development.ini /.well-known/admin/operations/ca_certificate_probes/probe.json`


### Routes Designed for JSON Automation


#### `/.well-known/admin/operations/ca_certificate_probes/probe.json`

Probes known URLs of LetsEncrypt keys and saves them with the correct role information.

If the keys were previously discovered during a signing process, it will decorate the existing records with the role data.

#### `/.well-known/admin/operations/deactivate_expired.json`

Deactivates expired certs

#### `/.well-known/admin/operations/redis/prime.json`

Primes a redis cache with domain data.

#### `/.well-known/admin/operations/update_recents.json`

Updates domain records to list the most recent certificate for the domain


### Routes with JSON support

several routes have support for JSON requests via a `.json` suffix.

these are usually documented on the html version

#### `/.well-known/admin/certificate/upload.json`

This can be used used to directly import certs issued by LetsEncrypt

	curl --form "private_key_file=@privkey1.pem" --form "certificate_file=@cert1.pem" --form "chain_file=@chain1.pem" http://127.0.0.1:6543/.well-known/admin/certificate/upload.json

	curl --form "private_key_file=@privkey2.pem" --form "certificate_file=@cert2.pem" --form "chain_file=@chain2.pem" http://127.0.0.1:6543/.well-known/admin/certificate/upload.json
	
Note that the url is not `/upload` like the html form but `/upload.json`

Both URLS accept the same form data, but `/upload.json` returns json data that is probably more readable from the commandline

Errors will appear in JSON if encountered.

if data is not POSTed to the form, instructions are returned in the json.

There is even an `invoke` script to automate these imports:

	invoke import_letsencrypt_certs_archive --archive-path='/path/to/archive' --server-url-root='http://127.0.0.1:6543'


#### `/.well-known/admin/ca_certificate/upload.json`

Upload a new LetsEncrypt certificate.

`uplaod_bundle` is preferred as it provides better tracking.


#### `/.well-known/admin/ca_certificate/upload_bundle.json`

Upload a new LetsEncrypt certificate with a known role.


#### `/.well-known/admin/domain/{DOMAIN|ID}/config.json` Domain Data

`{DOMAIN|ID}` can be the internal numeric id or the domain name.

will return a JSON document:

    {"domain": {"id": "1",
                "domain_name": "a",
                },
     "latest_certificate_single": null,
     "latest_certificate_multi": {"id": "1",
                                  "private_key": {"id": "1",
                                                  "pem": "a",
                                                  },
                                  "certificate": {"id": "1",
                                                  "pem": "a",
                                                  },
                                  "chain": {"id": "1",
                                            "pem": "a",
                                            },
                                  "fullchain": {"id": "1",
                                                "pem": "a",
                                                },
                                  }
     }

if you pass in the querystring '?idonly=1', the PEMs will not be returned.

notice that the numeric ids are returned as strings. this is by design.


#### `/.well-known/admin/certificate/{ID}/config.json` Certificate Data

The certificate JSON payload is what is nested in the DOMAIN payload

    {"id": "1",
     "private_key": {"id": "1",
                     "pem": "a",
                     },
     "certificate": {"id": "1",
                     "pem": "a",
                     },
     "chain": {"id": "1",
               "pem": "a",
               },
     "fullchain": {"id": "1",
                   "pem": "a",
                   },
     }

notice that the numeric ids are returned as strings. this is by design.

Need to get the cert data directly? NO SWEAT. transforms on the server and sent to you with the appropriate headers.

* /.well-known/admin/certificate/{ID}/cert.crt
* /.well-known/admin/certificate/{ID}/cert.pem
* /.well-known/admin/certificate/{ID}/cert.pem.txt
* /.well-known/admin/certificate/{ID}/chain.cer
* /.well-known/admin/certificate/{ID}/chain.crt
* /.well-known/admin/certificate/{ID}/chain.der
* /.well-known/admin/certificate/{ID}/chain.pem
* /.well-known/admin/certificate/{ID}/chain.pem.txt
* /.well-known/admin/certificate/{ID}/fullchain.pem
* /.well-known/admin/certificate/{ID}/fullchain.pem.txt
* /.well-known/admin/certificate/{ID}/privkey.key
* /.well-known/admin/certificate/{ID}/privkey.pem
* /.well-known/admin/certificate/{ID}/privkey.pem.txt


# FAQ

## Does this reformat certs?

Yes. PEM certs are reformatted to have a single trailing newline (via stripping then padding the input). This seems to be one of the more common standards people have for saving certs. Otherwise certs are left as-is.

## Is there a fast way to import existing certs?

Yes. Use `curl` on the commandline. see the TOOLS section	

## What happens if multiple certs are available for a domain ?

Multiple Domains on a cert make this part of management epically & especially annoying.

The current solution is quick and dirty:

* there is a an "operation" hook that caches the most-recent "multi" and "single" cert for every domain
* certificates will not be deactivated if they are the most-recent used multi or single cert for any domain.

This means that a cert will stay active so long as any domain has not yet-replaced it.

When querying for a domain's cert, the system will currently send the most recent cert. a future feature might allow for this to be customized, and show the most widely usable cert.

## Why use openssl? / does this work on windows?

It was much easier to peg this to `openssl` in a linux environment for now; which rules out windows.

In the future this could all be done with Python's crypto library. However openssl is fast and this was primarily designed for dealing with linux environments. sorry.

## Where does data come from?

When imported, certs are read into text form and parsed.

When generated via acme, cert data is provided in the headers.

Useful fields are duplicated from the cert into SQL to allow for better searching. Certs are not changed in any way (aside from whitespace cleanup)


# misc tips

So far this has been tested behind a couple of load balancers that use round-robin dns. They were both in the same physical network.

* nginx is on port 80. everything in the /.well-known directory is proxied to an internal machine *which is not guaranteed to be up*
* this service is only spun up when certificate management is needed
* /.well-known/admin is not on the public internet



# redis support

The first version of support for redis caching is done.

there are several config options for redis support, they are listed above.

## redis priming style

currently only `redis.prime_style = 1` and `redis.prime_style = 2` are supported.

### prime_style = 1

this prime style will store data into redis in the following format:

* `d:{DOMAIN_NAME}` a 3 element hash for ServerCertificate (c), PrivateKey (p), CACertificate (i). note it has a leading colon.
* `c{ID}` the ServerCertificate in PEM format; (c)ert
* `p{ID}` the PrivateKey in PEM format; (p)rivate
* `i{ID}` the CACertificate in PEM format; (i)ntermediate cert

the redis datastore might look something like this:

	r['d:foo.example.com'] = {'c': '1', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
	r['d:foo2.example.com'] = {'c': '2', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
	r['c1'] = CERT.PEM  # (c)ert
	r['c2'] = CERT.PEM
	r['p2'] = PKEY.PEM  # (p)rivate
	r['i99'] = CACERT.PEM  # (i)ntermediate cert
	
to assemble the data for `foo.example.com`:

* (c, p, i) = r.hmget('d:foo.example.com', 'c', 'p', 'i')
** returns {'c': '1', 'p': '1', 'i': '99'}
* cert = r.get('c1')
* pkey = r.get('p1')
* chain = r.get('i99')
* fullchain = cert + "\n" + chain

### prime_style = 2

this prime style will store data into redis in the following format:

* `{DOMAIN_NAME}` a 2 element hash for FullChain [ServerCertificate+CACertificate] (f), PrivateKey (p)

the redis datastore might look something like this:

	r['foo.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}
	r['foo2.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}


## search expiring soon

## expire nginx worker cache

After priming redis with new data, one should be able to hit an nginx route that expires the shared cache

## update objects

account keys:
* timestamp last cert issue
* timestamp last csr
* count certs
* count issues

## api hooks

in the meantime, `curl` can be used to trigger normal requests

## upload CERT/Chains for 'flow' CSR

## associate all objects to one another when imported

only some objects are currently associated

## full unit tests

This is still sketching out the idea.
this is not ready for production yet.
i'm personally using it, but the API is not stable and tests are not integrated.


## Database Docs

If using postgresql...

	create user letsencrypt_admin with password 'le_admin';
	create database letsencrypt_admin with owner letsencrypt_admin ;
	
	change the config settings



Getting Started
---------------

- cd <directory containing this file>

- $VENV/bin/python setup.py develop

- $VENV/bin/initialize_pyramid_letsencrypt_admin_db development.ini

- $VENV/bin/pserve development.ini


Import Letsencrypt Data?
-------------------------

after running the server, in another window...

- $VENV/bin/pip install invoke

- cd tools

- $VENV/bin/invoke import_letsencrypt_certs_archive --archive-path='//etc/letsencrypt/archive' --server-url-root='http://http://127.0.0.1:6543'


There is also a button under "operations" to probe LetsEncrypt's public website and update your certs with data.


What does it look like?
---------------

It uses bootstrap.

![Admin Index](https://raw.github.com/jvanasco/pyramid_letsencrypt_admin/master/docs/images/01-admin_index.png)
![Enter Domains](https://raw.github.com/jvanasco/pyramid_letsencrypt_admin/master/docs/images/02-enter_domains.png)
![Enter Challenges](https://raw.github.com/jvanasco/pyramid_letsencrypt_admin/master/docs/images/03-enter_challenge.png)
![Check Status](https://raw.github.com/jvanasco/pyramid_letsencrypt_admin/master/docs/images/04-view_status.png)
