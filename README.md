peter_sslers README
================================

Peter SSLers *or how i stopped worrying and learned to love the ssl certificate*.

`peter_sslers` is a package designed to help *experienced* admins and devops people manage SSL Certificates and deploy them on larger systems.

This package is *not* aimed at casual or single-site users.  This package is *not* aimed at novice users.

Peter offers lightweight tools to centrally manage SSL Certificate data in a SQL database of your choice.

Peter combines an ACME client designed to operate against the LetsEncrypt service, alongside tools designed to manage & deploy certificates.

Peter's core tool is a lightweight database-backed `Pyramid` application that can:

* act as a client for the entire "LetsEncrypt" issuance process, operating behind a proxied webserver
* import existing ssl certificates
* ease provisioning certificates onto various servers
* browse certificate data and easily see what needs to be renewed
* communicate with a properly configured openresty enabled `nginx` web server (see next)

Peter ships with a `lua` module for the `openresty` framework on the `nginx` server which will:

* dynamically request certificates from a primed redis cache
* store data in shared `nginx` worker memory and
* expose routes to flush the worker shared memory or expire select keys. 

The `Pyramid` based application can function as a daemon or a commandline script.

Do you like book-keeping?  Peter's `Pryamid` component logs everything into sql.  

Do you like cross-referencing?  Your certs are broken down into fields that are cross-referenced or searchable within Peter as well.

Peter has absolutely no security measures and should only be used by people who understand that (that should be a self-selecting group, because many people won't want this tool).  Peter is a honeybadger, he don't care.  He just takes what he wants.

Peter offers several commandline tools -- so spinning up a tool "webserver" mode may not be necessary at all -- or might only be needed for brief periods of time.

SqlAlchemy is the backing database library, so virtually any database can be used (sqlite, postgres, mysql, oracle, mssql, etc). `sqlite` is the default, but the package has been tested against postgres.  sqlite is actually kind of great, because a single `.sqlite` file can be sftp'd on-to and off-of different machines for distribution and local viewings.

## Why?

Most of us hate having to spend time on DevOps tasks.  Personally, I would rather spend time working on the Product or consumer sides.  This tool was designed as a swiss-army-knife to streamline some tasks and troubleshoot a handful of issues with https hosting.  This is pre-release and still being worked on as it fixes new issues on a production system.  PRs are absolutely welcome, even if just fixes or additions to the test-suite.


# An important WARNING:

* This package DOES NOT USE/KNOW/CARE ABOUT SECURITY.
* This package manages PRIVATE SSL KEYS and makes them readable.
* If you do not known / are not really awesome with basic network security PLEASE DO NOT USE THIS.


# The Components

## "Peter SSLers" - a Pyramid Application

"Peter SSLers" is the core toolkit.  It is a `Pyramid` application that can be spun up as a webserver or used via a commandline interface.  Peter is your friend and handles all of the Certificate Management and translation functions for you.  He's a bit eccentric, but basically a good guy.

## "SSL Minnow" - The Datastore

By default, the "SSL Minnow" is a sqlite database `ssl_minnow.sqlite`.  It is the backing datastore for SSL Certificates and the operations log.  Your data is ONLY saved to the SSL Minnow - not to the filesystem like other LE clients - so you should be careful with it.  If the Minnow would be lost, it can not be recovered.  Be a good skipper, or your three hour tour could end up taking many years and might involve the Harlem Globetrotters.

## "Tools"

The "/tools" directory contains scripts useful for certificate operations.  Currently this includes:

* an `invoke` script for some miscellaneous tasks
* a `lua` library for integrating with nginx/openresty
* sample `nginx` configuration files for admin, public and testing routes
* a sample `fake_server.py` that will spin up a server with routes that you can test against.  this will allow you to setup your integration without running peter_sslers

# General Management Concepts

## Input

1. An admin dashboard allows you to upload certificates (in a triplet of Cert, Signing Key, CA-Chain)
2. An admin dashboard allows you to initiate LetsEncrypt certificate signing. Upload a list of domains, your LetsEncrypt account key, and private key used for signing/serving, and the system will generate the CSR and perform all the verifications.
3. A public interface allows you to proxypass the acme-challenges that LetsEncrypt issues for manual verification. (ie, run this behind nginx)
4. You can run the 'webserver' on a private IP, and `curl` data into it via the commandline or miscellaneous scripts

## Output

1. All the keys & certs are viewable in a wonderfully connected RDMBS browser.
2. Any keys/certs/chains can be queried in PEM & DER formats.
3. All the certificates are checked to track their validity dates, so you can search and re-issue
4. This can "prime" a Redis cache with SSL Cert info in several formats.  A LUA script for OpenResty is included that enables dynamic SSL certs.

## Management

* Everything is in the RDBMS and de-duped.
* chains are built on-the-fly.
* a growing API powers most functionality
* public and admin routes can be isolated in the app & firewall, so you can just turn this on/off as needed
* you can easily see when certificates and/or domains expire and need to be renewed
* if sqlite is your backend, you can just run this for signing and deployment; then handle everything else offline.
* "Admin" and "Public" functions are isolated from each other. By changing the config, you can run a public-only "validation" interface or enable the admin tools that broadcast certificate information.
* the pyramid server can query nginx locations to clear out the shared cache 


# Installation

This is pretty much ready to go for development use.  Python should install everything for you.  If it doesn't, someone screwed up.

You should create a virtualenv for this project. In this example, we will create the following directory structure:

* `certificate_admin` - core page
* `certificate_admin/peter_sslers-venv` - dedicated virtualenv
* `certificate_admin/peter_sslers` - git checkout

Here we go...

	mkdir certificate_admin
	cd certificate_admin

	virtualenv peter_sslers-venv
	source peter_sslers-venv/bin/activate

	git clone https://github.com/aptise/peter_sslers.git
	cd peter_sslers
	python setup.py develop
	initialize_peter_sslers_db development.ini	
	prequest development.ini /.well-known/admin/api/ca-certificate-probes/probe.json
	pserve --reload development.ini
	
Then you can visit `http://127.0.0.1:6543`

Editing the `development.ini` file will let you specify how the package runs.

`Pyramid` applications are based on `.ini` configuration files.  You can use multiple files to deploy the server differently on the same machine, or on different environments.

Some tools are provided to automatically import existing certificates and chains (see below).

It is recommended to open up a new terminal and do the following commands

	cd certificate_admin
	source peter_sslers-venv/bin/activate
	cd peter_sslers
	prequest development.ini /.well-known/admin/api/ca-certificate-probes/probe.json
	cd tools
	invoke import_letsencrypt_certs_archive --archive-path='/etc/letsencrypt/archive' --server-url-root='http://127.0.0.1:6543'

The `prequest` command above will import the current LetsEncrypt certificates to get you started.
The `invoke` command will import existing LetsEncrypt issued certificates


# Implementation Details

The webserver exposes the following routes/directories:

* `/.well-known/acme-challenge` - directory
* `/.well-known/public/whoami` - URL prints host
* `/.well-known/admin` - admin tool IMPORTANT - THIS EXPOSES PRIVATE KEYS ON PURPOSE


# Just a friendly reminder:

THE ADMIN TOOL SHOULD NEVER BE PUBLICLY ACCESSIBLE.
YOU SHOULD ONLY RUN IT ON A PRIVATE NETWORK

By default, the production.ini file won't even run the admin tools.  that is how serious we are about telling you to be careful!


# why/how?

Again, the purpose of this package is to enable certificate management in systems where one or more of the following apply:

* you have a lot of domains
* you have a lot of machines
* your domains resolve to more than one IP address

Imagine you want to issue a certificate for 100 domains, which could be served from any one of 5 machines (load balancers or round-robin dns) and the certificates need to be deployable to all 5 machines.

To solve this you can:

* proxy external ` /.well-known/acme-challenge/` to one or more machines running this tool (they just need to share a common datastore)
* make ` /.well-known/admin` only usable within your LAN or NEVER USABLE
* on a machine within your LAN, you can query for the latest certs for domain(s) using simple `curl` commands

In a more advanced implementation (such as what this was originally designed to manage) the certificates need to be loaded into a `Redis` server for use by an `openresty`/`nginx` webserver/gateway that will dynamically handle ssl certificates.

This package does all the annoying openssl work in terms of building chains and converting formats *You just tell it what domains you need certificates for and in which format and THERE YOU GO.*


# Deployment Concepts

![Network Map: Simple](https://raw.github.com/aptise/peter_sslers/master/docs/assets/network_map-01.png)

PeterSSlers can run as a standalone service OR proxied behind nginx/apache/etc

The SSLMinnow datastore is entirely separate and standalone.  It is portable.

![Network Map: Configure](https://raw.github.com/aptise/peter_sslers/master/docs/assets/network_map-02.png)

In order to make network configuration more simple, the package includes a "fake server" that includes routes for the major public and admin endpoints. This should support most integration tests. 

![Network Map: Advanced](https://raw.github.com/aptise/peter_sslers/master/docs/assets/network_map-03.png)

In an advanced setting, multiple servers proxy to multiple peter-sslers "public" instances.

The instances share a single SSLMinnow data store.

The "Admin" tool runs on the private intranet.


# notes

## Certificate/Key Translations

Certificates and Keys are stored in the PEM format, but can be downloaded in the DER format if needed.

There are several ways to download each file. Different file suffix will change the format and headers.

Peter shows you buttons for available formats on each page.

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

### Account/Domain Keys

	key.pem 		PEM		application/x-pem-file
	key.pem.txt		PEM		text/plain
	key.key 		DER		application/pkcs8

### Account/Domain Keys

	key.pem 		PEM		application/x-pem-file
	key.pem.txt		PEM		text/plain
	key.key 		DER		application/pkcs8


# Configuration options

Your `environment.ini` exposes a few configuration options:

* `openssl_path` - the full path to your openssl binary (default `openssl`)
* `openssl_path_conf` - the full path to your openssl binary (default `/etc/ssl/openssl.cnf`)

* `certificate_authority` - the LetsEncrypt certificate authority. by default we use their staging URL. you will have to manually put in the real URL as defined on their docs.

* `enable_views_public` - boolean, should we enable the public views?
* `enable_views_admin` - boolean, should we enable the admin views?

* `redis.url` - URL of redis (includes port)
* `redis.prime_style` - MUST be "1" or "2"; see Redis Prime section below.
* `redis.timeout.cacert` - INT seconds (default None)
* `redis.timeout.cert` - INT seconds (default None)
* `redis.timeout.pkey` - INT seconds (default None)
* `redis.timeout.domain` - INT seconds (default None)

* `nginx.reset_servers` - comma(,) separated list of servers with an expiry route; see Redis Prime section below
* `nginx.reset_path` - defaults to `/ngxadmin/shared_cache/expire`
* `requests.disable_ssl_warning` - will disable the ssl warnings from the requests library

If you have a custom openssl install, you probably want these settings

	openssl_path = /opt/openssl/bin/openssl
	openssl_path_conf = /usr/local/ssl/openssl.cnf

These options are used by the server AND by the test suite.

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

`tools/nginx_lua_library` is a library that can be used in an openresty/nginx environment to dynamically serve the correct SSL certificate for a given domain.

It supports both the prime cache types 1 & 2.

It is implemented as a library with 2 scripts that invoke it.

* `ssl_certhandler.lua`
* `ssl_certhandler-lookup.lua`
* `ssl_certhandler-expire.lua`

The `-lookup.lua` and `-expire.lua` scripts can set via `_by_lua_file` or copied into a block.  

The library is hardcoded to use db9 in redis.  if you want another option, edit or PR a fix on the line that looks like:

	ngx.log(ngx.ERR, "changing to db 9: ", times)
	redcon:select(9)
	
Redis is NOT required, but recommended.  Instead you can failover to directly query a peter_sslers pyramid instance.

To use the Peter fallback, you must install this lua-resty library:

* lua-resty-http https://github.com/pintsized/lua-resty-http

The demo expects this to be installed into tools/lua-lib

example:

	cd tools
	mkdir lua-lib
	cd lua-lib
	git checkout https://github.com/pintsized/lua-resty-http.git

Hits and misses from the fallback API will be cached in the shared cache dict.  If you need to remove values, you will need to restart the server OR use one of the nginx/lua examples for cache clearing.  Fallback API requests will notify the Pyramid app that the request should have write-through cache behavior.


### ssl_certhandler.lua

Core library.  Exposes several functions.

Make sure your nginx contains:

    server {
		init_by_lua 'require "resty.core"';
	    lua_shared_dict cert_cache 1m;
	}


### ssl_certhandler-lookup.lua

This is very simple, it merely specfies a cache, duration, and prime_version

	local ssl_certhandler = require "ssl_certhandler"

	-- Local cache related
	local cert_cache = ngx.shared.cert_cache
	local cert_cache_duration = 7200 -- 2 hours

	local prime_version = 1
    local fallback_server = 'http://0.0.0.0:6543'
	ssl_certhandler.set_ssl_certificate(cert_cache, cert_cache_duration, prime_version, fallback_server)

	return

invoked within nginx...

    server {
        listen 443 default_server;
        ...
		ssl_certificate_by_lua_file /path/to/ssl_certhandler-lookup.lua;
	}


### ssl_certhandler-expire.lua

The nginx shared memory cache persists across configuration reloads.  Servers must be fully restarted to clear memory.

The workaround?  API endpoints to "flush" the cache or expire certain keys(domains):

	local ssl_certhandler = require "ssl_certhandler"

	-- Local cache related
	local cert_cache = ngx.shared.cert_cache

	ssl_certhandler.expire_ssl_certs(cert_cache)

invoked within nginx

    server {
        listen 443 default_server;
        ...
	    location /ngxadmin/shared_cache/expire {
			content_by_lua_file /path/to/ssl_certhandler-expire.lua;
	    }
	}
	
This creates the following routes:

* `/ngxadmin/shared_cache/expire/all`
** Flushes the entire nginx certificate cache
* `/ngxadmin/shared_cache/expire/domain/{DOMAIN}`
** Flushes the domain's pkey & chain entires in the certificate cache

On success, these routes return JSON in a HTTP-200-OK document.

* {"result": "success", "expired": "all"}
* {"result": "success", "expired": "domain", "domain": "{DOMAIN}"}
* {"result": "error", "expired": "None", "reason": "Unknown URI"}

On error, these routes should generate a bad status code.

The Pyramid component can query these endpoints automatically for you.

### Details

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


## prequest

you can use the prequest syntax to spin up a URL and get or post data

`$VENV/bin/prequest development.ini /.well-known/admin/api/ca-certificate-probes/probe.json`
`$VENV/bin/prequest development.ini /.well-known/admin/api/redis/prime.json`


## Routes Designed for JSON Automation


### `/.well-known/admin/api/ca-certificate-probes/probe.json`

Probes known URLs of LetsEncrypt keys and saves them with the correct role information.

If the keys were previously discovered during a signing process, it will decorate the existing records with the role data.

### `/.well-known/admin/api/deactivate-expired.json`

Deactivates expired certs

### `/.well-known/admin/api/redis/prime.json`

Primes a redis cache with domain data.

### `/.well-known/admin/api/update-recents.json`

Updates domain records to list the most recent certificate for the domain


## Routes with JSON support

several routes have support for JSON requests via a `.json` suffix.

these are usually documented on the html version

### `/.well-known/admin/certificate/upload.json`

This can be used used to directly import certs issued by LetsEncrypt

	curl --form "private_key_file=@privkey1.pem" --form "certificate_file=@cert1.pem" --form "chain_file=@chain1.pem" http://127.0.0.1:6543/.well-known/admin/certificate/upload.json

	curl --form "private_key_file=@privkey2.pem" --form "certificate_file=@cert2.pem" --form "chain_file=@chain2.pem" http://127.0.0.1:6543/.well-known/admin/certificate/upload.json
	
Note that the url is not `/upload` like the html form but `/upload.json`

Both URLS accept the same form data, but `/upload.json` returns json data that is probably more readable from the commandline

Errors will appear in JSON if encountered.

if data is not POSTed to the form, instructions are returned in the json.

There is even an `invoke` script to automate these imports:

	invoke import_letsencrypt_certs_archive --archive-path='/path/to/archive' --server-url-root='http://127.0.0.1:6543'


### `/.well-known/admin/ca-certificate/upload.json`

Upload a new LetsEncrypt certificate.

`uplaod_bundle` is preferred as it provides better tracking.


### `/.well-known/admin/ca-certificate/upload-bundle.json`

Upload a new LetsEncrypt certificate with a known role.


### `/.well-known/admin/domain/{DOMAIN|ID}/config.json` Domain Data

`{DOMAIN|ID}` can be the internal numeric id or the domain name.

will return a JSON document:

    {"domain": {"id": "1",
                "domain_name": "a",
                },
     "server_certificate__latest_single": null,
     "server_certificate__latest_multi": {"id": "1",
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

if you pass in the querystring '?openresty=1' to identify the request as coming from openresty (as an api request), this will function as a write-through cache for redis and load the domain's info into redis (if redis is configured)


### `/.well-known/admin/certificate/{ID}/config.json` Certificate Data

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

Need to get the cert data directly? NO SWEAT. Peter transforms this for you on the server, and sends it to you with the appropriate headers.

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

Yes. Use `curl` on the commandline. see the TOOLS section for an `invoke` script that can automate many certificates from the Letsencrypt Store.


## What happens if multiple certs are available for a domain ?

Multiple Domains on a cert make this part of management epically & especially annoying.

The current solution:

* there is a an API endpoint to cache the most-recent "multi" and "single" cert for every domain onto the domain's record (update-recents)
* certificates *will not* be deactivated if they are the most-recent "multi" or "single" cert for any one domain.

This means that a cert will stay active so long as any one domain has not yet-replaced it.

When querying for a domain's cert, the system will currently send the most recent cert. a future feature might allow for this to be customized, and show the most widely usable cert.

## Why use openssl directly? / does this work on windows?

It was much easier to peg this to `openssl` in a linux environment for now; which rules out windows.

In the future this could all be done with Python's crypto library. However openssl is fast and this was primarily designed for dealing with linux environments. sorry.

If someone wants to make a PR to make this fully python based... ok!


## Where does the various data come from?

When imported, certificates are read into "text" form and parsed for data.

When generated via the acme protocol, certificate data is provided in the headers.

Useful fields are duplicated from the certificate into SQL to allow for better searching. Certificates are not changed in any way (aside from whitespace cleanup).


# Misc tips

So far this has been tested behind a couple of load balancers that use round-robin dns. They were both in the same physical network.

* nginx is on port 80. everything in the `/.well-known directory` is proxied to an internal machine *which is not guaranteed to be up*
* this service is only spun up when certificate management is needed
* `/.well-known/admin` is not on the public internet

For testing certificates, these 2 commands can be useful:

reprime Redis cache

	$ prequest development.ini /.well-known/admin/api/redis/prime.json

clear out nginx cache

	curl -k -f https://127.0.0.1/ngxadmin/shared_cache/expire/all	

the `-k` will keep the cert from verifying, the `-f` wont blow up from errors

# Redis support

There are several `.ini` config options for Redis support, they are listed above.

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


# Tests

To keep things simple, tests are run using unittest.

    python setup.py test

There are a few environment variables you can set:

	# run tests that hit nginx for cache clearing
	export SSL_RUN_NGINX_TESTS=True

	# run tests that hit redis for cache priming
	export SSL_RUN_REDIS_TESTS=True

	# run tests that hit the LetsEncryptAPI
	export SSL_RUN_LETSENCRYPT_API_TESTS=True

	# Set TRUE if you expect the LE API verificaiton to fail
	# this is desired right now, because it's rather complicated to set up a -
	# - test suite that responds to public requests
	export SSL_LETSENCRYPT_API_VALIDATES=True

Tests are done on a sqlite database as specified in test.ini

The test.ini should also reflect the openssl for your distribution

`test_data/` contains the keys and certificates used for testing

You can overwrite the testdb; beware that it CAN NOT run as a memory db.  it must be a disk file due to how some tests are written.


Gotchas
-------

This requires a relatively new version of openssl to handle multiple-domain certificates.



Getting Started
---------------

- cd <directory containing this file>

- $VENV/bin/python setup.py develop

- $VENV/bin/initialize_peter_sslers_db development.ini

- $VENV/bin/pserve development.ini


Import Letsencrypt Data?
-------------------------

after running the server, in another window...

- $VENV/bin/pip install invoke

- cd tools

- $VENV/bin/invoke import_letsencrypt_certs_archive --archive-path='/etc/letsencrypt/archive' --server-url-root='http://127.0.0.1:6543'


There is also a button under "operations" to probe LetsEncrypt's public website and update your certs with data.


What does it look like?
---------------

It uses bootstrap.

![Admin Index](https://raw.github.com/aptise/peter_sslers/master/docs/images/01-admin_index.png)
![CSR: Automate 'manual': Enter Domains](https://raw.github.com/aptise/peter_sslers/master/docs/images/02-enter_domains.png)
![CSR: Automate 'manual': Enter Challenges](https://raw.github.com/aptise/peter_sslers/master/docs/images/03-enter_challenge.png)
![CSR: Check Verification Status](https://raw.github.com/aptise/peter_sslers/master/docs/images/04-view_status.png)
![CSR: New FULL](https://raw.github.com/aptise/peter_sslers/master/docs/images/09-new_csr.png)
![Operations Log](https://raw.github.com/aptise/peter_sslers/master/docs/images/05-operations_log.png)
![List: Authority Certificates](https://raw.github.com/aptise/peter_sslers/master/docs/images/06-ca_certificates.png)
![Focus: Authority Certificate](https://raw.github.com/aptise/peter_sslers/master/docs/images/07-ca_certificates_focus.png)
![Upload Existing Certificates](https://raw.github.com/aptise/peter_sslers/master/docs/images/10-upload_cert.png)
![List Certificates](https://raw.github.com/aptise/peter_sslers/master/docs/images/11-certificates_list.png)
![List Domains](https://raw.github.com/aptise/peter_sslers/master/docs/images/12-domains_list.png)
