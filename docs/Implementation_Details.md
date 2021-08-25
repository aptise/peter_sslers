* [Previous - General_Management_Concepts](https://github.com/aptise/peter_sslers/docs/General_Management_Concepts.md)
* [Next - Automation](https://github.com/aptise/peter_sslers/docs/Automation.md)

# Implementation Details

The webserver exposes the following routes/directories:

* `/.well-known/acme-challenge` - directory
* `/.well-known/public/whoami` - URL prints host
* `/.well-known/admin` - admin tool IMPORTANT - THIS EXPOSES PRIVATE KEYS ON PURPOSE

The server will respond to requests with the following header to identify it:

    X-Peter-SSLers: production



# Just a friendly reminder:

THE ADMIN TOOL SHOULD NEVER BE PUBLICLY ACCESSIBLE.
YOU SHOULD ONLY RUN IT ON A PRIVATE NETWORK

By default, the `example_production.ini` file won't even run the admin tools.
That is how serious we are about telling you to be careful!


# why/how?

Again, the purpose of this package is to enable Certificate management in systems
where one or more of the following apply:

* you have a lot of Domains
* you have a lot of machines
* your Domains resolve to more than one IP address

Imagine you want to issue a Certificate for 100 Domains, which could be served from
any one of 5 machines (load balancers or round-robin dns) and the Certificates need
to be deployable to all 5 machines.

To solve this you can:

* proxy external ` /.well-known/acme-challenge/` to one or more machines running
  this tool (they just need to share a common datastore)
* make ` /.well-known/admin` only usable within your LAN or NEVER USABLE
* on a machine within your LAN, you can query for the latest certs for Domain(s)
  using simple `curl` commands

In a more advanced implementation (such as what this was originally designed to
manage) the Certificates need to be loaded into a `Redis` server for use by an
`OpenResty`/`Nginx` webserver/gateway that will dynamically handle SSL Certificates.

In a simple example, `OpenResty`/`Nginx` will query
`/.well-known/admin/domain/example.com/config.json` to pull the active Certificate
information for a Domain. In advanced versions, that Certificate information will
be cached into multiple levels of `OpenResty`/`Nginx` and `Redis` using different
optimization strategies.

This package does all the annoying openssl work in terms of building chains and
converting formats *You just tell it what Domains you need Certificates for and
in which format AND THERE YOU GO.*


# Deployment Concepts

![Network Map: Simple](https://raw.github.com/aptise/peter_sslers/main/docs/assets/network_map-01.png)

PeterSSlers can run as a standalone service OR proxied behind `Nginx`/`Apache`/etc

The SSLMinnow datastore is entirely separate and standalone. It is portable.

![Network Map: Configure](https://raw.github.com/aptise/peter_sslers/main/docs/assets/network_map-02.png)

In order to make network configuration more simple, the package includes a "fake
server" that includes routes for the major public and admin endpoints. This should
support most integration test needs.

![Network Map: Advanced](https://raw.github.com/aptise/peter_sslers/main/docs/assets/network_map-03.png)

In an advanced setting, multiple servers proxy to multiple peter-sslers "public"
instances.

The instances share a single SSLMinnow data store.

The "Admin" tool runs on the private intranet.


# Notes

## Certificate/Key Translations

Certificates and Keys are stored in the PEM format, but can be downloaded in the
DER format if needed.

There are several ways to download each file. Different file suffix will change
the format and headers.

Peter shows you buttons for available formats on each page.

### CertificateSigned

The Certificate Itself:

    cert.pem            PEM     application/x-pem-file
    cert.pem.txt        PEM     text/plain
    cert.cer            DER     application/pkix-cert
    cert.crt            DER     application/x-x509-server-cert
    cert.der            DER     application/x-x509-server-cert

The Certificate Chain:

    chain.pem           PEM     application/x-pem-file
    chain.pem.txt       PEM     text/plain

The Certificate Fullchain

    fullchain.pem       PEM     application/x-pem-file
    fullchain.pem.txt   PEM     text/plain

### CertificateCA

The CertificateAuthority's Certificate:

    cert.pem            PEM     application/x-pem-file
    cert.pem.txt        PEM     text/plain
    cert.cer            DER     application/pkix-cert
    cert.crt            DER     application/x-x509-ca-cert
    cert.der            DER     application/x-x509-ca-cert

### CertificateCAChain

One or more CertificateAuthority Certificates

    chain.pem           PEM     application/x-pem-file
    chain.pem.txt       PEM     text/plain

### CertificateRequest

    csr.pem             PEM     application/x-pem-file
    csr.pem.txt         PEM     text/plain
    csr.csr             PEM     application/pkcs10

### Account/Domain Keys

    key.pem             PEM     application/x-pem-file
    key.pem.txt         PEM     text/plain
    key.key             DER     application/pkcs8

### Account/Domain Keys

    key.pem             PEM     application/x-pem-file
    key.pem.txt         PEM     text/plain
    key.key             DER     application/pkcs8


# Configuration options

Your `environment.ini` exposes a few configuration options.

These are documented at-length on the in-app settings page.

* `openssl_path` - the full path to your openssl binary (default `openssl`)
* `openssl_path_conf` - the full path to your openssl binary (default `/etc/ssl/openssl.cnf`)

* `certificate_authority` - the LetsEncrypt CertificateAuthority. by default we
  use their staging URL. you will have to manually put in the real URL as defined on
  their docs. You can also use the string "pebble" or "custom" to enable local testing.
* `certificate_authority_agreement` - the LetsEncrypt agreement URL used when
  creating new accounts. Everything will probably fail if you don't include this argument.
* `certificate_authority_endpoint` - ACME v1; if `certificate_authority=custom` or
  `certificate_authority=pebble`, you must supply a url for the endpoint
* `certificate_authority_directory` - ACME v2; if `certificate_authority=custom` or
  `certificate_authority=pebble`, you must supply a url for the directory endpoint

* `cleanup_pending_authorizations` - boolean, default True. if an AcmeChallenge
  fails when processing an AcmeOrder, should the remaining AcmeAuthorizations be deactivated?

* `enable_views_public` - boolean, should we enable the public views?
* `enable_views_admin` - boolean, should we enable the admin views?
* `enable_acme_flow` - boolean, should we enable the ACME-flow tool?

* `redis.url` - URL of `Redis` (includes port)
* `redis.prime_style` - MUST be "1" or "2"; see `Redis` Prime section below.
* `redis.timeout.certca` - INT seconds (default None)
* `redis.timeout.cert` - INT seconds (default None)
* `redis.timeout.pkey` - INT seconds (default None)
* `redis.timeout.domain` - INT seconds (default None)

* `nginx.servers_pool` - comma(,) separated list of servers with an expiry route;
  see `Redis` Prime section below
* `nginx.userpass` - http authhentication (username:password) which will be provided
  to each server in `nginx.servers_pool`
* `nginx.reset_path` - defaults to `/.peter_sslers/nginx/shared_cache/expire`
* `nginx.status_path` - defaults to `/.peter_sslers/nginx/shared_cache/status`
* `requests.disable_ssl_warning` - will disable the ssl warnings from the requests
  library

* `admin_server` (optional) defaults to `HTTP_HOST`
* `admin_prefix` (optional) prefix for the admin tool. defaults to `/.well-known/admin`
* `admin_url` (optional) used for display in instructions. If omitted,
  scheme+server+prefix will be used.

If you have a custom openssl install, you probably want these settings

    openssl_path = /usr/local/bin/openssl
    openssl_path_conf = /usr/local/ssl/openssl.cnf

These options are used by the server AND by the test suite.

# Tools

## `invoke` Script

There is an `invoke` script in the `tools` directory that can be used to automate
certain tasks.

Right now the invoke script offers:

* `import-certbot-certs-archive` given a directory of your local LetsEncrypt archive
  (which has versioned certs), it will import them all into a server of your choice.
* `import-certbot-certs-live` given a directory of your local LetsEncrypt install, it
  will import the active onesinto a server of your choice.
* `import-certbot-cert-version` given a specific directory of your LetsEncrypt archive,
  it will import specific items
* `import-certbot-cert-plain` given a directory of an unversioned Certificate (like a
  particular directory within the "live" directory), will import it.

* `import-certbot-account` import a specific LetsEncrypt account
* `import-certbot-accounts-server` import all accounts for a LetsEncrypt server
  (i.e. v1, v1-staging)
* `import-certbot-accounts-all` import all accounts for all LetsEncrypt servers


## Commandline Interface

You can interact with this project via a commandline interface in several ways.

* Run a webserver instance and query JSON urls or use a browser like lynx.
* Run explicit routes via `prequest`. This allows you to do admin tasks without
  spinnig up a server.


## `OpenResty`/`Nginx` Lua integration

The `OpenResty`/`Nginx` implementation was migrated to a dedicated sibling repository,
handled by `opm` distribution.

https://github.com/aptise/lua-resty-peter_sslers

    opm get lua-resty-peter_sslers


## prequest

You can use Pyramid's `prequest` syntax to spin up a URL and GET/POST data

`$VENV/bin/prequest -m POST example_development.ini /.well-known/admin/api/redis/prime.json`

Using `prequest` is recommended in most contexts, because it will not timeout.
This will allow for long-running processes.


## Routes Designed for JSON Automation


### `/.well-known/admin/api/deactivate-expired.json`

Deactivate expired Certificates.

### `/.well-known/admin/api/redis/prime.json`

Prime a `Redis` cache with Domain data.

### `/.well-known/admin/api/update-recents.json`

Updates Domain records to list the most recent Certificates for the Domain.


## Routes with JSON support

Most routes have support for JSON requests via a `.json` suffix.

These are usually documented on the html version, and via "GET" requests to the
json version.

### `/.well-known/admin/certificate-signed/upload.json`

This can be used used to directly import Certificates already issued by LetsEncrypt

    curl --form "private_key_file=@privkey1.pem" \
         --form "certificate_file=@cert1.pem" \
         --form "chain_file=@chain1.pem" \
         http://127.0.0.1:7201/.well-known/admin/certificate-signed/upload.json

    curl --form "private_key_file=@privkey2.pem" \
         --form "certificate_file=@cert2.pem" \
         --form "chain_file=@chain2.pem" \
         http://127.0.0.1:7201/.well-known/admin/certificate-signed/upload.json

Note the url is not `/upload` like the html form but `/upload.json`.

Both URLS accept the same form data, but `/upload.json` returns json data which
is probably more readable from the commandline.

Errors will appear in JSON if encountered.

If data is not POSTed to the form, instructions are returned in the json.

There is an `invoke` script to automate these imports:

    invoke import-certbot-certs-archive \
           --archive-path='/path/to/archive' \
           --server-url-root='http://127.0.0.1:7201/.well-known/admin'

    invoke import-certbot-cert-version \
           --domain-certs-path="/path/to/ssl/archive/example.com" \
           --certificate-version=3 \
           --server-url-root="http://127.0.0.1:7201/.well-known/admin"

    invoke import-certbot-certs-live \
           --live-path='/etc/letsencrypt/live' \
           --server-url-root='http://127.0.0.1:7201/.well-known/admin'

    invoke import-certbot-cert-plain \
           --cert-path='/etc/letsencrypt/live/example.com' \
           --server-url-root='http://127.0.0.1:7201/.well-known/admin'


### `/.well-known/admin/certificate-ca/upload-cert.json`

Upload a new CertificateAuthority (LetsEncrypt) Certificate.

### `/.well-known/admin/certificate-ca-chain/upload-chain.json`

Upload a new CertificateAuthority (LetsEncrypt) Chain.  A chain are the
intermediate certificates.

### `/.well-known/admin/domain/{DOMAIN|ID}/config.json` Domain Data

`{DOMAIN|ID}` can be the internal numeric id or the Domain name.

Will return a JSON document:

    {"domain": {"id": "1",
                "domain_name": "a",
                },
     "certificate_signed__latest_single": null,
     "certificate_signed__latest_multi": {"id": "1",
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

If you pass in the querystring '?idonly=1', the PEMs will not be returned.

Notice that the numeric ids are returned as strings. This is by design.

If you pass in the querystring '?openresty=1' to identify the request as coming
from `OpenResty` (as an API request), this will function as a write-through cache
for `Redis` and load the Domain's info into `Redis` (if `Redis` is configured).

This is the route use by the `OpenResty` Lua script to query Domain data.

### `/.well-known/admin/certificate/{ID}/config.json` Certificate Data

The certificate JSON payload is what is nested in the Domain payload

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

Notice that the numeric ids are returned as strings. This is by design.

Need to get the Certificate data directly? NO SWEAT. Peter transforms this for you
on the server, and sends it to you with the appropriate headers.

* /.well-known/admin/certificate-signed/{ID}/cert.crt
* /.well-known/admin/certificate-signed/{ID}/cert.pem
* /.well-known/admin/certificate-signed/{ID}/cert.pem.txt
* /.well-known/admin/certificate-signed/{ID}/chain.cer
* /.well-known/admin/certificate-signed/{ID}/chain.crt
* /.well-known/admin/certificate-signed/{ID}/chain.der
* /.well-known/admin/certificate-signed/{ID}/chain.pem
* /.well-known/admin/certificate-signed/{ID}/chain.pem.txt
* /.well-known/admin/certificate-signed/{ID}/fullchain.pem
* /.well-known/admin/certificate-signed/{ID}/fullchain.pem.txt
* /.well-known/admin/certificate-signed/{ID}/privkey.key
* /.well-known/admin/certificate-signed/{ID}/privkey.pem
* /.well-known/admin/certificate-signed/{ID}/privkey.pem.txt


# Workflow Concepts

## Object Attributes

### Domain

#### `is_active`

If a Domain is "active", then it is actively managed and should be included in
ACME Order renewals or generating `Nginx` configuration.

### AcmeOrder

#### `is_auto_renew`

Set to `True` by default. If `True`, this Certificate will be auto-renewed by the
renewal queue. If `False`, renewals must be manual.

### CertificateSigned

#### `is_active`

If a Certificate is "active" (`True` by default) then it is actively managed and
should be included in generating `Nginx` configuration.

#### `is_deactivated` and `is_revoked`

If a certificate is not "active", only one of these will be `True`. If an inactive
certificate was deactivated, then it can be activated and this flag will reverse.
If the certificate was revoked, it is permanent and should not be re-activated.

## Domain Queue

The Domain queue, `/admin/queue-domains`, is designed to allow for Domains to be
"queued in" for later batch processing.

If a Domain is added to the queue, the following logic takes place:

* If the Domain is already managed, but is not `active`, activate it.
* If the Domain is not managed and not in the queue, add it to the queue.
* In all other cases, ignore the request. the Domain is either actively managed
  or queued to be so.


## Renewal Queue

* `update` will calculate which Certificates need to be renewed
* `process` will do the actual renewal

Certificates end up in the renewal queue through the `update` command or being
individually queued.

Certificates can also have a "custom renewal".

To process the queue:

To deal with timeouts and various issues, queue processing only works on one queue
item at a time.

There are simple ways to process the entire queue though:

* Visit the renewal page and choose HTML processing. An item will be popped off
the queue. Refresh tags are used to continue processing until finished.
* Use the API endpoint. Inspect results and continue processing as needed


# FAQ

## Is this secure?

Nothing is truly secure, is it?

PeterSSLers stores Certificates and PrivateKeys in plaintext - just like Certbot
and most LetsEncrypt clients store their assets.

The project splits the web-based views into two concepts: Public and Admin.

The
[Public Views](https://github.com/aptise/peter_sslers/tree/main/peter_sslers/web/views_public)
are isolated to the '/.well-known/acme-challenge` directory, and expose the same
information as every other LetsEncrypt client. These routes are generally safe.

The
[Admin Views](https://github.com/aptise/peter_sslers/tree/main/peter_sslers/web/views_admin)
are isolated to the '/.well-known/admin` directory; while these routes can be
extremely dangerous, a reasonably competent security policy can be implemented to
make this section of the application suite password protected and/or available
only to local network traffic.

The [SQLAlchemy Project](https://sqlalchemy.org) is used to handle database activity.
SQLAlchemy's ORM uses bind parameters and is inherently safe from SQL Injection Attacks.


## Does this reformat Certificates?

Yes. PEM certs are reformatted to have a single trailing newline (via stripping
then padding the input) and newlines are standardized to unix ("\n"). This seems
to be one of the more common standards people utilize for saving Certificates.
Certificates may be reformatted for compliance with other details of open standards.
The actual content of Certificates are unchanged.


## Is there a fast way to import existing Certificates?

See the *TOOLS* section for an `invoke` script that can automate importing
Certificates and other data from the LetsEncrypt data store.  The "invoke" tools
provide a commandline interface to batch POSTing data to the PeterSSLers server;
one could use `curl` or write their own tools.


## What happens if multiple Certificates are available for a Domain ?

Multiple Domains on a Certificate make this part of management epically &
especially annoying.

The current solution:

* There is a an API endpoint to cache the most-recent "multi" and "single" Certificate
  for every Domain onto the Domain's record (update-recents)
* Certificates *will not* be deactivated if they are the most-recent "multi" or
  "single" Certificate for any one Domain.

This means that a Certificate will stay active so long as any one Domain has not
yet-replaced it.

When querying for a Domain's Certificate, the system will currently send the most
recent Certificate. a future feature might allow for this to be customized, and show
the most widely usable Certificate.


## How does this handle Certbot AccountKeys?

Certbot stores RSA AccountKeys in a JWK (JSON Web Key) format.  AccountKeys from the
Certbot client are reformatted into PEM-encoded RSA key.  The data from the various
json files are archived into the database for use later. The account data is anayzed
for the actual environment it is registered with, and that becomes part of the
AcmeAccount record.


## Why use OpenSSL directly? / Does this work on Windows?

When this package was first developed, installing the necessary python packages for
cryptography required a lot of work and downloading. OpenSSL should already be
running on any machine PeterSslers needs to work on, so it was chosen for easy in quick
deployment.

It was also much easier to peg this to `openssl` in a linux environment for now;
which ruled out Windows.

The current version only uses `openssl` if the requisite Python modules are not
installed. That should work on Windows.

If someone wants to make a PR to fully support Windows, it will be reviewed!


## Where does the various data associated with Certificates come from?

When imported, Certificates are decoded and parsed for data.

When generated via the ACME protocol, Certificate data is provided in the headers.

Useful fields are duplicated from the cCrtificate into SQL to allow for better
searching. Certificates are not changed in any way, aside from the cleanup of
whitespace and/or other formatting concerns.


# Misc Tips

This library was designed to be deployed behind a couple of load balancers that
use round-robin DNS. They were both in the same physical network.

* `Nginx` is on port 80. everything in the `/.well-known directory` is proxied to
  an internal machine *which is not guaranteed to be up*
* this service is only spun up when certificate management is needed
* `/.well-known/admin` is not on the public internet

For testing Certificates, these 2 commands can be useful:

reprime `Redis` cache

    $ prequest -m POST example_development.ini /.well-known/admin/api/redis/prime.json

clear out `Nginx` cache

    curl -k -f https://127.0.0.1/.peter_sslers/nginx/shared_cache/expire/all

the `-k` will keep the Certificate from verifying, the `-f` wont blow up from errors.

# `Redis` support

There are several `.ini` config options for `Redis` support, they are listed above.

## `Redis` priming style

currently only `redis.prime_style = 1` and `redis.prime_style = 2` are supported.

### prime_style = 1

This prime style will store data into `Redis` in the following format:

* `d:{DOMAIN_NAME}` a 3 element hash for
  * CertificateSigned (c)
  * PrivateKey (p)
  * CertificateCAChain (i)
  * Note: the leading colon is required
* `c{ID}` the CertificateSigned in PEM format; (c)ert
* `p{ID}` the PrivateKey in PEM format; (p)rivate
* `i{ID}` the CertificateCAChain in PEM format; (i)ntermediate certs

The `Redis` datastore might look something like this:

    r['d:foo.example.com'] = {'c': '1', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['d:foo2.example.com'] = {'c': '2', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['c1'] = CERT.PEM  # (c)ert
    r['c2'] = CERT.PEM
    r['p2'] = PKEY.PEM  # (p)rivate
    r['i99'] = CHAIN.PEM  # (i)ntermediate certs

to assemble the data for `foo.example.com`:

* (c, p, i) = r.hmget('d:foo.example.com', 'c', 'p', 'i')
** returns {'c': '1', 'p': '1', 'i': '99'}
* cert = r.get('c1')
* pkey = r.get('p1')
* chain = r.get('i99')
* fullchain = cert + "\n" + chain

### prime_style = 2

This prime style will store data into `Redis` in the following format:

* `{DOMAIN_NAME}` a 2 element hash for:
  * FullChain [CertificateSigned+CertificateCAChain] (f)
  * PrivateKey (p)

The `Redis` datastore might look something like this:

    r['foo.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}
    r['foo2.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}


# Tests

To keep things simple, tests are run using unittest.

    python setup.py test

There are a few environment variables you can set:

    # run tests that hit `Nginx` for cache clearing
    export SSL_RUN_NGINX_TESTS=True

    # run tests that hit `Redis` for cache priming
    export SSL_RUN_REDIS_TESTS=True

    # run tests that hit the LetsEncryptAPI
    export SSL_RUN_LETSENCRYPT_API_TESTS=True

    # Set TRUE if you expect the LE API verificaiton to fail
    # this is desired right now, because it's rather complicated to set up a -
    # - test suite that responds to public requests
    export SSL_LETSENCRYPT_API_VALIDATES=True

Tests are done on a SQLite database as specified in `test.ini` AND MAY REQUIRE
CUSTOMIZATION FOR YOUR OPENSSL location. The `test.ini` should also reflect the
OpenSSL for your distribution. Do not edit `test.ini` though, instead create a
`test_local.ini` file and set an environment variable to use that file. More info
on this is available in the development readme file.

`test_data/` contains the keys and Certificates used for testing

You can overwrite the testdb; beware that it CAN NOT run as a memory db. It must
be a disk file due to how the tests are structured.

If running tests against the LetsEncrypt test API, there are some extra
configurations to note:

* `SSL_TEST_DOMAINS` should reflect one or more Domains which point to the IP
  address the server runs on. This will be used for verification of AcmeChallenges.
  LetsEncrypt must be able to communicate with this Domain on port 80.
* `SSL_TEST_PORT` lets you specify which port the test server should bind to
* `/tools/nginx_conf/testing.conf` is an `Nginx` configuration file that can be
  used for testing. it includes a flag check so you can just touch/remove a file
  to alter how `Nginx` proxies.



# Workflow Concepts

## Object Attributes

### Domain

#### `is_active`

If a Domain is "active", then it is actively managed and should be included in
ACME Order renewals or generating `Nginx` configuration.

### AcmeOrder

#### `is_auto_renew`

Set to `True` by default. If `True`, this Certificate will be auto-renewed by the
renewal queue. If `False`, renewals must be manual.

### CertificateSigned

#### `is_active`

If a Certificate is "active" (`True` by default) then it is actively managed and
should be included in generating `Nginx` configuration.

#### `is_deactivated` and `is_revoked`

If a certificate is not "active", only one of these will be `True`. If an inactive
certificate was deactivated, then it can be activated and this flag will reverse.
If the certificate was revoked, it is permanent and should not be re-activated.

## Domain Queue

The Domain queue, `/admin/queue-domains`, is designed to allow for Domains to be
"queued in" for later batch processing.

If a Domain is added to the queue, the following logic takes place:

* If the Domain is already managed, but is not `active`, activate it.
* If the Domain is not managed and not in the queue, add it to the queue.
* In all other cases, ignore the request. the Domain is either actively managed
  or queued to be so.


## Renewal Queue

* `update` will calculate which Certificates need to be renewed
* `process` will do the actual renewal

Certificates end up in the renewal queue through the `update` command or being
individually queued.

Certificates can also have a "custom renewal".

To process the queue:

To deal with timeouts and various issues, queue processing only works on one queue
item at a time.

There are simple ways to process the entire queue though:

* Visit the renewal page and choose HTML processing. An item will be popped off
the queue. Refresh tags are used to continue processing until finished.
* Use the API endpoint. Inspect results and continue processing as needed


# Oddities

*   When an ``AcmeAuthorization`` is "deactivated", the "ACME Server" will
 	disassociate the related "ACME Challenges" on the upstream server itself.
	Invoking both ``acme-server/deactivate`` and ``acme-server/sync`` from an
	``AcmeAuthorization`` object will sync the PeterSSLers object to the
	"ACME Authorization" object on the server. This will transition the status
	of the ``AcmeChallenge`` object to ``*410*``, an internal code which means
	"This ``AcmeChallenge`` has disappeared".  The "ACME Challenge" objects will
	still remain on the "ACME Server" in a "pending" state, which will be
	reflected if an ``acme-server/sync`` is invoked from the ``AcmeChallenge``
	object.
	
	Illustration:
	
		1. Create AcmeOrder
			AcmeAuthorization.status = "*discovered*"
		2. Load AcmeAuthorization
			AcmeAuthorization.status = "pending"
			AcmeChallenge.status = "pending"
		3. Deactivate AcmeAuthorization
			AcmeAuthorization.status = "deactivated"
			AcmeChallenge.status = "*410*"
		3. Sync AcmeChallenge
			AcmeChallenge.status = "pending"
	
	No known ACME Servers recycle pending Challenges across Authorizations.
	Adding an "Authorization2Challenge" table to track the "active" status of
	the relationship would unnecessarily complicate this application, however
	it will be done if necessary in the future.

* 	On startup, if the "Global Default" AcmeAccount belongs to a different
	server than the default AcmeServer (as specified by the
	``certificate_authority`` setting in the ``.ini`` file), the AcmeAccount
	will be unset as  default.
