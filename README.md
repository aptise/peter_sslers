pyramid_letsencrypt_admin README
==================

`pyramid_letsencrypt_admin` is a tool designed to help EXPERIENCED DEVOPS people to manage certificate deployment on large systems.  it offers  a lightweight database backed webserver that can handle the LetsEncrypt issuance process, import any existing ssl certificates, and easily provision them to servers.  this tool has absolutely no security measures and should only be used by people who understand that.  (that should be a self-selecting group, because many people won't want this)

# A HUGE WARNING

* This package DOES NOT USE/KNOW/CARE ABOUT SECURITY. 
* This package manages PRIVATE KEYS and makes them readable.
* If you do are not really awesome with basic network security PLEASE DO NOT USE THIS.

# What this package does:

The package spins up a Webserver that manages certificate data in a SQL database.

SqlAlchemy is the DB library, so virtually any database can be used (sqlite, postgres, mysql, oracle, mssql, etc).

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

The webserver exposes the following routes/directors:

* `/.well-known/acme-challenge` - directory
* `/.well-known/whoami` - URL prints host 
* `/.well-known/admin` - admin tool THIS EXPLORES PRIVATE KEYS ON PURPOSE

THE ADMIN TOOL SHOULD NOT BE PUBLICLY ACCESSIBLE.  
YOU SHOULD ONLY RUN IT ON YOUR PRIVATE NETWORK

# why/how?

The purpose of this package is to enable certificate management in systems where one or more of the following apply:

* you have a lot of domains
* you have a lot of machines
* your domains resolve to more than one IP address

Imagine you want to issue a certificate for 100 domains, which could be served from any one of 5 machines (load balancers or round-robin dns) and the certificates need to be deployable to all 5 machines.

To solve this you can:

* proxy external `/acme-challenge/` to one or more machines running this tool (they just need to share a common datastore)
* make `/admin` only usable within your LAN
* on a machine within your LAN, you can query for the latest certs for domain(s) using simple `curl` commands

In a more advanced implementation, the certificates need to be loaded into `redis` for use by an `openresty`/`nginx` server that will dynamically handle ssl connections.  

This package does all the annoying openssl work in terms of building chains and converting formats  *You just tell it what domains you need certificates for and in which format, and THERE YOU GO.*


# notes

## Certificate/Key Translations

Certificates and Keys are stored in the PEM format, but can be downloaded in the DER format if needed.

There are several ways to download each file.  Different file suffix will change the format and headers.

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
* `certificate_authority` - the LetsEncrypt certificate authority. default is their staging.  you'll have to manually put in the production.

* `enable_views_public` - boolean, should we enable the public views?
* `enable_views_admin` - boolean, should we enable the admin views?

# tools

## invoke script

there is an `invoke` script in the `tools` directory that can be used to automate certain tasks.

right now the invoke script offers:

`import_letsencrypt_certs_archive` given a directory of your local LetsEncrypt archive (which has versioned certs), it will import them all into a server of your choice.


## commandline interface

### Routes Designed for JSON Automation

#### /admin/operations/update_recents

Updates domain records to list the most recent certificate for the domain

#### /admin/operations/deactivate_expired

Deactivates expired certs

### Routes with JSON support

several routes have support for JSON requests via a `/json` suffix. 

these are usually documented on the html version

#### /admin/certificate/upload/json

This can be used used to directly import certs issued by LetsEncrypt

	curl --form "private_key_file=@privkey1.pem" --form "certificate_file=@cert1.pem" --form "chain_file=@chain1.pem" http://127.0.0.1:6543/.well-known/admin/certificate/upload/json

	curl --form "private_key_file=@privkey2.pem" --form "certificate_file=@cert2.pem" --form "chain_file=@chain2.pem" http://127.0.0.1:6543/.well-known/admin/certificate/upload/json
	
Note that the url is not `/upload` like the html form but `/upload/json`

Both URLS accept the same form, but /upload/json returns json data that is probably more readable.

Errors will appear in JSON if encountered.

if data is not POSTed to the form, instructions are returned in the json.

There is even an `invoke` script to automate these imports:

	invoke import_letsencrypt_certs_archive --archive-path='/path/to/archive' --server-url-root='http://127.0.0.1:6543'


### Routes Designed for JSON access

#### Domain Data

`/admin/domain/{DOMAIN|ID}/config.json`

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


#### Certificate Access

`/admin/certificate/{ID}/config.json`

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

Need to get the cert data directly?  NO SWEAT.  transforms on the server and sent to you with the appropriate headers.

* /admin/certificate/{ID}/cert.crt
* /admin/certificate/{ID}/cert.pem
* /admin/certificate/{ID}/cert.pem.txt
* /admin/certificate/{ID}/chain.cer
* /admin/certificate/{ID}/chain.crt
* /admin/certificate/{ID}/chain.der
* /admin/certificate/{ID}/chain.pem
* /admin/certificate/{ID}/chain.pem.txt
* /admin/certificate/{ID}/fullchain.pem
* /admin/certificate/{ID}/fullchain.pem.txt
* /admin/certificate/{ID}/privkey.key
* /admin/certificate/{ID}/privkey.pem
* /admin/certificate/{ID}/privkey.pem.txt


# FAQ

## Does this reformat certs?

Yes. PEM certs are reformatted to have a single trailing newline (via stripping then padding the input).  This seems to be one of the more common standards people have for saving certs.  Otherwise certs are left as-is.

## Is there a fast way to import existing certs?

Yes.  Use `curl` on the commandline.  see the TOOLS section	

## What happens if multiple certs are available for a domain ?

Multiple Domains on a cert make this part of management epically & especially annoying.

The current solution is quick and dirty:

* there is a an "operation" hook that caches the most-recent "multi" and "single" cert for every domain
* certificates will not be deactivated if they are the most-recent used multi or single cert for any domain.

This means that a cert will stay active so long as any domain has not yet-replaced it.

When querying for a domain's cert, the system will currently send the most recent cert.  a future feature might allow for this to be customized, and show the most widely usable cert.

## Why use openssl? / does this work on windows?

It was much easier to peg this to `openssl` in a linux environment for now; which rules out windows.

In the future this could all be done with Python's crypto library.  However openssl is fast and this was primarily designed for dealing with linux environments.  sorry.

## Where does data come from?

When imported, certs are read into text form and parsed.

When generated via acme, cert data is provided in the headers.

Useful fields are duplicated from the cert into SQL to allow for better searching.  Certs are not changed in any way (aside from whitespace cleanup)


# misc tips

So far this has been tested behind a couple of load balancers that use round-robin dns.  They were both in the same physical network.

* nginx is on port 80.  everything in the /.well-known directory is proxied to an internal machine *which is not guaranteed to be up*
* this service is only spun up when certificate management is needed
* /admin is not on the public internet



# redis support

currently building support for redis

redis would be something like this:
	r['d:foo.example.com'] = ('cert:1', 'key:a', 'fullcert:99')
	r['d:foo2.example.com'] = ('cert:2', 'key:a', 'fullcert:99')
	r['c:1'] = CERT.DER
	r['c:2'] = CERT.DER
	r['k:2'] = PKEY.DER
	r['s:99'] = CACERT.DER

prime script should:
	loop through all ca_cert> cache into redis
	loop through all pkey> cache into redis
	loop through all cert> cache into redis
	

# TODO

## search expiring soon

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
