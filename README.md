pyramid_letsencrypt_admin README
==================

`pyramid_letsencrypt_admin` is a tool designed to help EXPERIENCED DEVOPS ENGINEERS manage certificate deployment on large systems

# A HUGE WARNING

* This package DOES NOT USE/KNOW/CARE ABOUT SECURITY. 
* This package manages PRIVATE KEYS and makes them readable.
* If you do are not really awesome with basic network security PLEASE DO NOT USE THIS.

# What this package does:

The package spins up a Webserver that manages certificate data in a SQL database.

SqlAlchemy is the DB library, so virtually any database can be used (sqlite, postgres, mysql, oracle, mssql, etc).

You can manage certificates in a few ways:

* Input

1. An admin dashboard allows you to upload certificates (in a triplet of Cert, Signing Key, CA-Chain)
2. An admin dashboard allows you to initiate LetsEncrypt certificate signing. Upload a list of domains, your LetsEncrypt account key, and private key used for signing/serving, and the system will generate the CSR and perform all the verifications.
3. An admin dashboard allows you to proxy the acme-challenges that LetsEncrypt issues for manual verification

* Output

1. All the keys & certs are viewable in a wonderfully connected RDMBS browser.
2. Any keys/certs/chains can be queried in PEM & DER formats.
3. All the certificates are checked to track their validity dates, so you can search and re-issue

* Management

Everything is in RDBMS and de-duped.
chains are built on-the-fly.
in the future, an api will allow this to work.

# Installation

This is pretty much ready to go for development, usage

you should create a virtualenv though.



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
* make `/admin` usable within your LAN
* on a machine within your LAN, you can query for the latest certs for domain(s)


# notes

## Certificate/Key Translations

Certificates and Keys are stored in the PEM format, but can be downloaded in the DER format if needed.

There are several ways to download each file.  Different file suffix will change the format and headers.

### CA Certificate

	cert.pem 		PEM		application/x-pem-file
	cert.pem.txt	PEM		text/plain
	cert.cer 		DER		application/pkix-cert
	cert.der 		DER		application/x-x509-ca-cert

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
* `certificate_authority` - the letsencrypt certificate authority. default is their staging.  you'll have to manually put in the production.


# TODO

## combined chains

## search expiring soon

## api hooks

## upload CERT/Chains for 'flow' CSR

## full unit tests

This is still sketching out the idea.  this is not ready for production yet.


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


What does it look like?
---------------

It uses bootstrap.

![Admin Index](https://raw.github.com/jvanasco/pyramid_letsencrypt_admin/master/docs/images/01-admin_index.png)
![Enter Domains](https://raw.github.com/jvanasco/pyramid_letsencrypt_admin/master/docs/images/02-enter_domains.png)
![Enter Challenges](https://raw.github.com/jvanasco/pyramid_letsencrypt_admin/master/docs/images/03-enter_challenge.png)
![Check Status](https://raw.github.com/jvanasco/pyramid_letsencrypt_admin/master/docs/images/04-view_status.png)
