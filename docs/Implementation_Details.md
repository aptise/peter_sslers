* [Previous - General_Management_Concepts](https://github.com/aptise/peter_sslers/tree/main/docs/General_Management_Concepts.md)
* [Next - Automation](https://github.com/aptise/peter_sslers/tree/main/docs/Automation.md)

# Implementation Details

The webserver exposes the following routes/directories:

* `/.well-known/acme-challenge` - directory
* `/.well-known/public/whoami` - URL prints host
* `/.well-known/peter_sslers` - admin tool IMPORTANT - THIS EXPOSES PRIVATE KEYS ON PURPOSE

The server will respond to requests with the following header to identify it:

    X-Peter-SSLers: production



## Just a friendly reminder:

THE ADMIN TOOL SHOULD NEVER BE PUBLICLY ACCESSIBLE.
YOU SHOULD ONLY RUN IT ON A PRIVATE NETWORK

By default, the `example_production.ini` file won't even run the admin tools.
That is how serious we are about telling you to be careful!


## manage custom trust 

To specify the CA Certificate bundles:

    import peter_sslers.lib.cas
    peter_sslers.lib.cas.CA_ACME = [bool, str]

    # use ca_bundle_pem in configuration
    # peter_sslers.lib.cas.CA_NGINX = [bool, str]


## why/how?

Again, the purpose of this package is to enable Certificate Management in systems
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
* make ` /.well-known/peter_sslers` only usable within your LAN or NEVER USABLE
* on a machine within your LAN, you can query for the latest certs for Domain(s)
  using simple `curl` commands

In a more advanced implementation (such as what this was originally designed to
manage) the Certificates need to be loaded into a `Redis` server for use by an
`OpenResty`/`Nginx` webserver/gateway that will dynamically handle SSL Certificates.

In a simple example, `OpenResty`/`Nginx` will query
`/.well-known/peter_sslers/domain/example.com/config.json` to pull the active Certificate
information for a Domain. In advanced versions, that Certificate information will
be cached into multiple levels of `OpenResty`/`Nginx` and `Redis` using different
optimization strategies.

This package does all the annoying openssl work in terms of building chains and
converting formats *You just tell it what Domains you need Certificates for and
in which format AND THERE YOU GO.*



## Deployment Concepts

![Network Map: Simple](https://raw.github.com/aptise/peter_sslers/tree/main/docs/assets/network_map-01.png)

PeterSSlers can run as a standalone service OR proxied behind `Nginx`/`Apache`/etc

The SSLMinnow datastore is entirely separate and standalone. It is portable.

![Network Map: Configure](https://raw.github.com/aptise/peter_sslers/tree/main/docs/assets/network_map-02.png)

In order to make network configuration more simple, the package includes a "fake
server" that includes routes for the major public and admin endpoints. This should
support most integration test needs.

![Network Map: Advanced](https://raw.github.com/aptise/peter_sslers/tree/main/docs/assets/network_map-03.png)

In an advanced setting, multiple servers proxy to multiple peter-sslers "public"
instances.

The instances share a single SSLMinnow data store.

The "Admin" tool runs on the private intranet.


## Notes

### Certificate/Key Translations

Certificates and Keys are stored in the PEM format, but can be downloaded in the
DER format if needed.

There are several ways to download each file. Different file suffix will change
the format and headers.

Peter shows you buttons for available formats on each page.

#### CertificateSigned

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

#### CertificateCA

The CertificateAuthority's Certificate:

    cert.pem            PEM     application/x-pem-file
    cert.pem.txt        PEM     text/plain
    cert.cer            DER     application/pkix-cert
    cert.crt            DER     application/x-x509-ca-cert
    cert.der            DER     application/x-x509-ca-cert

#### CertificateCAChain

One or more CertificateAuthority Certificates

    chain.pem           PEM     application/x-pem-file
    chain.pem.txt       PEM     text/plain

#### CertificateRequest

    csr.pem             PEM     application/x-pem-file
    csr.pem.txt         PEM     text/plain
    csr.csr             PEM     application/pkcs10

#### Account/Domain Keys

    key.pem             PEM     application/x-pem-file
    key.pem.txt         PEM     text/plain
    key.key             DER     application/pkcs8

#### Account/Domain Keys

    key.pem             PEM     application/x-pem-file
    key.pem.txt         PEM     text/plain
    key.key             DER     application/pkcs8



## Workflow Concepts

### Object Attributes

#### Domain

##### `is_active`

If a Domain is "active", then it is actively managed and should be included in
ACME Order renewals or generating `Nginx` configuration.

#### CertificateSigned

##### `is_active`

If a Certificate is "active" (`True` by default) then it is actively managed and
should be included in generating `Nginx` configuration.

##### `is_deactivated` and `is_revoked`

If a certificate is not "active", only one of these will be `True`. If an inactive
certificate was deactivated, then it can be activated and this flag will reverse.
If the certificate was revoked, it is permanent and should not be re-activated.

## Oddities

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
