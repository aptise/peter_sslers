* [Previous - Configuration_Options](https://github.com/aptise/peter_sslers/tree/main/docs/Configuration_Options.md)
* [Next - Implementation_Details](https://github.com/aptise/peter_sslers/tree/main/docs/Implementation_Details.md)

# General Management Concepts


## Intuitive Hierarchy of Related Objects

* The Core Object for Certificates is a `RenewalConfiguration`:
    * The intersection of an Account[AcmeServer], Domains, Renewal Options [automatic renewal?, Private Key Technology, Private Key Cycling].
    * Previous versions used a CertificateSigned and AcmeOrder
* A RenewalConfiguration's primary relations are:
    AcmeAccount - which account owns the configuration?
    UniqueFQDNSet - a simple listing of the domains, shorthand for compatible certificates
    UniquelyChallengedFQDNSet - specific challenge preferences per domain; a UniqueFQDNSet but with per-domain preferred challenge types
    AcmeOrders - generated from this configuration
* A PrivateKey is considered a secondary item to the RenewalConfiguration. One can be specified for a given AcmeOrder, but the RenewalConfiguration can specify it's own strategy when obtaining an initial Certificate or Renewing; and that strategy can default to the AcmeAccount.
* A PrivateKey can be re-used across new/renewed AcmeOrders if specified.
* An AcmeAccount can specify: use the same PrivateKey for up to 1 year, always use a unique PrivateKey, use a new PrivateKey every day, use a new PrivateKey every week. The AcmeAccount can choose to use daily or weekly per-account or global keys.


### CertificateCAs and Certificate Chains

Earlier versions of this library treated the entire chain as a unique CertificateCA.

This has since changed.

The normalized data structure used by the backend and object hierarchy is as follows:

* `CertificateSigned`
  * The "End Entity" Certificate
* `CertificateSignedChain`
  * One or more per `CertificateSigned`
  * Maps a `CertificateSigned` to the ACME indicated `CertificateCAChain`
  * Indicates if the association was the primary/default or an alterate
* `CertificateCAChain`
  * Represents a chain of one or more `CertificateCA` Certificates
  * item 0 signed the `CertificateSigned`
  * item n is typically signed by the Trust store Certificate
* `CertificateCA`
  * A root or intermediate Certificate

When Alternate Chains are offered by the ACME server, the system will download
all chains and associate them to the Certificate.

PeterSSLers also has a tool/endpoint to handle CertificateCA "Reconciliation".

With Reconciliation, CertificateCAs with an issuer URI (aka "Authority Information
Access" URI) will have that URI downloaded, processed and enrolled into the system.
The record pertaining to the downloaded Certificate - which may have already been
in the system, will be noted with the URI the Certificate was downloaded from.

Reconciliation is designed to help ensure PeterSSLers can provide downstream tools
with all the necessary Certificates in a chain -- including the Trusted Roots if
necessary.


### Unique Fully Qualified Domain Sets (UniqueFQDNSet)

With PeterSSLers, Certificates are not associated to "Domains" but to "UniqueFQDNSets",
which are unique collections of domains.

This design was implemented for two reasons:

1. Certbot has a concept of "Lineage", which tracks the version history of a given
   Certificate. This can create confusion when adding and removing domains, as the
   lineage certificate's name does not necessarily reflect what is in the Certificate.

2. One of the LetsEncrypt service's ratelimits is based on a CertificateRequest's
   "uniqueness" of Domains, which is essentially a UniqueFQDNSet (There may only
   be *n* "Duplicate Certificates" issued per week). By tracking the UniqueFQDNSets
   natively, PeterSSLers can help you avoid hitting these limits.  To more easily
   deal with this limit, AcmeOrders/Certificates/CertificateRequests are designed
   around the idea of a "UniqueFQDNSet" and not a single Domain.

When requesting a new Certificate or importing existing ones, this happens all
behind-the-scenes: a listing of Domains is turned into a unique set of Domain names.


## Accounts and AccountKeys

Like Certbot, PeterSSLers supports using multiple accounts and multiple ACME
servers.


* An `AcmeAccount` is the intersection of a contact email address and an `AcmeAccountKey`
* You may use the same contact email address with different ACME Servers
* You may not use the same `AcmeAccountKey` with different ACME Servers or accounts.
* You may choose a `PrivateKey` Technology and Cycling Strategy


## Single or Multi-Step Operations

When provisioning a certificate, there are 3 options available:

* _Create an ACME Order_ This option will internally validate the information
  required for generating an ACME Order, and submit it to the ACME Server. To
  complete the Order and obtain a Certificate, you must manually or
  programmatically complete the required steps.

* _Process in a Single Request_ This option will create an ACME Order, submit it
  to the ACME Server, and then attempt to complete every ACME Challenge, finalize
  the order, and download the certificate.

* _Process in Multiple Requests_ This option will create an ACME Order,
  submit it to the ACME Server, and then invoke some additional synchronization
  operations that do not happen on within the "Create an ACME Order" flow. You
  may then manually or programmatically complete the required steps.

When manually or programmatically completing steps, you may elect to either
explicitly invoke the next step, or to let the system "autodetect" the next step.
When processing orders programmatically, "json" endpoints can be leveraged.


## A single web application?

In a perfect world we could deploy the combination of a web application (enter data,
serve responses) and a task runner (process ACME Server interactions) - but that
involves quite a bit of overhead to deploy and run.

The ACME protocol requires a web server to respond to HTTP-01 validation requests.
A web server is a great choice for an admin interface, and to provide a programmatic
API.

The `Pyramid` framework has a wonderful utility called
[`prequest`](https://docs.pylonsproject.org/projects/pyramid/en/latest/pscripts/prequest.html)
which allows users to invoke web requests from the commandline.

Using `prequest`, long-running processes can be easily triggered off the commandline,
so a persistent web server is not required, and the "server" aspect of this package
is only needed to complete the HTTP-01 challenges.

If challenges are being completed with the DNS-01 method, the web server aspect of
this package is not needed.


## Cryptography: Python vs OpenSSL

When this package was initially written, a decision was made to avoid using Python
cryptography libraries and wrap OpenSSL via subprocesses:

* The Python cryptography libraries required large downloads and/or builds, which
  hindered jumping into a server to fix something fast.
* OpenSSL was on every target machine

As time progressed, it has become much easier to deploy Python cryptography libraries
onto target server, and many servers already have them installed.

The project now uses Cryptography exclusively.


## "autocert" functionality

The system has two endpoints that can quickly provide single Domain Certificates
in an "autocert" functionality to nginx:

* `/api/domain/certificate-if-needed` will instantiate a CertificateRequest if
  needed, or serve an existing Certificate. This is designed for programmatic access
  and offers full control.

* `/api/domain/autocert` will instantiate a CertificateRequest if needed, or
  serve existing Certificate. this is designed for automatically handling the
  Certificate process from within nginx, has some throttle protections, and
  relies on configurable system default values.

While several webservers offer "autocert" functionality, PeterSSLers is different
because our integration handles the "autocert" from a secondary service that multiple
webservers can interact with.


## Certificates and CertificateRequests

PeterSSLers handles several types of CertificateRequests:

1. (Preferred) The system will generate a CertificateRequest as part of the 
   ordering process with the built-in ACME-v2 client.
2. Legacy. An existing CertificateRequest (and Certificate) can be imported
   for tracking and relationship analysis.


## Input

1. An admin dashboard allows you to upload Certificates, in a triplet of
   (Certificate, PrivateKey, CA-Chain).
2. An admin dashboard allows you to initiate LetsEncrypt Certificate signing.
   Upload a list of Domains, your LetsEncrypt AccountKey, and PrivateKey used
   for signing/serving, and the system will generate the CSR and perform all the
   verifications.
3. A public interface allows you to proxypass the AcmeChallenges that LetsEncrypt
   issues for manual verification. (ie, run this behind `Nginx`)
4. You can run the 'webserver' on a private IP, and `curl` data into it via the
   commandline or miscellaneous scripts

## Output

1. All the keys & certs are viewable in a wonderfully connected RDMBS browser.
2. Any keys/certs/chains can be queried in PEM & DER formats.
3. All the Certificates are checked to track their validity dates, so you can
   search and re-issue
4. This can "prime" a `Redis` cache with SSL Cert info in several formats.
   A Lua script for `OpenResty` is included that enables dynamic SSL certs.

## Management

* Everything is in the RDBMS and de-duped.
* Certificate chains are built on-the-fly.
* A growing API powers most functionality
* Public and Admin routes can be isolated in the app & firewall, so you can just
  turn this on/off as needed
* you can easily see when Certificates and/or Domains expire and need to be renewed
* if SQLite is your backend, you can just run this for signing and deployment;
  then handle everything else offline.
* "Admin" and "Public" functions are isolated from each other. By changing the
  config, you can run a public-only "validation" interface or enable the admin
  tools that broadcast Certificate information.
* the `Pyramid` server can query `Nginx` locations to clear out the shared cache


## PrivateKey Cycling

PeterSSLers allows you to control how PrivateKeys are cycled on renewals or new
orders.

* `single_use` - This is the stame strategy the official LetsEncrypt client,
  Certbot, uses. A new PrivateKey is generated for each Certificate.

PeterSSLers is designed to host large amounts of websites, and aggressively cache
the Certificates and keys into OpenResty/Nginx and Redis. Being able to recycle
keys will use less memory and support more sites. The following options are available:

* `single_use__reuse_1_year` - The certificate will be re-used for 1 year from date of
  creation, then be replaced by a new certificate with the same lifetime.
* `account_daily` - The AcmeOrder/Certificate should use a PrivateKey generated for a
  unique ACME Account for the DAY the AcmeOrder is finalized.
* `account_weekly` - The AcmeOrder/Certificate should use a PrivateKey generated for a
  unique ACME Account for the WEEK the AcmeOrder is finalized.
* `global_daily` - The AcmeOrder/Certificate should use a PrivateKey generated for the
  entire installation for the DAY the AcmeOrder is finalized.
* `global_weekly` - The AcmeOrder/Certificate should use a PrivateKey generated for the
  entire installation for the WEEK the AcmeOrder is finalized.

AcmeOrders and Renewals can also specify:

* `account_default` - The AcmeOrder/Certificate will use whatever option is set as
  the default strategy for the active AccountKey.

Using the weekly or daily options will allow you to constantly cycle new keys into
your installation, while minimizing the total number of keys the system needs to
operate.

Re-using PrivateKeys across AcmeOrders is particularly useful because this
application's OpenResty plugin leverages a three-level cache (nginx-worker,
nginx-master, redis) for dynamic Certificate lookups.

In large-scale deployments, using a single PrivateKey per Certificate can cause
memory concerns that lead users to stuff Certificates up to the limit of 100
domain names. By re-using PrivateKeys, these concerns can be greatly alleviated
and make grouping Certificates by domain more attractive.

For example, consider bucketing 50 domains with the bare "registered domain" and a
subdomain (either the wildcard `*` or `www`):

| Strategy | Certificates | PrivateKeys |
| --- | --- | --- |
| 1 Certificate | 1 | 1 |
| 50 Certificates, No PrivateKey resuse | 50 | 50 |
| 50 Certificates + PrivateKey resuse | 50 | 1 |


## Certificate Pinning and Alternate Chains

PeterSSLers will track/enroll EVERY Certificate Chain presented by the upstream
ACME Server. There is no facility to disable this functionality, and there are
no plans to disable this functionality.

The Default Certificate Chains can only be pinned globally. The "CertificateCA"
Administration Panel has an option to set a hierarchy of upstream CA Certificates.
When a default chain is needed, Peter will iterate the list of preferred upstream
CAs and return the first signing chain that matches. If no match is found, the
default upstream from ACME will be used.

This only affects the "default" endpoints, which are used as shortcuts for Nginx
and other system integrations. Every signing chain is always available for a
given Certificate. Certificates also list the possible signing chains by their
system identifier AND SHA1 fingerprint.
