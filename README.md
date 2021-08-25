ACME-v2 RELEASE
================================

Hi!

ACME-V2 support involved a large rewrite of the Client and the Certificate
Manager's design. The central object changed from a `CertificateSigned` to the
`AcmeOrder`, which caused a ripple effect.

This project is still undergoing active development, and the design is not
entirely finalized yet... but... most of the functionality is working (and this
package is used in production!). Everything is covered by extensive unit and
integrated tests.

WE ARE ALMOST THERE!!!


peter_sslers README
================================

Peter SSLers *or how i stopped worrying and learned to LOVE the SSL Certificate*.

`peter_sslers` is a framework designed to help *experienced* Admins and DevOps
persons manage SSL Certificates and deploy them on larger systems (e.g. you have
lots of Domains and/or Nodes and/or Networks).

What's in the "box" ?

* `OpenResty` Lua module to enable Dynamic SSL Certificate Handling on the `Nginx`
  webserver
* A robust SSL Certificate Manager and Explorer, with Admin Dashboard and a
  full programmatic API
* An integrated ACME V2 Client for the LetsEncrypt CertificateAuthority

THIS LIBRARY CONTAINS EVERYTHING YOU NEED TO SSL-ERATE AN INIFINITELY SCALEABLE
MULTI-SERVER OR MULTI-DOMAIN SETUP!!!

Amazing, right?

This project is *not* aimed at casual users or people concerned with a handful of
websites or servers.

This project is designed for people who have lots of Domains and/or Servers,
all of which need to be coordinated and centrally managed. The target audience
is companies that offer whitelabel services, such as: SAAS, PAAS, hosting user
domains, and other infrastructure oriented systems.

If you can use Certbot or another consumer friendly simple client to solve your
needs, YOU ALMOST ABSOLUTELY WANT TO USE THAT CLIENT.

Peter, as we fondly call this package, offers lightweight tools to centrally manage
SSL Certificate data in a centralized SQL database of your choice. PostgreSQL is
recommended; Sqlite is supported and the primary testing environment. A good-faith
effort is made to get this to work on MySQL, but, well, sigh.

Peter combines an integrated ACME V2 Client designed to primarily operate against
the LetsEncrypt service, alongside tools designed to manage, deploy and troubleshoot
SSL Certificates.

The client supported ACME v1 until version `0.4.0`.
**As of 0.4.0, Only ACME V2 is supported.**
**As of 0.5.0, Only lua-resty-peter_sslers >0.5.0 is supported.**

It is highly likely that PeterSSLers will work with most, if not all, ACME Servers.
However, **only LetsEncrypt is supported as a target ACME Server** at this time.
LetsEncrypt implementation of the ACME RFC,
[Boulder](https://github.com/letsencrypt/boulder) has made some unique decisions
regarding RFC spec-compliant implementation details, and this system was written
to support those first and foremost.

Peter's core tool is a lightweight database-backed `Pyramid` application that can:

* Act as a client for the entire "LetsEncrypt" Certificate provisioning process,
  operating behind a proxied webserver.
* Offer a simple API for creating and managing the ACME process. Your client
  software will only talk to Peter, never LetsEncrypt/ACME.
* Import existing ACME Account Credentials for various CA Operations.
* Import existing SSL Certificates for management and exploration
* Ease provisioning Certificates onto various servers across your systems
* Browse Certificate data and easily see what needs to be renewed
* Interact with the upstream ACME Servers to deal with accounts, pending
  AcmeAuthorizations, and all that mess.
* Communicate with a properly configured `OpenResty` enabled `Nginx` web server
  (see next section)
* Prime a Redis cache with Certificate data
* Translate Certificates into different formats
* Be the source of lots of puns!

Peter ships alongside a `Lua` `opm` module for the `OpenResty` framework on the
`Nginx` server which will:

* Dynamically request Certificates from a primed `Redis` cache
* Store data in shared `Nginx` worker and main memory and
* Expose routes to flush the worker shared memory or expire select keys.

The `OpenResty` module is available in a separate project,
https://github.com/aptise/lua-resty-peter_sslers and can be installed into your
`OpenResty`/`Nginx` server via the `opm` package installer. It has been used in
production for several years.

The `Pyramid` based application can function as a daemon for Admin or API access,
or even a commandline script. Most web pages offer `.json` endpoints, so you can
easily issue commands via `curl` and have human-readable data in a terminal window.
Don't want to do things manually? Ok - everything was built to be readable on
commandline browsers... yes, this is actually developed-for and tested-with Lynx.
I shit you not, Lynx.

Do you like book-keeping and logging?  Peter's ACME Client logs everything into
SQL so you can easily find the answers to burning questions like:

* What AcmeAuthorizations are still pending?
* What AcmeChallenges are active?
* Which external IPs are triggering my AcmeChallenges?
* Where did this PrivateKey come from?
* How many requests have I been making to upstream servers?

All communication to the upstream ACME server is logged using Python's standard
`logging` module.

module: `peter_sslers.lib.acme_v2`
* log level: `logging.info` will show the raw data received
* log level: `logging.debug` will show the response parsed to json, when applicable

THIS PACKAGE IS EXTREME TO THE MAX!!!

Do you like cross-referencing?  Your certs are broken down into fields that are
cross-referenced or searchable within Peter as well.

*Peter has absolutely no security measures and should only be used by people who
understand that.* This should be a self-selecting group, because many people will
not want this tool. Peter is a honeybadger, he don't care. He does what he wants.

Peter offers several commandline tools -- so spinning up a tool "webserver" mode
may not be necessary at all -- or might only be needed for brief periods of time.

SQLAlchemy is the backing database library, so virtually any database can be used
(SQLite, PostgreSQL, MySQL, Oracle, mssql, etc). `SQLite` is the default, but
the package is deployed against PostgreSQL. SQLite is actually kind of great,
because a single `.sqlite` file can be sftp'd on-to and off-of different machines
for distribution and local viewings.

Peter will use installed Python cryptography modules whenever possible.
If the required packages are not available, Peter will leverage the system's
installed OpenSSL binaries using subprocesses. The reason is to minimize the
amount of installations/downloads/packages when used for emergency debugging.
*Every single operation involved with procuring and inspecting SSL Certificates
is implemented Python-first, with an OpenSSL fallback.*

Although Python2 is no longer supported by Python itself, both Python2 and Python3
are targeted platforms for this library because we all have to deal legacy systems.


Why?
-----

Most of us hate having to spend time on DevOps tasks. Personally, I would rather
spend time working on the core product or consumer products. This tool was designed
as a swiss-army-knife to streamline some tasks and troubleshoot a handful of issues
with https hosting. This also allows for programmatic control of most ACME
operations that can be difficult to accomplish with Certbot and other popular clients.

Peter sits in between your machines and LetsEncrypt. It is designed to let your
applications programmatically interact with ACME servers, allowing you to
provision new Certificates and load them into webservers.

Peter is originally designed for systems that offer whitelabel services in the cloud.

PRs are absolutely welcome, even if just fixes or additions to the test-suite.


Status
------

Peter SSLers is fully functional and deployed in production environments for:

* Certificate management
* Manual renewal
* Interrogating and syncing with ACME Servers

The following features are being reworked:

* Queuing new Domains for Certificate provisioning
* Automatic renewal


WARNING (Important)
===================

* This package DOES NOT USE/KNOW/CARE ABOUT SECURITY.
* This package manages PRIVATE SSL KEYS and makes them readable.
* If you do not know / are not really awesome with basic network security PLEASE
  DO NOT USE THIS.


ACME2 Features
==============

| Feature | Supported? |
| --- | --- |
| New Certificate | Yes |
| Deactivate Account | Yes |
| Account Key Rollover | Yes |


The Components
==============

"Peter SSLers" - a `Pyramid` Application
----------------------------------------

"Peter SSLers" is the core toolkit. It is a `Pyramid` application that can be
spun up as a webserver or used via a commandline interface. Peter is your friend
and handles all of the Certificate Management and translation functions for you.
He's a bit eccentric, but basically a good guy.

"SSL Minnow" - The Datastore
----------------------------------------

By default, the "SSL Minnow" is a SQLite database `ssl_minnow.sqlite`. It is the
backing datastore for SSL Certificates and the operations log. Your data is ONLY
saved to the SSL Minnow - not to the filesystem like other LE clients - so you
should be careful with it. If the Minnow would be lost, it can not be recovered.
Be a good skipper, or your three hour tour could end up taking many years and might
involve the Harlem Globetrotters, who are great to watch but do you want to be stuck
on a remote desert island with them?!?! No.

"SSLX" - The `OpenResty` package
----------------------------------------

OpenResty is a fork of the nginx webserver which offers a lot of programmatic hooks
(similar to Apache's mod_perl). One of the many hooks allows for programmatic
determination and loading of SSL Certificates based on the hostname.

A tiered waterfall approach is used to aggressively cache Certificates:

* initial attempt: `nginx` worker memory
* failover 1:  `nginx` shared memory
* failover 2: centralized `redis` server
* failover 3: querying the `Peter SSLers` `Pyramid` application

The `Pyramid` application can be used to prime and clear each cache level.

SSLX, I'm your only friend. SSLX, Your love will sing for you.

Available via the opm package manager:

    opm get lua-resty-peter_sslers

The source and docs are available on a separate github repository:

* https://github.com/aptise/lua-resty-peter_sslers


"Tools"
----------------------------------------

The "/tools" directory contains scripts useful for Certificate operations.
Currently this includes:

* An `invoke` script for importing Certbot archives, and potentially other tasks.
* A sample `fake_server.py` that will spin up a web server with routes which you can
  test against. This will allow you to setup your proxy integration without running
  peter_sslers itself. Responses include the header: `X-Peter-SSLers: fakeserver`.



ToDo
=====

See `TODO.txt`


Getting Started
===============

Please read the
[Full Installation Instructions](https://github.com/aptise/peter_sslers/docs/Installation.md)

The abridged version:

- mkdir certificate_admin
- cd certificate_admin
- virtualenv peter_sslers-venv
- source peter_sslers-venv/bin/activate
- git clone https://github.com/aptise/peter_sslers.git
- cd peter_sslers
- $VENV/bin/python setup.py develop
- vi example_development.ini
- $VENV/bin/initialize_peter_sslers_db example_development.ini
- $VENV/bin/pserve example_development.ini



Full Documentation
==================

* [Installation](https://github.com/aptise/peter_sslers/docs/Installation.md)
* [Configuration Options](https://github.com/aptise/peter_sslers/docs/Configuration_Options.md)
* [General_Management_Concepts](https://github.com/aptise/peter_sslers/docs/General_Management_Concepts.md)
* [Implementation_Details](https://github.com/aptise/peter_sslers/docs/Implementation_Details.md)
* [Automation](https://github.com/aptise/peter_sslers/docs/Automation.md)
* [Frequently Asked Questions](https://github.com/aptise/peter_sslers/docs/Frequently_Asked_Questions.md)
* [Misc](https://github.com/aptise/peter_sslers/docs/Misc.md)
* [Tools](https://github.com/aptise/peter_sslers/docs/Tools.md)
* [Tests](https://github.com/aptise/peter_sslers/docs/Tests.md)
* [Versioning](https://github.com/aptise/peter_sslers/docs/Versioning.md)
