If you'd like to jump to the [QuickStart](https://github.com/aptise/peter_sslers/blob/main/docs/QuickStart.md), otherwise keep reading.

Project History
===============

PeterSSLers is a bundled ACME Client, Certificate Manager, OpenResty/Nginx Plugin
and Python-based framework designed for programmatically managing SSL Certificates.

This project started at Aptise Media as an internal tool for obtaining and managing
SSL Certificates for partner/customer domains. The project integrated an ACME(v1)
Client, a SQL based Certificate Manager, and an OpenResty plugin for dynamic
certificate loading.

ACME-V2 support involved a large rewrite of the Client and the Certificate
Manager's design. The central object changed from a `CertificateSigned` to the
`AcmeOrder`, which caused a ripple effect.  The V1 release again changed the
central object to a new `RenewalConfiguration` concept and streamlined operations.


peter_sslers README
===================

Peter SSLers *or how i stopped worrying and learned to LOVE the SSL Certificate*.

`peter_sslers` is a framework designed to help *experienced* Admins and DevOps
persons manage SSL Certificates and deploy them on larger systems (e.g. you have
lots of Domains and/or Nodes and/or Networks).  This system is NOT designed for
casual usage; it was designed for the needs of cloud deployed PAAS/SAAS systems
that host domains for scalable numbers of customers over scalable nodes.

What's in the "box" ?

* This project is a Python/[Pyramid](https://github.com/pylons/pyramid) based
  robust SSL Certificate Client, Manager and Explorer, complete with:
  * an Admin Dashboard,
  * a fullly programmatic API,
  * commandline tools
  * cron job "routines"
  * an integrated ACME V2 Client optimized for the
    [LetsEncrypt](https://LetsEncrypt.org) CertificateAuthority.
* The paired project
  [Lua-Resty Peter_SSLers](https://github.com/aptise/lua-resty-peter_sslers)
  is an [OpenResty](https://github.com/openresty/openresty) Lua module to enable
  Dynamic SSL Certificate Handling on the `Nginx` webserver.

**This library contains everything you need to ssl-erate an inifinitely scaleable
multi-server or multi-domain setup!!!**

Amazing, right?

This project is *not* aimed at casual users or people concerned with a handful of
websites or servers.

This project is designed for people who have lots of Domains and/or Servers,
all of which need to be coordinated and centrally managed. The target audience
is companies that offer whitelabel services, such as: SAAS, PAAS, hosting user
domains, and other infrastructure oriented systems.

If you can use Certbot or another consumer friendly simple client to solve your
needs, YOU ALMOST ABSOLUTELY WANT TO USE THAT CLIENT INSTEAD.

Peter, as we fondly call this package, offers lightweight tools to centrally manage
SSL Certificate data in a centralized SQL database of your choice. PostgreSQL is
recommended; sqlite3 is supported and the primary testing environment.

Peter combines an integrated ACME V2 Client designed to primarily operate against
the LetsEncrypt service, alongside tools designed to manage, deploy and troubleshoot
SSL Certificates.

It is highly likely that PeterSSLers will work with most, if not all, ACME Servers.
However, **only LetsEncrypt's Boulder and Pebble are target ACME Servers at this time**.
LetsEncrypt implementation of the ACME RFC,
[Boulder](https://github.com/letsencrypt/boulder) has made some unique decisions
regarding RFC spec-compliant implementation details, and this system was written
to support those first and foremost.  Widespread compatibility is hopefully achieved
by using the [Pebble](https://github.com/letsencrypt/pebble) ACME Server for
testing.

Peter's core tool is a lightweight database-backed
[Pyramid](https://github.com/pylons/pyramid) application that can:

* Act as a client for the entire ACME Certificate provisioning process,
  operating behind a proxied webserver for HTTP-01 challenges or integrating
  with an [acme-dns](https://github.com/joohoi/acme-dns) .
* Offer a unified API for creating and managing the ACME process. Your client
  software will only talk to Peter, never LetsEncrypt/ACME.
* Import existing ACME Account Credentials for various CA Operations.
* Import existing SSL Certificates for management and exploration
* Ease provisioning Certificates onto various servers across your systems
* Browse Certificate data and easily see what needs to be renewed
* Interact with the upstream ACME Servers to deal with accounts, pending
  AcmeAuthorizations, and all that mess.
* Communicate with a properly configured
  [OpenResty](https://github.com/openresty/openresty) enabled `Nginx` web server
  (see next section)
* Prime a Redis cache with Certificate data
* Translate Certificates into different formats
* Be the source of lots of puns!

Peter ships alongside a `Lua` `opm` module for the
[OpenResty](https://github.com/openresty/openresty) framework on the `Nginx`
server which will:

* Dynamically request Certificates from a primed `Redis` cache
* Store data in `Nginx`'s shared worker and main memories
* Expose routes to flush the worker shared memory or expire select keys.

The [Peter_SSLers OpenResty Module](https://github.com/aptise/lua-resty-peter_sslers)
module is available in a separate project,
[lua-resty-peter_sslers](https://github.com/aptise/lua-resty-peter_sslers) and can
be installed into your [OpenResty](https://github.com/openresty/openresty) / `Nginx`
server via the `opm` package installer. It has been used in production for several
years.

The [Pyramid](https://github.com/pylons/pyramid) based application can function
as a daemon for Admin or API access, or even a commandline script. Most web pages
offer `.json` endpoints, so you can easily issue commands via `curl` and have
human-readable data in a terminal window. Don't want to do things manually? Ok -
everything was built to be readable on commandline browsers... yes, this is
actually developed-for and tested-with Lynx.  I sh*t you not, Lynx.

Do you like book-keeping and logging?  Peter's ACME Client can log everything into
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

**THIS PACKAGE IS EXTREME TO THE MAX!!!**

Do you like cross-referencing?  Your certs are broken down into fields that are
cross-referenced or searchable within Peter as well.

*Peter has absolutely no security measures and should only be used by people who
understand that.* This should be a self-selecting group, because many people will
not want this tool. Peter is a honeybadger, he don't care. He does what he wants.

Peter offers several commandline tools -- so spinning up a tool "webserver" mode
may not be necessary at all -- or might only be needed for brief periods of time.

SQLAlchemy is the underlying database library, so virtually any database can be used
(SQLite, PostgreSQL, MySQL, Oracle, mssql, etc). `SQLite` is the default, but
the package has been deployed against PostgreSQL. SQLite is actually kind of great,
because a single `.sqlite` file can be sftp'd on-to and off-of different machines
for distribution and local viewings.

Peter only uses the Cryptography package, support for PyOpenSSL was dropped.


How?
-----

There are 2 main libraries:

* The paired
  [Lua-Resty Peter_SSLers](https://github.com/aptise/lua-resty-peter_sslers)
  project, an [OpenResty](https://github.com/openresty/openresty) Lua module
  that enables Dynamic SSL Certificate Handling on the `Nginx` webserver.

* This Python library, [Peter_SSLers](https://github.com/aptise/peter_sslers),
  which provides:
  * Commandline Tools
  * A webserver application for obtaining and managing certificates
    * designed for JSON/API programmatic usage
    * usable by humans with simplified html
  * An isolated library and model for building custom applications

Provisioning Certificates and initial orders are currently done through the web
interface.

Renewing Certificates can be done via two methods:

* If the web application is running, it can renew certificates
* A commandline routine will spin up a webserver to answer challenges if needed

Current support for ACME Challenge Types:

* HTTP-01: answered by the native webserver
* DNS-01: domains will be registered with a global acme-dns server
* TLS-ALPN-01: support is not currently planned



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

* Certificate Management
* Certificate Procurement
* Manual Renewal
* Programmatic Renewal
* Interrogating and syncing against ACME Servers
* Queuing new Domains for Certificate Provisioning
* Automatic Renewal
* Backup Certificates
* ARI Monitoring

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
| Renew Certificate | Yes |
| Deactivate Account | Yes |
| Account Key Rollover | Yes |
| Automatic Renewal Information | Yes |
| EAB | No [1] |
| IP Address Certificates | No [2] |

[1] EAB is not implemented due to the lack of need. This may one day change.

[2] The foundation for IP Address Certificates has been completed, but the support
is not feature complete.


The Components
==============

"Peter SSLers" - a `Pyramid` Application
----------------------------------------

"Peter SSLers" is the core toolkit. It is a
[Pyramid](https://github.com/pylons/pyramid) application that can be spun up as a
webserver or used via a commandline interface. Peter is your friend and handles all
of the Certificate Management and translation functions for you.  He's a bit
eccentric, but basically a good guy.

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

[OpenResty](https://github.com/openresty/openresty) is a fork of the nginx
webserver which offers a lot of programmatic hooks (similar to Apache's mod_perl).
One of the many hooks allows for programmatic determination and loading of SSL
Certificates based on the hostname.

A tiered waterfall approach is used to aggressively cache Certificates:

* initial attempt: `nginx` worker memory
* failover 1:  `nginx` shared memory
* failover 2: centralized `redis` server
* failover 3: querying the `Peter SSLers` `Pyramid` application

The [Pyramid](https://github.com/pylons/pyramid) application can be used to prime
and clear each cache level.

SSLX, I'm your only friend. SSLX, Your love will sing for you.

Available via the opm package manager:

    opm get lua-resty-peter_sslers

The source and docs are available on a separate github repository:

* https://github.com/aptise/lua-resty-peter_sslers


"Routines" and Scripts
----------------------------------------

Several "routines" and scripts are provided for commandline invocation:

Routines for cron:

* periodic_tasks
  This routine runs all the other routines on a schedule
  * on first run:
    * it generates a line to enter into your crontab, using an random minute
    * a json file is created that lists which hours the other routines will be run
  * on subsequent runs:
    * the json file is loaded and tasks are dispatched

  The crontab should be installed to run every hour on a set minute, said set minute
  recommended by the periodic_tasks script.  The scheduler will figure out what to run
  on a given hour.

  If certs need to be ordered, a WSGI server running on :config.ini:`http_port.renewals`
  will be spun up to answer AcmeChallenges in a subprocess. Whatever server is
  listening to port80 should proxy to this server.  This server only responds to
  public URLs.
  
  `periodic_tasks` is designed to run every core routine on an hourly basis.

  If alternate invocation strategies are required, there is a specific commandline
  routine for each task which can be used instead.

Please read the
[Automation Guide](https://github.com/aptise/peter_sslers/blob/main/docs/Automation.md)
for more details and additional routines.


ToDo
=====

See `TODO.txt`


Getting Started
===============

Please read the
[Full Installation Instructions](https://github.com/aptise/peter_sslers/blob/main/docs/Installation.md)

There is also a
[QuickStart](https://github.com/aptise/peter_sslers/blob/main/docs/QuickStart.md)

The abridged version:

```
mkdir certificate_admin
cd certificate_admin
virtualenv peter_sslers-venv
source peter_sslers-venv/bin/activate
git clone https://github.com/aptise/peter_sslers.git
cd peter_sslers
$VENV/bin/pip3 install -e .
mkdir data_development
co example_configs/development.ini data_development/config.ini
vi data_development/config.ini
$VENV/bin/initialize_peter_sslers_db data_development
$VENV/bin/import_certbot data_development dir=/etc/letsencrypt
$VENV/bin/pserve data_development/config.ini
```


Full Documentation
==================

* [QuickStart](https://github.com/aptise/peter_sslers/blob/main/docs/QuickStart.md)
* [Installation](https://github.com/aptise/peter_sslers/blob/main/docs/Installation.md)
* [Configuration Options](https://github.com/aptise/peter_sslers/blob/main/docs/Configuration_Options.md)
* [General_Management_Concepts](https://github.com/aptise/peter_sslers/blob/main/docs/General_Management_Concepts.md)
* [Implementation_Details](https://github.com/aptise/peter_sslers/blob/main/docs/Implementation_Details.md)
* [Automation](https://github.com/aptise/peter_sslers/blob/main/docs/Automation.md)
* [Frequently Asked Questions](https://github.com/aptise/peter_sslers/blob/main/docs/Frequently_Asked_Questions.md)
* [Misc](https://github.com/aptise/peter_sslers/blob/main/docs/Misc.md)
* [Tools](https://github.com/aptise/peter_sslers/blob/main/docs/Tools.md)
* [Tests](https://github.com/aptise/peter_sslers/blob/main/docs/Tests.md)
* [Versioning](https://github.com/aptise/peter_sslers/blob/main/docs/Versioning.md)


Related Projects
==================
* [aptise/lua-resty_peter_sslers](https://github.com/aptise/lua-resty-peter_sslers)
* [aptise/cert_utils](https://github.com/aptise/cert_utils)
* OpenResty
  * [Github Source](https://github.com/openresty/openresty)
  * [Project Homepage](https://openresty.org)
* Pyramid
  * [Github Source](https://github.com/pylons/pyramid)
  * [Project Homepage](https://trypyramid.com)
