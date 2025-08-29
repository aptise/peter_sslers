* [Previous - Implementation_Details](https://github.com/aptise/peter_sslers/blob/main/docs/Implementation_Details.md)
* [Next - Frequently_Asked_Questions](https://github.com/aptise/peter_sslers/blob/main/docs/Frequently_Asked_Questions.md)

# Automation

## Onboarding

To facilitate repetitive onboarding, the concept of "EnrollmentFactorys" was created.

An EnrollmentFactory defines the following for re-use,
which can be quickly turned into a RenewalConfiguration.

    AcmeAccount(s) for Primary (and optionally backup) Certificate(s)
    PrivateKey Technology
    PrivateKey Cycling
    ACME profile
    Domain Template

### Domain Template

The Domain Template concept is unique to an Enrollment Factory.

The template will accept a single domain name, and then expand it as needed.

For example, given the following template:

    {DOMAIN}, www.{DOMAIN}, mail.{DOMAIN}

It would become expended for `example.com` into:

    example.com, www.example.com, mail.example.com

An Enrollment Factory features separate templates for HTTP-01 and DNS-01 challenges

By defining an Enrollment Factory, new clients/domains can be easily on-boarded


## Routines

Several routines are designed for integration with cron scheduling:

### periodic_tasks
  This routine runs all the other routines on a schedule
  * on first run:
    * it generates a line to enter into your crontab, using an random minute
    * a json file is created that lists which hours the other routines will be run
  * on subsequent runs:
    * the json file is loaded and tasks are dispatched

  The crontab should be installed to run every hour on a set minute, said set minute
  recommended by the periodic_tasks script.  The scheduler will figure out what
  routines to run on a given hour.

  `periodic_tasks` is designed to run every core routine on an hourly basis.

  If alternate invocation strategies are required, there is a specific commandline
  routine for each task which can be used instead.


### routine__automatic_orders

This has moderate overhead and should run at least once a day.

This will order certs under the following conditions:

* managed certs that are expiring, based on ARI or notAfter
* active renewal configurations that have not ordered a primary or backup

This routine may require inbound traffic and firewall adjustment.

This routine does two tasks:

1- Orders missing certificates.  When a RenewalConfiguration supporting a backup
certificate is created, only the primary is ordered.  The backup order is deferred
to manual ordering or being picked up by this routine.

2- Renews expiring certificates, based on ARI Data and the certificate's expiry

If certs need to be ordered, a public WSGI server running on
:config.ini:`http_port.renewals` in the `.ini` configuration file will be
started to answer AcmeChallenges in a subprocess. Whatever server is listening
to port80 should proxy traffic to this server.

This server WILL NOT expose the admin urls.

This sever WILL expose the following urls:

* `/.well-known/acme-challenge` - directory
* `/.well-known/public/whoami` - URL prints host

Firewall adjustments may be needed

### routine__clear_old_ari_checks

This routine clears out old ari-checks stored on disk

An ARI check is considered outdated once it has been replaced with a newer ARI check.

### routine__reconcile_blocks

Syncs and tries to complete any pending acme-orders that may be stuck

### routine__run_ari_checks

This is low-overhead and can run hourly, if not multiple times per day.

This routine iterates all the enrolled certificates and polls them for ARI information.

The ARI information is used to hint at renewal time.

This routine does not require inbound traffic or firewall adjustment.


### update_filepaths

If an EnrolmentFactory or RenewalConfiguration is set to persist to disk, this
will ensure the currently exported certificates are the most recent.

* `update_filepaths {env_development/config.ini}` will export PEM certificate data onto the filesystem, with the following implementation details:

  * data will be written to a `certificates` subfolder of the `{DATA_DIR}` directory
  * only certificates with an ACTIVE RenewalConfiguration will be written
  * data will be organized into
    * a `global` directory for certs without an EnrollmentFactory
    * a directory of the EnrollmentFactory's unique name, if there is a factory
  * the name of each director will be `rc-{id}`, wherein `id` is the numeric identifier for the RenewalConfiguration
  * if the RenewalConfiguration has a unique label, a symlink will be created
  * for each certificate, the directory will contain a `primary` and `backup` subdirectory
  * within each subdirectory will be 4 files, like Certbot:
    * `chain.pem`
    * `fullchain.pem`
    * `cert.pem`
    * `pkey.pem`
   * when Certificates are persisted to disk, they will be written to a working directory, that working directory will then replace the existing data directory

For example, a directory structure might look like this:

    data_production_/certificates/global/rc-1/primary/cert.pem
    data_production_/certificates/global/rc-1/primary/chain.pem
    data_production_/certificates/global/rc-1/primary/fullchain.pem
    data_production_/certificates/global/rc-1/primary/pkey.pem
    data_production_/certificates/global/rc-1/backup/cert.pem
    data_production_/certificates/global/rc-1/backup/chain.pem
    data_production_/certificates/global/rc-1/backup/fullchain.pem
    data_production_/certificates/global/rc-1/backup/pkey.pem
    data_production_/certificates/factory_a/rc-2/primary/cert.pem
    data_production_/certificates/factory_a/rc-2/primary/chain.pem
    data_production_/certificates/factory_a/rc-2/primary/fullchain.pem
    data_production_/certificates/factory_a/rc-2/primary/pkey.pem
    data_production_/certificates/factory_a/rc-2/backup/cert.pem
    data_production_/certificates/factory_a/rc-2/backup/chain.pem
    data_production_/certificates/factory_a/rc-2/backup/fullchain.pem
    data_production_/certificates/factory_a/rc-2/backup/pkey.pem
    data_production_/certificates/factory_a/example.com >symlink> rc-2


## Scripts

### ssl_manage

The `ssl_manage` tool tries to implement all core operations.


### acme_dns_audit
    audit acme-dns accounts
    checks credentials and cnames
    generates a CSV for you to handle


### deactivate_duplicate_certificates

It is possible to have multiple certificates due to imports and how renewals work.

For example, failing to renew with "replaces" or choosing no candidates for "replaces"
will create a new "lineage".  A Lineage in PeterSSLers starts with an original
certificate procurement and continues as that certificate is replaced.

This script will automatically disable all duplicates, aka extraneous lineages.

These can also be disabled manually through the admin interface.


### import_certbot
  * directly imports a local certbot directory (unlike `Tools` below, which use the API)

### initializedb
    initial setup script

### refresh_pebble_ca_certs
  * dev tool to refresh the pebble certs when needed

### refresh_roots
   * parses the current installed version of cert_utils to pull new roots and compatability data
   * this will delete data created by previous versions
   * client generated data will be preserved

### register_acme_servers
can be used to :
  * load additional CAs through a json file
  * assign TrustedRoots to existing or new CAs
  * export existing acme-server configurations, in a format that can
    be imported by the same tool
  * Update the SSL Root Stores for an acme server (i.e. the root that secures
    your connection to the CA, not the root the CA's issued certs chain to)





## Routes Designed for JSON Automation

### `/.well-known/peter_sslers/api/deactivate-expired.json`

Deactivate expired Certificates.

### `/.well-known/peter_sslers/api/redis/prime.json`

Prime a `Redis` cache with Domain data.

### `/.well-known/peter_sslers/api/update-recents.json`

Updates Domain records to list the most recent Certificates for the Domain.


## Routes with JSON support

Most routes have support for JSON requests via a `.json` suffix.

These are usually documented on the html version, and via "GET" requests to the
json version.

### `/.well-known/peter_sslers/x509-certificate/upload.json`

This can be used used to directly import Certificates already issued by LetsEncrypt

    curl --form "private_key_file=@privkey1.pem" \
         --form "certificate_file=@cert1.pem" \
         --form "chain_file=@chain1.pem" \
         http://127.0.0.1:7201/.well-known/peter_sslers/x509-certificate/upload.json

    curl --form "private_key_file=@privkey2.pem" \
         --form "certificate_file=@cert2.pem" \
         --form "chain_file=@chain2.pem" \
         http://127.0.0.1:7201/.well-known/peter_sslers/x509-certificate/upload.json

Note the url is not `/upload` like the html form but `/upload.json`.

Both URLS accept the same form data, but `/upload.json` returns json data which
is probably more readable from the commandline.

Errors will appear in JSON if encountered.

If data is not POSTed to the form, instructions are returned in the json.

There is an `invoke` script to automate these imports:

    invoke import-certbot-certs-archive \
           --archive-path='/path/to/archive' \
           --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers'

    invoke import-certbot-cert-version \
           --domain-certs-path="/path/to/ssl/archive/example.com" \
           --certificate-version=3 \
           --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers"

    invoke import-certbot-certs-live \
           --live-path='/etc/letsencrypt/live' \
           --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers'

    invoke import-certbot-cert-plain \
           --cert-path='/etc/letsencrypt/live/example.com' \
           --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers'

If peter_sslers is installed on the same machine: the commandline script
`import_certbot`, which is installed into the shell path via entrypoints, will
yield superior performance as it does not require HTTP.

### `/.well-known/peter_sslers/x509-certificate-trusted/upload-cert.json`

Upload a new CertificateAuthority (LetsEncrypt) Certificate.

### `/.well-known/peter_sslers/x509-certificate-trust-chain/upload-chain.json`

Upload a new CertificateAuthority (LetsEncrypt) Chain.  A chain are the
intermediate certificates.

### `/.well-known/peter_sslers/domain/{DOMAIN|ID}/config.json` Domain Data

`{DOMAIN|ID}` can be the internal numeric id or the Domain name.

Will return a JSON document:

    {"domain": {"id": "1",
                "domain_name": "a",
                },
     "x509_certificate__latest_single": null,
     "x509_certificate__latest_multi": {"id": "1",
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

### `/.well-known/peter_sslers/certificate/{ID}/config.json` Certificate Data

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

* /.well-known/peter_sslers/x509-certificate/{ID}/cert.crt
* /.well-known/peter_sslers/x509-certificate/{ID}/cert.pem
* /.well-known/peter_sslers/x509-certificate/{ID}/cert.pem.txt
* /.well-known/peter_sslers/x509-certificate/{ID}/chain.cer
* /.well-known/peter_sslers/x509-certificate/{ID}/chain.crt
* /.well-known/peter_sslers/x509-certificate/{ID}/chain.der
* /.well-known/peter_sslers/x509-certificate/{ID}/chain.pem
* /.well-known/peter_sslers/x509-certificate/{ID}/chain.pem.txt
* /.well-known/peter_sslers/x509-certificate/{ID}/fullchain.pem
* /.well-known/peter_sslers/x509-certificate/{ID}/fullchain.pem.txt
* /.well-known/peter_sslers/x509-certificate/{ID}/privkey.key
* /.well-known/peter_sslers/x509-certificate/{ID}/privkey.pem
* /.well-known/peter_sslers/x509-certificate/{ID}/privkey.pem.txt

