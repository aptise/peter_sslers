* [Previous - Automation](https://github.com/aptise/peter_sslers/blob/main/docs/Automation.md)
* [Next - Misc](https://github.com/aptise/peter_sslers/blob/main/docs/Misc.md)

# FAQ

## Is this secure?

Nothing is truly secure, is it?

PeterSSLers stores Certificates and PrivateKeys in plaintext - just like Certbot
and most LetsEncrypt Clients store their assets.

The project splits the web-based views into two concepts: Public and Admin.

The
[Public Views](https://github.com/aptise/peter_sslers/blob/main/peter_sslers/web/views_public)
are isolated to the '/.well-known/acme-challenge` directory, and expose the same
information as every other LetsEncrypt Client. These routes are generally safe.

The
[Admin Views](https://github.com/aptise/peter_sslers/blob/main/peter_sslers/web/views_admin)
are isolated to the '/.well-known/peter_sslers` directory; while these routes can be
extremely dangerous, a reasonably competent security policy can be implemented to
make this section of the application suite password protected and/or available
only to local network traffic.

The [SQLAlchemy Project](https://sqlalchemy.org) is used to handle database activity.
SQLAlchemy's ORM uses bind parameters and is inherently safe from SQL Injection Attacks.

Like any other project, it is possible to expose Private Keys to the public internet --
but it is also possible to ensure that never happens.

## Does this reformat Certificates?

Yes. PEM certs are reformatted to have a single trailing newline (via stripping
then padding the input) and newlines are standardized to unix ("\n"). This seems
to be one of the more common standards utilized when saving Certificates.
Certificates may be reformatted for compliance with other details of open standards.
The actual contents of Certificates are unchanged.


## Is there a fast way to import existing Certificates?

If the certificates are on the same server, the `import_certbot` script will
parse and enroll all of the Certbot data directly into the database.

If the certificates are on another server, the *TOOLS* section has an
 `invoke` script that can automate importing Certificates and other data from
the Cerbot data store.  The "invoke" tools
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
Certbot Client are reformatted into PEM-encoded RSA or EC key.  The data from the various
json files are archived into the database for use later. The account data is anayzed
for the actual environment it is registered with, and that becomes part of the
AcmeAccount record.


## Where does the various data associated with Certificates come from?

When imported, Certificates are decoded and parsed for data.

When generated via the ACME protocol, Certificate data is provided in the headers.

Useful fields are duplicated from the cCrtificate into SQL to allow for better
searching. Certificates are not changed in any way, aside from the cleanup of
whitespace and/or other formatting concerns.


## Import LetsEncrypt Data?

After running the server, in another window...

- $VENV/bin/pip install invoke
- cd tools
- $VENV/bin/invoke import-certbot-certs-archive --archive-path='/etc/letsencrypt/archive' --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers'


There is also a button under "operations" to sync LetsEncrypt's public website
and update your certs with data, however the current codebase ships with these
CA Certificates pre-loaded.


## How to check if it's working?

The Lua script for SSL certificate handling makes a handful of `DEBUG` and `NOTICE`
calls during certain actions. `Nginx` typically ignores `DEBUG` unless you enable
it at configuration/build time.

After querying the server, you can check the `Redis` server directly to see if
keys are being set. Assuming `Redis` is configured to use 127.0.0.1:6379:9

    workstation username$ redis-cli
    127.0.0.1:6379> select 9
    OK
    127.0.0.1:6379[9]> keys *

This should then show a bunch of keys. If not, you have a problem.

You can also query nginx directly for status. Please note, the status route is
configurable:

    https://example.com/.peter_sslers/nginx/shared_cache/status

The payload might look like:

    {
        "servers_status": {
            "errors": [],
            "success": [
                "http://127.0.0.1"
            ],
            "servers": {
                "http://127.0.0.1": {
                    "note": "This is a max(1024) listening of keys in the ngx.shared.DICT `cert_cache`. This does not show the worker's own LRU cache, or Redis.",
                    "keys": {
                        "valid": [
                            "example.com"
                        ],
                        "invalid": [
                            "127.0.0.1"
                        ]
                    },
                    "config": {
                        "expiries": {
                            "resty.lrucache": 15,
                            "ngx.shared.cert_cache": 45
                        },
                        "maxitems": {
                            "resty.lrucache": 200
                        }
                    },
                    "result": "success"
                }
            }
        },
        "result": "success"
    }

If you start to see valid/invalid keys disappear it is often because the `expiries`
or `maxitems` have removed them from the cache.


## Are Alternate Chains Supported?

LetsEncrypt and other ACME Certificate Authorities may support "Alternate Chains"
of their signed Certificates that lead to different trusted roots.

Alternate Chains are fully supported by PeterSSLers

* All Alternate CertificateCAChains are downloaded and tracked
* Machine-readable Endpoints are available to detect and utilize the Alternate Chains
* Default UX, payloads and endpoints are optimized for the Primary Chain
* Default payloads may be configured to enforce a chain preference, so alternate
  chains can override the default chain


## Can Certificates be saved to disk?

Yes. RenewalConfigurations and EnrollmentFactories can be configured to persist
the most recent Certificate onto disk - both automatically and on demand.

PeterSSLers does not offer deployment hooks and has no plans to. PeterSSLers
offers a programmatic API and python library for interacting with the datastore.

Instead of trying to jam a deployment script into the Certificate Provisioning
process, the preferred method is to either:

1- Write a deployment script that utilizes the programmatic API, or
2- Monitor PeterSSLers API or on-disk storage for changes.


## Why are incorrect plural spellings used?

Nice catch.  English can be a difficult language for non-native learners, as words
can be pluralized in different ways.

In an effort to make things more accessible, this project breaks some grammar rules
and strives to just add an "s" for plurals:

For instance, the second example below may be confusing to non-native users:

    acme-account > acme-accounts
    enrollment-factory > enrollment-factories

To accomodate that, bad grammar is used:

    acme-account > acme-accounts
    enrollment-factory > enrollment-factorys
    
Although this breaks language rules, the intent and meaning is clear and a larger
English vocabulary is not needed to understand this.


## What does it look like?

PeterSSLers was designed to be used on terminals, so it looks great on Lynx...

![Admin Index - Lynx](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/lynx_01-admin_index.png)
![Admin Index - Lynx](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/lynx_02-api_docs.png)

And most endpoints offer JSON versions, so you can process everything that way~

But... This project uses bootstrap, so it looks fine on browsers!

![Admin Index](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/01-admin_index.png)
![CSR: Automate 'manual': Enter Domains](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/02-enter_domains.png)
![CSR: Automate 'manual': Enter  AcmeChallenges](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/03-enter_challenge.png)
![CSR: Check Verification Status](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/04-view_status.png)
![CSR: New FULL](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/09-new_csr.png)
![Operations Log](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/05-operations_log.png)
![List: Authority Certificates](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/06-certificate_cas.png)
![Focus: Authority Certificate](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/07-certificate_cas_focus.png)
![Upload Existing Certificates](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/10-upload_cert.png)
![List Certificates](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/11-certificates_list.png)
![List Domains](https://raw.github.com/aptise/peter_sslers/blob/main/docs/images/12-domains_list.png)
