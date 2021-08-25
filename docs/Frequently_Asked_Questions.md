* [Previous - Automation](https://github.com/aptise/peter_sslers/docs/Automation.md)
* [Next - Misc](https://github.com/aptise/peter_sslers/docs/Misc.md)

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
