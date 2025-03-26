* [Previous - README](https://github.com/aptise/peter_sslers/README.md)
* [Installation](https://github.com/aptise/peter_sslers/blob/main/docs/Installation.md)

If you want a quick testdrive, this quickstart should suffice.

Otherwise, jump to the full Installation directions.

# QuickStart

If you just want to give this a quick go to explore your Certbot data:

    # make a new directory
    mkdir certificate_admin
    cd certificate_admin

    # create and engage a dedicated python virtualenv
    virtualenv peter_sslers-venv
    source peter_sslers-venv/bin/activate

    # close the repo
    git clone https://github.com/aptise/peter_sslers.git
    cd peter_sslers
    pip install -e .
    initialize_peter_sslers_db conf/example_development.ini
    import_certbot conf/example_development.ini
    pserve --reload  conf/example_development.ini

Then you can visit `http://127.0.0.1:7201/.well-known/peter_sslers`

Note: you can invoke `import_certbot` with any path to a Certbot directory:

    import_certbot conf/example_development.ini dir=/path/to/etc/letsencrypt


# Initial Actions

Upon visiting the main page for the first time:

    http://127.0.0.1:7201/.well-known/peter_sslers

You should be alerted that the Global "EnrollmentPolicy" has not yet been configured.

## Configuring an EnrollmentPolicy

An `EnrollmentPolicy` set the defaults for managing orders in several contexts:

* "global" applies to every context, unless another policy overrides it.
* "autocert" applies to domains ordered through the `autocert` mechanism
* "certificate-if-needed" applies to domains ordered through the `certificate-if-needed` mechanism

Each policy defines things like:

* Which ACME Account(s) to use?  A primary and backup can be configured.
* Should an ACME "profile" be communicated to the server?
* What kinds of PrivateKeys should be used?
* When should PrivateKeys be recycled?

In order to configure the "global" EnrollmentPolicy, you must first set up at lease one AcmeAccount.

There are instructions in the README_DEVELOPEMENT for running local instances of the Pebble test server.

The "global" policy only allows you to specify:

* Primary AcmeAccount [required]
* Backup AcmeAccount [optional, and must be on a different AcmeServer than the Primary Account]

For simplicity, the "global" EnrollmentPolicy will always invoke the "account defaults" for the other settings.

The other EnrollmentPolicy ("autocert", "certificate-if-needed") will allow you to set specific defaults for
various settings.

Configuring a Backup Account is not required, but recommended.

The other EnrollmentPolicy options do not need to be configured *unless* you want to use those systems.


### EnrollmentPolicy Details

All EnrollmentPolicys require a Primary ACME Account; a Backup ACME Account is supported.

Backup AcmeAccounts MUST be on a separate ACME Server.

Currently, Enrollment Policies support the following fields for each type (Primary or Backup)

1. AcmeAccount
2. PrivateKey Technology - Specify a KeyType, or default to the AcmeAccount's configuration
   e.g. RSA_2048, EC_P256
3. PrivateKey Cycling  - Specify a Cycle, or default to the AcmeAccount's configuration
    e.g. single use, reuse for 1 year, use an account daily/weekly key
4. ACME Profile - `@` will invoke the AcmeAccount's default; blank will submit blank


### Autocert and Certificate-if-Needed

These policies are used to automatically create the RenewalConfigurations for Autocert and CIN orders


# Renewal and Backup Certificates

Renewal and ordering (unordered) Backup Certificates can happen two ways:

* on demand through the web interface
* through a commandline routing, `routine__automatic_orders`

Routines are invoked with a configuration file and can be installed into schedulers like cron.

    routine__run_ari_checks conf/production.ini
    routine__automatic_orders conf/production.ini

The `routine__run_ari_checks` command will update stale ARI data for certificates

The `routine__automatic_orders` command will do two things:
* Order missing certificates from active RenewalConfigurations (backup or primary)
* Renew expired certificates

If "Automatic Orders" occur via web interface, the web application itself will answer the challenges.  Traffic from port 80 must be directed to the port configured for `admin_server` in the `.ini` file.

If "Automatic Orders" occur via commandline, a web application limited to the public routes (not the admin interface) will spin up on the port identified by `http_port.renewals` in the `.ini` file.


