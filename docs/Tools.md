# Tools

## commandline routines

Some routines are accessible via commandline scripts:

* `routine__run_ari_checks {example_development.ini}` will run necessary ARI checks

* `routine__clear_old_ari_checks {example_development.ini}` will clear from the database outdated ARI checks.  An ARI check is considered outdated once it has been replaced with a newer ARI check.


* `update_filepaths {example_development.ini}` will export PEM certificate data onto the filesystem, with the following implementation details:

  * data will be written to a `certificates` subfolder of the `_data_` directory
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

    _data_/certificates/global/rc-1/primary/cert.pem
    _data_/certificates/global/rc-1/primary/chain.pem
    _data_/certificates/global/rc-1/primary/fullchain.pem
    _data_/certificates/global/rc-1/primary/pkey.pem
    _data_/certificates/global/rc-1/backup/cert.pem
    _data_/certificates/global/rc-1/backup/chain.pem
    _data_/certificates/global/rc-1/backup/fullchain.pem
    _data_/certificates/global/rc-1/backup/pkey.pem
    _data_/certificates/factory_a/rc-2/primary/cert.pem
    _data_/certificates/factory_a/rc-2/primary/chain.pem
    _data_/certificates/factory_a/rc-2/primary/fullchain.pem
    _data_/certificates/factory_a/rc-2/primary/pkey.pem
    _data_/certificates/factory_a/rc-2/backup/cert.pem
    _data_/certificates/factory_a/rc-2/backup/chain.pem
    _data_/certificates/factory_a/rc-2/backup/fullchain.pem
    _data_/certificates/factory_a/rc-2/backup/pkey.pem
    _data_/certificates/factory_a/example.com >symlink> rc-2
    

## `invoke` Script

There is an `invoke` script in the `tools` directory that can be used to automate
certain tasks.

Right now the invoke script offers:

* `import-certbot-certs-archive` given a directory of your local LetsEncrypt archive
  (which has versioned certs), it will import them all into a server of your choice.
* `import-certbot-certs-live` given a directory of your local LetsEncrypt install, it
  will import the active onesinto a server of your choice.
* `import-certbot-cert-version` given a specific directory of your LetsEncrypt archive,
  it will import specific items
* `import-certbot-cert-plain` given a directory of an unversioned Certificate (like a
  particular directory within the "live" directory), will import it.

* `import-certbot-account` import a specific LetsEncrypt account
* `import-certbot-accounts-server` import all accounts for a LetsEncrypt server
  (i.e. v1, v1-staging)
* `import-certbot-accounts-all` import all accounts for all LetsEncrypt servers


## Commandline Interface

You can interact with this project via a commandline interface in several ways.

* Run a webserver instance and query JSON urls or use a browser like lynx.
* Run explicit routes via `prequest`. This allows you to do admin tasks without
  spinnig up a server.


## `OpenResty`/`Nginx` Lua integration

The `OpenResty`/`Nginx` implementation was migrated to a dedicated sibling repository,
handled by `opm` distribution.

* Github Source: https://github.com/aptise/lua-resty-peter_sslers

Installation Instructions:

    opm get lua-resty-peter_sslers


## prequest

You can use Pyramid's `prequest` syntax to spin up a URL and GET/POST data

`$VENV/bin/prequest -m POST example_development.ini /.well-known/peter_sslers/api/redis/prime.json`

Using `prequest` is recommended in most contexts, because it will not timeout.
This will allow for long-running processes.

