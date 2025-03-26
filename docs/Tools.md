# Tools

The "/tools" directory contains scripts useful for Certificate operations.
Currently this includes:

* An `invoke` script for importing Certbot archives, and potentially other tasks.
* A sample `fake_server.py` that will spin up a web server with routes which you can
  test against. This will allow you to setup your proxy integration without running
  peter_sslers itself. Responses include the header: `X-Peter-SSLers: fakeserver`.
* A `replace_domain.py` script that can be used to alter an `acme-dns` database
  to support deterministically named DNS subdomains instead of the default randomized
  guid subdomains.


## `invoke` Script

There is an `invoke` script in the `tools` directory that can be used to automate
certain tasks.

The invoke scripts often duplicate, in an inferior manner, the Python scripts described
in the Automation docs. The other Python scripts operate directly on the underlying
database, while the invoke scripts use an HTTPS interface.

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

