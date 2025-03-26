* [Previous - QuickStart](https://github.com/aptise/peter_sslers/blob/main/docs/QuickStart.md)
* [Next - Configuration Options](https://github.com/aptise/peter_sslers/blob/main/docs/Configuration_Options.md)

# Installation

This is pretty much ready to go for development use.
Production use requires some tweaking by design.

Python should install everything for you.
If it doesn't, someone messed up. That someone was me. Sorry.

You should create a virtualenv for this project. In this example, we will create
the following directory structure:

* `certificate_admin` - core directory
* `certificate_admin/peter_sslers-venv` - dedicated virtualenv
* `certificate_admin/peter_sslers` - git checkout

Here we go...

    mkdir certificate_admin
    cd certificate_admin

    virtualenv peter_sslers-venv
    source peter_sslers-venv/bin/activate

    git clone https://github.com/aptise/peter_sslers.git
    cd peter_sslers
    python setup.py develop
    initialize_peter_sslers_db conf/example_development.ini
    pserve --reload conf/example_development.ini

Then you can visit `http://127.0.0.1:7201`

If you have an active Certbot install, you can import the enture dataset two ways:

1. On the same machine, you can invoke a quick command:

    import_certbot conf/example_development.ini dir=/etc/letsencrypt

2. On remote machines, you can import onto a central installation's database via
an `invoke` command and the web API.  Details are below.

Editing the `example_development.ini` file will let you specify how the package
runs. Some fields are necessary for it to work correctly, they are noted below...

This `Pyramid` application is configured via `.ini` files. You can use multiple
files to deploy the server differently on the same machine, or on different environments.

You can run this on SQLite or switch to PosgtreSQL by adjusting the SQLAlchemy url.

If you run via PosgtreSQL, you will need to setup the database BEFORE running
`initialize_peter_sslers_db`.

Roughly, that entails...

    $ psql -Upostgres
    psql> create user ssl_minnow with password '{PASSWORD}';
    psql> create database ssl_minnow with owner ssl_minnow ;

Some tools are provided to automatically import existing Certificates and Chains
(see below).

It is recommended to open up a new terminal and do the following commands:

    cd certificate_admin
    source peter_sslers-venv/bin/activate
    cd peter_sslers
    pserve  conf/example_development.ini

Then, in a second terminal window, you have two options:

## Option A - Filesystem import (only local machine)

The package installs a `import_certbot` script that will import an existing
Certbot directory structure from the local machine.   You can invoke
`import_certbot` with any path to a Certbot directory:

    cd certificate_admin
    source peter_sslers-venv/bin/activate
    import_certbot conf/example_development.ini dir=/path/to/etc/letsencrypt

## Option B - HTTP import (from any machine)

The package also makes available a series of routines via the `invoke` framework
that can be used to `POST` data from any machine onto a designated PeterSSLers
instance.  This was designed to easily import all the Certbot files from multiple
networked servers onto a centralized system.

    cd certificate_admin
    source peter_sslers-venv/bin/activate
    cd peter_sslers/tools
    invoke import-certbot-certs-live  --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers' --live-path='/etc/letsencrypt/live'
    invoke import-certbot-certs-archive  --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers' --live-path='/etc/letsencrypt/archive'
    invoke import-certbot-accounts-all --accounts-all-path='/etc/letsencrypt/accounts' --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers'

Alternately, you can use shell variables to make the above more readable:

    cd certificate_admin
    source peter_sslers-venv/bin/activate
    cd peter_sslers/tools
    export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
    invoke import-certbot-certs-live --live-path='/etc/letsencrypt/live'
    invoke import-certbot-certs-archive --live-path='/etc/letsencrypt/archive'
    invoke import-certbot-accounts-all --accounts-all-path='/etc/letsencrypt/accounts'

The `prequest` command above will import the current LetsEncrypt Certificates to
get you started.
The first `invoke` command will import existing LetsEncrypt live Certificates
The second `invoke` command will import all existing LetsEncrypt issued Certificates
The third `invoke` command will import existing LetsEncrypt accounts

