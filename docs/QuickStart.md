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

