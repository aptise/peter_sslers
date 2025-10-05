Alembic
=======

Alembic is used to handle database schema changes and migrations.


Alembic Setup
=============


Alembic Configuration
---------------------

This Albembic installation is configured by the interaction of the following
three (3) files::

* `/pyproject.toml` specifies `/alembic` as the core Alembic directory under `[tool.alembic]`

* `/alembic/env.py` controls the main alembic configuration

* `/{{ENVIRONMENT}}/config.ini` specifies an `sqlalchemy.url` under `[alembic]`



Alembic Initialization
----------------------

When the database is created via::

    initialize_peter_sslers_db data_testing

The last two lines setup alembic::    
        
    alembic_cfg = alembic.config.Config(config_uri, toml_file="pyproject.toml")
    alembic.command.stamp(alembic_cfg, "head")


Late to the party?
------------------

If alembic is not initialized and you manually ran some migrations, trick it!

    alembic -c data_development/config.ini stamp 0c3414079bfe  



Developer Instructions
======================

Creating Revisions with AutoGenerate
------------------------------------

    # a sample config is required for db inspection
    alembic -c data_development/config.ini revision --autogenerate -m "stub"    

For more info, see https://alembic.sqlalchemy.org/en/latest/autogenerate.html


Applying Revisions
------------------


Upgrade
~~~~~~~

    alembic -c data_development/config.ini upgrade head

Downgrade
~~~~~~~~~

    alembic -c data_development/config.ini downgrade {ID}

or

    alembic -c data_development/config.ini downgrade base
    

Example Flow A
--------------

1. Modify objects.py

2. Run `alembic autogenerate`
    
    alembic -c data_development/config.ini revision --autogenerate -m "revision_name"

3. Run `alembic upgrade`

    alembic -c data_development/config.ini upgrade head


Troubleshooting
--------------

When troubleshooting a revision generation/application, the following flow has
been useful::

Preparation
~~~~~~~~~~~

Ensure there is a backup version of the environment configuratoin

    cp -Rp data_development data_development-backup

Commands
~~~~~~~~

    # reset
    rm data_development/ssl_minnow.sqlite && \
    cp -Rp data_development-backup/ssl_minnow.sqlite data_development

    # generate revision
    alembic -c data_development/config.ini revision --autogenerate -m "test_revision"

    # apply revision
    alembic -c data_development/config.ini upgrade head
    # or
    # alembic -c data_development/config.ini upgrade 5bfca3b856ff
    
    # inspect database
    sqlite3 data_development/ssl_minnow.sqlite
    
    # create a revision to ensure we got everything
    alembic -c data_development/config.ini revision --autogenerate -m "check"
    
    # ---

    # downgrade
    alembic -c data_development/config.ini downgrade 0c3414079bfe

    # inspect database
    sqlite3 data_development/ssl_minnow.sqlite


Related
=======

Earlier non-Alembic migration scripts could break foreign key support.

To fix that, dump, edit, and load the database.

The editing is to search for the string `REFERENCES "`,
 which will match `REFERENCES "(table)"`

    cd data_env
    mv ssl_minnow.sqlite _ssl_minnow-backup.sqlite
    sqlite3 _ssl_minnow-backup.sqlite .dump > ssl_minnow.sql
    vi ssl_minnow.sql
    sqlite3 ssl_minnow.sqlite < ssl_minnow.sql





















