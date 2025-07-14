Alembic
=======

Alembic is used to handle database schema changes and migrations.


Alembic Setup
=============


Alembic Configuration
---------------------

Albembic is configured by the interaction of the following three (3) files::

* `/pyproject.toml` specifies `/alembic` as the core Alembic directory under `[tool.alembic]`

* `/alembic/env.py` controls the main alembic configuration

* `/{{ENVIRONMENT}}/config.ini` specifies an `sqlalchemy.url` under `[alembic]`



Alembic Initialization
----------------------

When the database is created via::

    initialized_db data_testing

The last two lines setup alembic::    
        
    alembic_cfg = alembic.config.Config(config_uri, toml_file="pyproject.toml")
    alembic.command.stamp(alembic_cfg, "head")





Developer Instructions
======================

pyproject configuration, based on the generic configuration.

Creating Revisions

    alembic revision -m "create account table"

Applying Revisions

    alembic -c data_development/config.ini upgrade head
    alembic -c data_development/config.ini downgrade base
    
See https://alembic.sqlalchemy.org/en/latest/autogenerate.html

    alembic -c data_development/config.ini revision --autogenerate -m "stub"
    
    
Example:


1. Modify objects.py

2. Run `alembic autogenerate`
    
    alembic -c data_development/config.ini revision --autogenerate -m "rate_limited"

3. Run `alembic upgrade`

    alembic -c data_development/config.ini upgrade head
