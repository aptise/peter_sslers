from sqlalchemy import engine_from_config
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import configure_mappers
import zope.sqlalchemy

# import or define all models here to ensure they are attached to the
# Base.metadata prior to any initialization routines
from .models import *  # flake8: noqa

# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()


def get_engine(settings, prefix="sqlalchemy."):
    return engine_from_config(settings, prefix)


def get_session_factory(engine):
    factory = sessionmaker()
    factory.configure(bind=engine)
    return factory


def get_tm_session(request, session_factory, transaction_manager):
    """
    Get a ``sqlalchemy.orm.Session`` instance backed by a transaction.

    This function will hook the session to the transaction manager which
    will take care of committing any changes.

    - When using pyramid_tm it will automatically be committed or aborted
      depending on whether an exception is raised.

    - When using scripts you should wrap the session in a manager yourself.
      For example::

          import transaction

          engine = get_engine(settings)
          session_factory = get_session_factory(engine)
          with transaction.manager:
              dbsession = get_tm_session(request, session_factory, transaction.manager)

    """
    dbSession = session_factory()
    zope.sqlalchemy.register(
        dbSession, transaction_manager=transaction_manager, keep_session=True
    )

    if request is not None:

        def _cleanup(request):
            dbSession.close()

        request.add_finished_callback(_cleanup)
    return dbSession


def get_session_simple(request, session_factory):
    """just gets a session wiuthout any transaction registration"""
    dbSession = session_factory()
    if request is not None:

        def _cleanup(request):
            dbSession.close()

        request.add_finished_callback(_cleanup)
    return dbSession


def includeme(config):
    """
    Initialize the model for a Pyramid app.

    Activate this setup using ``config.include('peter_sslers.models')``.

    """
    settings = config.get_settings()

    # use pyramid_tm to hook the transaction lifecycle to the request
    config.include("pyramid_tm")

    session_factory = get_session_factory(get_engine(settings))
    config.registry["dbSession_factory"] = session_factory

    # make request.dbSession available for use in Pyramid
    config.add_request_method(
        # r.tm is the transaction manager used by pyramid_tm
        lambda r: get_tm_session(r, session_factory, r.tm),
        "dbSession",
        reify=True,
    )

    # our logger
    engine = get_engine(settings, prefix="sqlalchemy_logger.")
    session_factory_logger = sessionmaker(bind=engine, autocommit=True)
    config.registry["dbSessionLogger_factory"] = session_factory_logger
    config.add_request_method(
        lambda r: get_session_simple(r, session_factory_logger),
        "dbSessionLogger",
        reify=True,
    )
