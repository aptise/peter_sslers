# stdlib
from typing import Any
from typing import Type
from typing import TYPE_CHECKING
from typing import Union

# pypi
from sqlalchemy import engine_from_config
from sqlalchemy.orm import sessionmaker
import zope.sqlalchemy

# from sqlalchemy import event

# local
# import the SqlAlchemy model, which will call `sqlalchemy.orm.configure_mappers`
from ... import model  # noqa: F401

if TYPE_CHECKING:
    from pyramid.config import Configurator
    from pyramid.request import Request
    from sqlalchemy.engine.base import Engine
    from sqlalchemy.orm import scoped_session
    from sqlalchemy.orm.session import Session
    import transaction

    _TYPES_SESSION = Union[Type[Session], scoped_session[Any], sessionmaker[Session]]

# ==============================================================================


# standard decorator style
# @event.listens_for(SomeSessionOrFactory, 'persistent_to_detached')
def receive_persistent_to_detached(session: "_TYPES_SESSION", instance) -> None:
    print("persistent_to_detached", id(session), instance.__class__)


def get_engine(
    settings: "Configurator",
    prefix: str = "sqlalchemy.",
) -> "Engine":
    return engine_from_config(settings, prefix)


def get_session_factory(engine: "Engine") -> "_TYPES_SESSION":
    factory = sessionmaker()
    factory.configure(bind=engine)
    # factory.configure(expire_on_commit=False)
    # event.listen(factory, "persistent_to_detached", receive_persistent_to_detached)
    return factory


def get_tm_session(
    request: "Request",
    session_factory: "_TYPES_SESSION",
    transaction_manager: "transaction.manager",
):
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
    # cache our request into dbSession.info
    # https://docs.sqlalchemy.org/en/13/orm/session_api.html?highlight=session%20info#sqlalchemy.orm.session.sessionmaker.params.info
    dbSession = session_factory(info={"request": request})
    zope.sqlalchemy.register(
        dbSession, transaction_manager=transaction_manager, keep_session=True
    )

    if request is not None:

        def _cleanup(request):
            dbSession.close()

        request.add_finished_callback(_cleanup)

    return dbSession


def includeme(config: "Configurator") -> None:
    """
    Initialize the model for a Pyramid app.

    Activate this setup using ``config.include('peter_sslers.models')``.

    """
    settings = config.get_settings()  # self.registry.settings

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
