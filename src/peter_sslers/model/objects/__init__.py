"""
Coding Style:

    class Foo():
        columns
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        relationships
        constraints
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        properties/functions

IMPORTANT

Under Pyramid, the `request` is stashed into the db session

    # stashed in peter_sslers/web/models/__init__.py
    request = dbSession.info["request"]


    There are two ways of getting an object's session in SQLAlchemy

    1. Legacy Classmethod

        dbSession = sqlalchemy.orm.session.Session.object_session(self)

    2. Modern Runtime API

        dbSession = sa_inspect(self).session

    The Legacy Method is faster and not deprecated.
    The Modern Method is preferable in situations where you may do other
    things with the object's runtime information.

    In this project, we will opt for the legacy system


"""

# ==============================================================================

# import order matters here
from .objects import *  # noqa: F401,F403
from .aliases import *  # noqa: E402,F401,F403,I100
from . import advanced_relationships  # noqa: I100,F401
