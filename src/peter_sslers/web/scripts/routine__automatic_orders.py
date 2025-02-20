# stdlib
import os
import sys

# pypi
from pyramid.paster import get_appsettings
from pyramid.paster import setup_logging
from pyramid.scripts.common import parse_vars
import transaction

# local
from . import _disable_warnings  # noqa: F401
from ..models import get_engine
from ..models import get_session_factory
from ..models import get_tm_session
from ...lib import db as lib_db
from ...lib.config_utils import ApplicationSettings
from ...lib.utils import ApiContext
from ...lib.utils import RequestCommandline
from ...model.meta import Base

# from ...lib import db as lib_db
# from ...lib.config_utils import ApplicationSettings

# ==============================================================================


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> [var=value]\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])
    setup_logging(config_uri)

    settings = get_appsettings(config_uri, options=options)

    application_settings = ApplicationSettings(config_uri)
    application_settings.from_settings_dict(settings)

    engine = get_engine(settings)

    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)

    # application_settings = ApplicationSettings(config_uri)
    # application_settings.from_settings_dict(settings)

    # dbSession = session_factory()
    dbSession = get_tm_session(None, session_factory, transaction.manager)

    ctx = ApiContext(
        dbSession=dbSession,
        request=RequestCommandline(
            dbSession, application_settings=application_settings
        ),
        config_uri=config_uri,
        application_settings=application_settings,
    )

    # actually, we order the backups first
    lib_db.actions.routine__order_missing(
        ctx,
        settings=settings,
        DEBUG=True,
    )

    # then we renew the expiring
    lib_db.actions.routine__renew_expiring(
        ctx,
        settings=settings,
        DEBUG=True,
    )

    exit()
