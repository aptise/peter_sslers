# stdlib
import datetime
import os
import sys

# pypi
from pyramid.paster import get_appsettings
from pyramid.paster import setup_logging
from pyramid.scripts.common import parse_vars
import transaction

# local
from ..models import get_engine
from ..models import get_session_factory
from ..models import get_tm_session
from ...lib.config_utils import ApplicationSettings
from ...lib.db import _setup
from ...lib.utils import ApiContext
from ...model.meta import Base


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

    engine = get_engine(settings)
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)

    application_settings = ApplicationSettings(config_uri)
    application_settings.from_settings_dict(settings)

    with transaction.manager:
        dbSession = get_tm_session(None, session_factory, transaction.manager)

        ctx = ApiContext(
            timestamp=datetime.datetime.now(datetime.timezone.utc),
            dbSession=dbSession,
            request=None,
            config_uri=config_uri,
            application_settings=application_settings,
        )

        # this will setup the initial AcmeServers and the placeholder PrivateKey
        _setup.initialize_database(ctx)

    transaction.commit()
