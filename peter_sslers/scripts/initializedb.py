import os
import sys
import transaction

from sqlalchemy import engine_from_config

from pyramid.paster import (get_appsettings,
                            setup_logging,
                            )

from pyramid.scripts.common import parse_vars

from ..models.meta import Base
from ..models import (
    get_engine,
    get_session_factory,
    get_tm_session,
)
from ..models import models


def usage(argv):
    cmd = os.path.basename(argv[0])
    print('usage: %s <config_uri> [var=value]\n'
          '(example: "%s example_development.ini")' % (cmd, cmd))
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
    if engine.name == 'sqlite':
        engineLogger = get_engine(settings, prefix='sqlalchemy_logger.')
        Base.metadata.create_all(engineLogger, tables=[models.SslAcmeEventLog.__table__, models.SslAcmeChallengeLog.__table__, ])
    session_factory = get_session_factory(engine)

    # with transaction.manager:
    #    dbSession = get_tm_session(None, session_factory, transaction.manager)
    #    model = MyModel(name='one', value=1)
    #    dbSession.add(model)
