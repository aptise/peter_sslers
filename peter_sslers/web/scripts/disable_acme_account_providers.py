from __future__ import print_function

# stdlib
import os
import sys

# pypi
import transaction
from pyramid.paster import get_appsettings, setup_logging
from pyramid.scripts.common import parse_vars

# local
from ...model.meta import Base
from ...model.objects import AcmeAccountProvider
from ..models import get_engine, get_session_factory, get_tm_session


# ==============================================================================


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> [var=value]\n"
        '(example: "%s example_development.ini")' % (cmd, cmd)
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

    with transaction.manager:
        dbSession = get_tm_session(None, session_factory, transaction.manager)
        dbAcmeAccountProviders = dbSession.query(AcmeAccountProvider).all()
        for acmeAccountProvider in dbAcmeAccountProviders:
            _disabled = acmeAccountProvider._disable()

    transaction.commit()
