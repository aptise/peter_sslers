"""
This file is used to test out migrations
it is checked into source, but not an entrypoint
this is a development tool only

example:

    python -m peter_sslers.web.scripts.workspace_migrations conf/example_development.ini

"""

from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import sys

# pypi
from pyramid.paster import get_appsettings
from pyramid.scripts.common import parse_vars

# local
from ...lib import db as lib_db  # noqa: F401
from ...lib.utils import new_scripts_setup

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

    settings = get_appsettings(config_uri, options=options)  # noqa: F841

    ctx = new_scripts_setup(config_uri, options=options)

    if False:
        from ...model.objects import CertificateSigned

        cs = ctx.dbSession.query(CertificateSigned).all()
        for c in cs:
            _duration = c.timestamp_not_after - c.timestamp_not_before
            _duration_seconds = _duration.total_seconds()
            _duration_hours = int(_duration_seconds / 3600)
            c.duration_hours = _duration_hours
        ctx.pyramid_transaction_commit()

    exit()


main()
