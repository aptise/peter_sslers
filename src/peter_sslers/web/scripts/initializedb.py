from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import sys

# pypi
from pyramid.scripts.common import parse_vars

# local
from ...lib.db import _setup
from ...lib.utils import new_scripts_setup


# ==============================================================================


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> [var=value]\n"
        '(example: "%s data_development/config.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])

    ctx = new_scripts_setup(config_uri, options=options)

    # this will setup the initial AcmeServers and the placeholder PrivateKey
    _setup.initialize_database(ctx)

    ctx.pyramid_transaction_commit()
