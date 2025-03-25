from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import sys

# pypi
from pyramid.scripts.common import parse_vars

# local
from ...lib import db as lib_db
from ...lib.utils import new_scripts_setup

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
    ctx = new_scripts_setup(config_uri, options=options)
    dbRoutineExecution = lib_db.actions.routine__run_ari_checks(ctx)  # noqa: F841
    ctx.pyramid_transaction_commit()
