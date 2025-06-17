from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import sys

# pypi
from pyramid.scripts.common import parse_vars

# local
from ...lib import db as lib_db
from ...lib.utils import new_scripts_setup
from ...lib.utils import validate_config_uri


# from ...lib import db as lib_db
# from ...lib.config_utils import ApplicationSettings

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
    config_uri = validate_config_uri(config_uri)
    options = parse_vars(argv[2:])

    ctx = new_scripts_setup(config_uri, options=options)

    # actually, we order the backups first
    dbRoutineExecution_1 = lib_db.actions.unset_acme_server_caches(  # noqa: F841
        ctx,
        transaction_commit=True,
    )
    print("unset_acme_server_caches()")
    print(dbRoutineExecution_1.as_json)

    # already commited above
    ctx.pyramid_transaction_commit()
