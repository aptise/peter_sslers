from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import sys

# pypi
from pyramid.paster import get_appsettings
from pyramid.scripts.common import parse_vars
from pyramid.settings import asbool

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
    print(
        "optional: this routine accepts a `dry-run` argument\n"
        '(example: "%s data_development/config.ini dry-run=true")' % (cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    validate_config_uri(config_uri)

    options = parse_vars(argv[2:])
    dry_run = asbool(options.get("dry-run", False))
    if dry_run:
        print("#" * 80)
        print("#" * 80)
        print("Attempting DRY RUN")
        print("#" * 80)
        print("#" * 80)

    settings = get_appsettings(config_uri, options=options)

    ctx = new_scripts_setup(config_uri, options=options)

    # actually, we order the backups first
    dbRoutineExecution_1 = lib_db.actions.routine__order_missing(  # noqa: F841
        ctx,
        settings=settings,
        dry_run=dry_run,
        DEBUG_LOCAL=False,
    )
    print("routine__order_missing()")
    print(dbRoutineExecution_1.as_json)

    # then we renew the expiring
    dbRoutineExecution_2 = lib_db.actions.routine__renew_expiring(  # noqa: F841
        ctx,
        settings=settings,
        dry_run=dry_run,
        DEBUG_LOCAL=False,
    )
    print("routine__renew_expiring()")
    print(dbRoutineExecution_2.as_json)

    ctx.pyramid_transaction_commit()
