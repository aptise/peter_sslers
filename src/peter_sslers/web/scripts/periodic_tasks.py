from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import os.path
import sys

# pypi
from pyramid.paster import get_appsettings
from pyramid.scripts.common import parse_vars

# local
from ...lib import db as lib_db
from ...lib.scheduling import Schedule
from ...lib.utils import new_scripts_setup

# ==============================================================================

DEBUG_STRUCTURE: bool = False


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri>\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])

    ctx = new_scripts_setup(config_uri, options=options)
    assert ctx.request

    settings = get_appsettings(config_uri, options=options)

    schedule = Schedule(ctx)
    print("Scheule file:", schedule.filepath)
    if not schedule.load():
        print("GENERATING NEW")
        schedule.new()
        schedule.save()
    else:
        print("LOADED")

    print("Crontab should be configured as:")
    print("")
    print("")
    print(
        "%s * * * * %s periodic_tasks.py %s"
        % (schedule.schedule["offset"]["minute"], sys.executable, config_uri)
    )
    print("")
    print("")
    print("---")
    print("Schedule:")
    print(schedule.schedule)
    print("---")

    tasks = schedule.to_dispatch()
    print("will dispatch these tasks:", tasks)

    # okay, what tasks should we do?
    if "routine__run_ari_checks" in tasks:
        print("routine__run_ari_checks")
        lib_db.actions.routine__run_ari_checks(ctx)
        ctx.pyramid_transaction_commit()

    if "routine__clear_old_ari_checks" in tasks:
        print("routine__clear_old_ari_checks")
        lib_db.actions.routine__clear_old_ari_checks(ctx)
        ctx.pyramid_transaction_commit()

    if "routine__order_missing" in tasks:
        print("routine__order_missing")
        lib_db.actions.routine__order_missing(
            ctx,
            settings=settings,
            DEBUG=False,
        )
        ctx.pyramid_transaction_commit()

    if "routine__renew_expiring" in tasks:
        print("routine__renew_expiring")
        lib_db.actions.routine__renew_expiring(
            ctx,
            settings=settings,
            DEBUG=False,
        )
        ctx.pyramid_transaction_commit()

    print("Thank you, and be excellent to each other.")
