from . import _disable_warnings  # noqa: F401

# stdlib
import datetime  # noqa: I100
import os
import os.path
import sys
from typing import Dict
from typing import TYPE_CHECKING

# pypi
from pyramid.paster import get_appsettings
from pyramid.scripts.common import parse_vars

# local
from ...lib import db as lib_db
from ...lib.scheduling import Schedule
from ...lib.utils import new_scripts_setup
from ...model import utils as model_utils

if TYPE_CHECKING:
    from ...model.objects import RoutineExecution

# ==============================================================================

DEBUG_STRUCTURE: bool = False


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri>\n"
        '(example: "%s data_development/config.ini")' % (cmd, cmd)
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

    TIMESTAMP_routine_start = datetime.datetime.now(datetime.timezone.utc)

    dbRoutines: Dict[str, "RoutineExecution"] = {}

    # okay, what tasks should we do?
    if "routine__run_ari_checks" in tasks:
        print("routine__run_ari_checks")
        dbRoutines["routine__run_ari_checks"] = lib_db.actions.routine__run_ari_checks(
            ctx
        )
        ctx.pyramid_transaction_commit()

    if "routine__clear_old_ari_checks" in tasks:
        print("routine__clear_old_ari_checks")
        dbRoutines["routine__clear_old_ari_checks"] = (
            lib_db.actions.routine__clear_old_ari_checks(ctx)
        )
        ctx.pyramid_transaction_commit()

    if "routine__reconcile_blocks" in tasks:
        print("routine__reconcile_blocks")
        dbRoutines["routine__reconcile_blocks"] = (
            lib_db.actions.routine__reconcile_blocks(
                ctx,
                transaction_commit=True,
            )
        )
        ctx.pyramid_transaction_commit()

    if "routine__order_missing" in tasks:
        print("routine__order_missing")
        dbRoutines["routine__order_missing"] = lib_db.actions.routine__order_missing(
            ctx,
            settings=settings,
            DEBUG=False,
        )
        ctx.pyramid_transaction_commit()

    if "routine__renew_expiring" in tasks:
        print("routine__renew_expiring")
        dbRoutines["routine__renew_expiring"] = lib_db.actions.routine__renew_expiring(
            ctx,
            settings=settings,
            DEBUG=False,
        )
        ctx.pyramid_transaction_commit()

    TIMESTAMP_routine_end = datetime.datetime.now(datetime.timezone.utc)
    dbRoutineExecution_global = lib_db.create.create__RoutineExecution(
        ctx,
        routine_id=model_utils.Routine.periodic,
        timestamp_start=TIMESTAMP_routine_start,
        timestamp_end=TIMESTAMP_routine_end,
        count_records_success=0,
        count_records_fail=0,
    )
    for _routine_name, _dbRoutine in dbRoutines.items():
        _dbRoutine = ctx.dbSession.merge(_dbRoutine)
        _dbRoutine.routine_execution_id__via = dbRoutineExecution_global.id
        ctx.dbSession.flush(objects=[_dbRoutine])

        print("Result = %s" % _routine_name)
        print(_dbRoutine.as_json)

    ctx.pyramid_transaction_commit()

    print("Thank you, and be excellent to each other.")
