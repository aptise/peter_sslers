# stdlib
import json
import logging
import math
import os
import os.path
import random
from typing import Dict
from typing import List
from typing import TYPE_CHECKING

# pypi
from typing_extensions import TypedDict

if TYPE_CHECKING:
    from .context import ApiContext

# ==============================================================================


log = logging.getLogger("peter_sslers.lib")


# ------------------------------------------------------------------------------


class TimeOffset(TypedDict):
    hour: int
    minute: int


class _Scheduled(TypedDict):
    offset: TimeOffset
    version: int
    tasks: Dict[str, List[int]]  # Taskname = [Hour, Minute]


# name : n-times-daily
# 24: hourly
# 12: every 2 hours
# 8: every 3 hours
# 6: every 4 hours

# ARI/replaces is subscriber-antagonistic
# The initial ISRG implementation uses a duration-padded window
# 90day certs have about a 45 hour window to renew
# short-lived certs only have a few hours to renew
# in order to effectively use `replaces`, clients must poll repeatedly
# IMPORTANT:  if this changes, update the version
TASK_2_FREQUENCY = {
    "routine__run_ari_checks": 24,
    "routine__clear_old_ari_checks": 24,
    "routine__order_missing": 8,
    "routine__renew_expiring": 8,
    "routine__reconcile_blocks": 8,
}
SCHEDULER_VERSION = 2


class Schedule:
    ctx: "ApiContext"
    filepath: str
    _schedule: _Scheduled

    def __init__(
        self,
        ctx: "ApiContext",
    ):
        self.ctx = ctx
        if TYPE_CHECKING:
            assert self.ctx.application_settings
        self.filepath = os.path.join(
            self.ctx.application_settings["data_dir"],
            self.ctx.application_settings["scheduler"],
        )

    def load(self) -> bool:
        try:
            if os.path.exists(self.filepath):
                with open(self.filepath, "rb") as fh:
                    self._schedule = json.load(fh)
                return True
            return False
        except Exception as exc:
            log.critical(exc)
            raise

    def save(self) -> bool:
        try:
            with open(self.filepath, "w") as fh:
                json.dump(self._schedule, fh)
            return True
        except Exception as exc:
            log.critical(exc)
            raise

    @property
    def schedule(self):
        return self._schedule

    def new(self) -> bool:
        """
        Create a new Scheduler.  Enter the tasks in it.
        If things change in the future, alert the user.
        """
        offset: TimeOffset = {
            "hour": random.randint(0, 23),  # will be used internally
            "minute": random.randint(5, 55),  # only used to suggest cron minute
        }
        _schedule: _Scheduled = {
            "offset": offset,
            "version": SCHEDULER_VERSION,
            "tasks": {},
        }

        for t, f in TASK_2_FREQUENCY.items():
            fx = math.floor(24 / f)
            ts = []
            for i in range(0, 24):
                candidate = fx * i
                if candidate < 24:
                    ts.append(candidate)
                else:
                    break
            _schedule["tasks"][t] = ts

        self._schedule = _schedule
        return self.save()

    def to_dispatch(self):
        # now = datetime.datetime.now(datetime.timezone.utc)
        offset_h = self._schedule["offset"]["hour"]
        adjusted_hour = self.ctx.timestamp.hour + offset_h
        if adjusted_hour >= 24:
            adjusted_hour = adjusted_hour - 24
        tasks = []
        for _task, _hours in self._schedule["tasks"].items():
            print(_task, _hours, adjusted_hour)
            if adjusted_hour in _hours:
                tasks.append(_task)
        return tasks
