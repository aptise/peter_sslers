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

# local
if TYPE_CHECKING:
    from .context import ApiContext

# ==============================================================================


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


# ------------------------------------------------------------------------------


class TimeOffset(TypedDict):
    hour: int
    minute: int


class _Scheduled(TypedDict):
    offset: TimeOffset
    version: int
    tasks: Dict[str, List[int]]  # Taskname = [Hour, Minute]


# name : n-times-daily
TASK_2_FREQUENCY = {
    "routine__run_ari_checks": 24,
    "routine__clear_old_ari_checks": 24,
    "routine__order_missing": 4,
    "routine__renew_expiring": 4,
}


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
            "version": 1,
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
        tasks = []
        for _task, _hours in self._schedule["tasks"].items():
            if adjusted_hour in _hours:
                tasks.append(_task)
        return tasks
