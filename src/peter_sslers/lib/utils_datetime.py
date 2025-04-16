# stdlib
import datetime
import logging
from typing import Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import ApiContext


# ==============================================================================

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# ==============================================================================


def datetime_ari_timely(
    ctx: "ApiContext",
    datetime_now: Optional[datetime.datetime] = None,
) -> datetime.datetime:
    """Returns a max datetime used to determine if ARI checking is timely when
    compared to the certificate's `notAfter`.

    This function pads the current datetime with a clockdrift and an expected
    offset interval for polling.

    See:: lib.db.get.get_CertificateSigneds_renew_now
    """
    # don't rely on ctx.timestamp, as it can be old
    assert ctx.application_settings
    if datetime_now is None:
        datetime_now = datetime.datetime.now(datetime.timezone.utc)

    # clockdrift; servers get out of sync
    TIMEDELTA_clockdrift = datetime.timedelta(minutes=5)

    # factor in the next expected schedule.
    _minutes = ctx.application_settings.get("offset.ari_updates", 60)
    TIMEDELTA_runner_interval = datetime.timedelta(minutes=_minutes)

    # This may be confusing:
    # usually we SUBTRACT for searches and automatic renewals to give a safer buffer
    # here, we ADD the offset to give a wider buffer for on-demand
    timestamp_max_expiry = (
        datetime_now + TIMEDELTA_clockdrift + TIMEDELTA_runner_interval
    )
    return timestamp_max_expiry
