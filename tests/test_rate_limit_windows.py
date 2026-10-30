from __future__ import annotations

from typing import TYPE_CHECKING
from typing import cast


import datetime
from typing import Generator
from typing import Union
from typing import cast

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from peter_sslers.lib.db import get
from peter_sslers.model.objects import RateLimited
from peter_sslers.model.objects import UniqueFQDNSet
from peter_sslers.model.objects import UniqueFQDNSet2Domain

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext


NOW = datetime.datetime(2026, 10, 29, 12, tzinfo=datetime.timezone.utc)


@pytest.fixture
def context() -> Generator[ApiContext, None, None]:
    from peter_sslers.lib.context import ApiContext

    engine = sa.create_engine("sqlite://")
    for model in (RateLimited, UniqueFQDNSet, UniqueFQDNSet2Domain):
        model.__table__.create(engine)
    with Session(engine) as session:
        for identity in (1, 2, 3):
            session.execute(
                sa.insert(UniqueFQDNSet).values(
                    id=identity,
                    domain_ids_string=str(identity),
                    timestamp_created=NOW,
                    operations_event_id__created=1,
                )
            )
        session.execute(
            sa.insert(UniqueFQDNSet2Domain),
            [
                {"unique_fqdn_set_id": 1, "domain_id": 1},
                {"unique_fqdn_set_id": 2, "domain_id": 1},
                {"unique_fqdn_set_id": 2, "domain_id": 2},
                {"unique_fqdn_set_id": 3, "domain_id": 3},
            ],
        )
        for identity, server, account, fqdn, age in [
            (1, 1, 1, 1, 1),
            (2, 1, 1, 1, 13),
            (3, 1, None, 2, 1),
            (4, 2, 2, 1, 1),
            (5, 1, 1, 1, 12),
        ]:
            session.execute(
                sa.insert(RateLimited).values(
                    id=identity,
                    acme_server_id=server,
                    acme_account_id=account,
                    unique_fqdn_set_id=fqdn,
                    timestamp_created=NOW - datetime.timedelta(hours=age),
                )
            )
        session.commit()
        yield ApiContext(dbSession=session, timestamp=NOW)
    engine.dispose()


def test_account_and_server_windows_exclude_old_events_and_include_boundary(
    context: ApiContext,
) -> None:
    assert get.get__RateLimited__by__acmeAccountId(context, 1) == 2
    assert get.get__RateLimited__by__acmeServerId(context, 1) == 1
    assert (
        get.get__RateLimited__by__acmeServerId(context, 1, exclude_accounts=False) == 3
    )
    assert (
        get.get__RateLimited__by__acmeServerId(
            context, 1, within_hours=24, exclude_accounts=False
        )
        == 4
    )
    assert get.get__RateLimited__by__acmeAccountId(context, 1, within_hours=0) == 0


def test_domain_overlap_counts_each_recent_rate_limit_once(context: ApiContext) -> None:
    assert get.get__RateLimited__by__acmeServerId_uniqueFqdnSetId(context, 1, 2) == 3
    assert get.get__RateLimited__by__acmeServerId_uniqueFqdnSetId(context, 1, 3) == 0


@pytest.mark.parametrize("hours", [-1, "12", 1.5])
def test_invalid_lookback_is_rejected(
    context: ApiContext, hours: Union[int, float, str]
) -> None:
    with pytest.raises(ValueError, match="within_hours"):
        get.get__RateLimited__by__acmeAccountId(
            context, 1, within_hours=cast(int, hours)
        )
