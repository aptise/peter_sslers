# stdlib
import json
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union

# pypi
import sqlalchemy
from sqlalchemy import delete

# local
from ...model import objects as model_objects

# from typing import Optional

if TYPE_CHECKING:
    from ..context import ApiContext


# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


def delete__RateLimited__by_AcmeAccountId(
    ctx: "ApiContext",
    acme_account_id: int,
) -> int:
    stmt = delete(model_objects.RateLimited).where(
        model_objects.RateLimited.acme_account_id == acme_account_id
    )
    executed = ctx.dbSession.execute(stmt)
    return 1

def delete__RateLimited__by_AcmeServerId(
    ctx: "ApiContext",
    acme_server_id: int,
) -> int:
    stmt = delete(model_objects.RateLimited).where(
        model_objects.RateLimited.acme_server_id == acme_server_id
    )
    executed = ctx.dbSession.execute(stmt)
    return 1
