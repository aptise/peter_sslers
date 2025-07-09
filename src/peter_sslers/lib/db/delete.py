# stdlib
import logging
from typing import TYPE_CHECKING

# pypi
from sqlalchemy import delete

# local
from ...model import objects as model_objects

if TYPE_CHECKING:
    from ..context import ApiContext

# from typing import Optional


# ==============================================================================

log = logging.getLogger("peter_sslers.lib.db")

# ------------------------------------------------------------------------------


def delete__RateLimited__by_AcmeAccountId(
    ctx: "ApiContext",
    acme_account_id: int,
) -> int:
    stmt = delete(model_objects.RateLimited).where(
        model_objects.RateLimited.acme_account_id == acme_account_id
    )
    executed = ctx.dbSession.execute(stmt)  # noqa: F841
    return 1


def delete__RateLimited__by_AcmeServerId(
    ctx: "ApiContext",
    acme_server_id: int,
) -> int:
    stmt = delete(model_objects.RateLimited).where(
        model_objects.RateLimited.acme_server_id == acme_server_id
    )
    executed = ctx.dbSession.execute(stmt)  # noqa: F841
    return 1


def delete__RateLimited__by_AcmeServerId_UniqueFQDNSetId(
    ctx: "ApiContext",
    acme_server_id: int,
    unique_fqdn_set_id: int,
) -> int:
    stmt = delete(model_objects.RateLimited).where(
        model_objects.RateLimited.acme_server_id == acme_server_id,
        model_objects.RateLimited.unique_fqdn_set_id == unique_fqdn_set_id,
    )
    executed = ctx.dbSession.execute(stmt)  # noqa: F841
    return 1
