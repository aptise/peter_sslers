"""Finite keyset scans that remain safe across per-item transaction boundaries."""

from typing import Iterator
from typing import List
from typing import Optional
from typing import TypeVar

from sqlalchemy import func
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.orm import Query

_T = TypeVar("_T")


def iter_query_id_batches(
    query: Query[_T],
    identity: InstrumentedAttribute[int],
    *,
    batch_size: int = 100,
    limit: Optional[int] = None,
    upper_bound: Optional[int] = None,
    descending: bool = False,
) -> Iterator[List[int]]:
    if type(batch_size) is not int or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("limit must be a non-negative integer or None")
    if limit == 0:
        return
    upper: Optional[int] = upper_bound
    if upper is None:
        upper = query.with_entities(func.max(identity)).order_by(None).scalar()
    if upper is None:
        return
    cursor: Optional[int] = None
    remaining = limit
    while remaining is None or remaining > 0:
        page = query.with_entities(identity).filter(identity <= upper)
        if cursor is not None:
            page = page.filter(identity < cursor if descending else identity > cursor)
        size = batch_size if remaining is None else min(batch_size, remaining)
        values = [
            row[0]
            for row in page.distinct()
            .order_by(None)
            .order_by(identity.desc() if descending else identity.asc())
            .limit(size)
            .all()
        ]
        if not values:
            return
        cursor = values[-1]
        if remaining is not None:
            remaining -= len(values)
        # Only scalar IDs survive the yield; no open cursor or ORM row is held
        # across the caller's commits, rollbacks or relationship refreshes.
        yield values
