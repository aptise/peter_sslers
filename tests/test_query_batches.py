"""Keyset paging must remain bounded when eligibility changes across commits."""

from __future__ import annotations

from typing import cast
from typing import Generator
from typing import List
from typing import Optional

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import Session

from peter_sslers.lib.db.batching import iter_query_id_batches


class BatchBase(DeclarativeBase):
    pass


class BatchRow(BatchBase):
    __tablename__ = "batch_row"
    id: Mapped[int] = mapped_column(primary_key=True)
    active: Mapped[bool] = mapped_column(default=True)


@pytest.fixture
def session() -> Generator[Session, None, None]:
    engine = sa.create_engine("sqlite://")
    BatchBase.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all(BatchRow(id=identity, active=True) for identity in range(1, 7))
        session.commit()
        yield session
    engine.dispose()


@pytest.mark.parametrize("descending", [False, True])
def test_commits_rollbacks_and_eligibility_changes_do_not_skip_ids_or_include_new_rows(
    session: Session, descending: bool
) -> None:
    pages = iter_query_id_batches(
        session.query(BatchRow).filter(BatchRow.active.is_(True)),
        BatchRow.id,
        batch_size=2,
        descending=descending,
    )
    first = next(pages)
    assert first == ([6, 5] if descending else [1, 2])
    session.execute(
        sa.update(BatchRow).where(BatchRow.id.in_(first)).values(active=False)
    )
    session.add(BatchRow(id=99, active=True))
    session.commit()
    second = next(pages)
    assert second == ([4, 3] if descending else [3, 4])
    session.execute(
        sa.update(BatchRow).where(BatchRow.id.in_(second)).values(active=False)
    )
    session.commit()
    with pytest.raises(sa.exc.IntegrityError):
        session.execute(sa.insert(BatchRow).values(id=1, active=True))
    session.rollback()
    assert list(pages) == ([[2, 1]] if descending else [[5, 6]])


@pytest.mark.parametrize(
    "limit, expected",
    [(0, []), (1, [[1]]), (3, [[1, 2], [3]]), (None, [[1, 2], [3, 4], [5, 6]])],
)
def test_batch_limit_caps_total_work_not_each_page(
    session: Session, limit: Optional[int], expected: List[List[int]]
) -> None:
    assert (
        list(
            iter_query_id_batches(
                session.query(BatchRow), BatchRow.id, batch_size=2, limit=limit
            )
        )
        == expected
    )


@pytest.mark.parametrize("size", [-1, 0, True, 1.5])
def test_invalid_batch_sizes_are_rejected(session: Session, size: object) -> None:
    with pytest.raises(ValueError, match="batch_size"):
        list(
            iter_query_id_batches(
                session.query(BatchRow), BatchRow.id, batch_size=cast(int, size)
            )
        )


def test_explicit_upper_fence_is_respected(session: Session) -> None:
    assert list(
        iter_query_id_batches(
            session.query(BatchRow), BatchRow.id, batch_size=2, upper_bound=3
        )
    ) == [[1, 2], [3]]
