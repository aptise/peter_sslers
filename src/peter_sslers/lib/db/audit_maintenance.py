"""Explicit, bounded maintenance of historical audit metadata.

Never prints payloads, commits transactions, or deletes functional objects.
"""

from dataclasses import dataclass
import datetime
import json
from typing import Optional

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from ...logging_utils import censor
from ...model.objects import OperationsEvent


@dataclass
class AuditMaintenanceResult:
    examined: int = 0
    eligible: int = 0
    changed: int = 0
    last_id: int = 0


def _positive(value: int, label: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError("%s must be a positive integer" % label)


def sanitize_payloads(
    session: Session,
    *,
    apply: bool = False,
    batch_size: int = 100,
    after_id: int = 0,
    limit: Optional[int] = None,
) -> AuditMaintenanceResult:
    """Censor legacy rows using Core SQL so ORM read censoring cannot hide them."""
    _positive(batch_size, "batch_size")
    if type(after_id) is not int or after_id < 0:
        raise ValueError("after_id must be a nonnegative integer")
    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("limit must be a nonnegative integer")
    table = OperationsEvent.__table__
    fence = session.execute(sa.select(sa.func.max(table.c.id))).scalar() or 0
    result = AuditMaintenanceResult(last_id=after_id)
    while limit is None or result.examined < limit:
        size = batch_size if limit is None else min(batch_size, limit - result.examined)
        rows = session.execute(
            sa.select(table.c.id, table.c.event_payload)
            .where(
                table.c.id > result.last_id,
                table.c.id <= fence,
            )
            .order_by(table.c.id)
            .limit(size)
        ).all()
        if not rows:
            break
        for identity, raw in rows:
            result.examined += 1
            result.last_id = identity
            try:
                document = json.loads(raw)
                if not isinstance(document, dict):
                    raise ValueError("Payload must be an object")
                safe = json.dumps(censor(document, max_items=None), allow_nan=False)
            except (TypeError, ValueError, RecursionError):
                safe = json.dumps(
                    {"v": 1, "historical_payload": "[OMITTED: invalid JSON object]"}
                )
            if safe != raw:
                result.eligible += 1
                if apply:
                    # Optimistic comparison avoids overwriting a concurrent writer.
                    updated = session.execute(
                        sa.update(table)
                        .where(
                            table.c.id == identity,
                            table.c.event_payload == raw,
                        )
                        .values(event_payload=safe)
                    )
                    if not isinstance(updated, CursorResult):
                        raise TypeError("Expected an audit update result")
                    result.changed += updated.rowcount
    session.expire_all()
    return result


def prune_events(
    session: Session,
    *,
    before: datetime.datetime,
    apply: bool = False,
    batch_size: int = 100,
    limit: int = 1000,
) -> AuditMaintenanceResult:
    """Delete only old, unreferenced leaves and their object links.

    Retains ancestors of retained children and operations referenced by functional
    rows. Re-run after committing to peel another level of an old event graph.
    The dry-run count represents this pass, not the entire eventual graph.
    """
    _positive(batch_size, "batch_size")
    _positive(limit, "limit")
    if before.tzinfo is None or before.utcoffset() is None:
        raise ValueError("before must include a timezone")
    if before >= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("before must be in the past")
    connection = session.connection()
    if apply and connection.dialect.name == "sqlite":
        # sqlite3 legacy transaction control does not begin a write transaction
        # for SELECT. Take its reserved writer lock before checking references;
        # this also protects databases whose connections do not enforce FKs.
        connection.exec_driver_sql("UPDATE operations_event SET id=id WHERE 1=0")
    # Reflect actual foreign keys, including locally extended schemas.
    schema = sa.MetaData()
    schema.reflect(bind=session.connection())
    events = schema.tables["operations_event"]
    links = schema.tables["operations_object_event"]
    references = []
    for table in schema.tables.values():
        for foreign_key in table.foreign_keys:
            target = foreign_key.column
            if target.table is links:
                raise ValueError(
                    "Retention does not support additional references to object-event rows"
                )
            if target.table is events and table is not links:
                source = table.alias()
                references.append(
                    sa.exists(
                        sa.select(1)
                        .select_from(source)
                        .where(
                            source.c[foreign_key.parent.name] == events.c[target.name]
                        )
                    )
                )
    result = AuditMaintenanceResult()
    # Capture one leaf set per pass. Newly eligible ancestors wait for the next
    # invocation, making preview/apply counts and transaction size predictable.
    fence = session.execute(sa.select(sa.func.max(events.c.id))).scalar() or 0
    while result.examined < limit:
        identities = list(
            session.execute(
                sa.select(events.c.id)
                .where(
                    events.c.timestamp_event < before,
                    events.c.id > result.last_id,
                    events.c.id <= fence,
                    *(~reference for reference in references),
                )
                .order_by(events.c.id)
                .limit(min(batch_size, limit - result.examined))
                .with_for_update()
            ).scalars()
        )
        if not identities:
            break
        result.last_id = identities[-1]
        result.examined += len(identities)
        result.eligible += len(identities)
        if apply:
            # FK checks remain authoritative if a concurrent writer adds a reference.
            session.execute(
                sa.delete(links).where(links.c.operations_event_id.in_(identities))
            )
            deleted = session.execute(
                sa.delete(events).where(events.c.id.in_(identities))
            )
            if not isinstance(deleted, CursorResult):
                raise TypeError("Expected an audit deletion result")
            result.changed += deleted.rowcount
        break  # One leaf batch per transaction; ancestors wait for the next pass.
    session.expire_all()
    return result
