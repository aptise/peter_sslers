"""Maintenance previews are read-only and pruning retains graph/provenance links."""

import datetime
import json
from typing import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from peter_sslers.lib.db.audit_maintenance import prune_events
from peter_sslers.lib.db.audit_maintenance import sanitize_payloads


@pytest.fixture
def session() -> Iterator[Session]:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.exec_driver_sql(
            "CREATE TABLE operations_event (id INTEGER PRIMARY KEY, operations_event_type_id INTEGER, timestamp_event DATETIME, event_payload TEXT, operations_event_id__child_of INTEGER REFERENCES operations_event(id))"
        )
        connection.exec_driver_sql(
            "CREATE TABLE operations_object_event (id INTEGER PRIMARY KEY, operations_event_id INTEGER REFERENCES operations_event(id))"
        )
        connection.exec_driver_sql(
            "CREATE TABLE functional_row (id INTEGER PRIMARY KEY, provenance INTEGER REFERENCES operations_event(id))"
        )
        for identity, parent in ((1, None), (2, 1), (3, None), (4, None), (5, None)):
            connection.execute(
                sa.text(
                    "INSERT INTO operations_event VALUES (:id, 1, :time, :payload, :parent)"
                ),
                {
                    "id": identity,
                    "time": "2020-01-01 00:00:00",
                    "parent": parent,
                    "payload": json.dumps(
                        {"v": 1, "password": "old-secret", "ids": list(range(120))}
                    ),
                },
            )
        connection.exec_driver_sql("INSERT INTO operations_object_event VALUES (1, 2)")
        connection.exec_driver_sql("INSERT INTO functional_row VALUES (1, 3)")
        connection.exec_driver_sql(
            "UPDATE operations_event SET timestamp_event='2099-01-01 00:00:00' WHERE id=5"
        )
    try:
        with Session(engine) as value:
            yield value
    finally:
        engine.dispose()


def test_sanitize_preview_apply_resume_and_rollback(session: Session) -> None:
    preview = sanitize_payloads(session, batch_size=1, limit=2)
    assert (preview.examined, preview.eligible, preview.changed, preview.last_id) == (
        2,
        2,
        0,
        2,
    )
    assert (
        "old-secret"
        in session.execute(
            sa.text("SELECT event_payload FROM operations_event WHERE id=1")
        ).scalar_one()
    )
    applied = sanitize_payloads(
        session, apply=True, batch_size=1, after_id=preview.last_id
    )
    assert applied.changed == 3
    raw = session.execute(
        sa.text("SELECT event_payload FROM operations_event WHERE id=3")
    ).scalar_one()
    assert "old-secret" not in raw
    assert json.loads(raw)["ids"] == list(range(120))
    session.rollback()
    assert (
        "old-secret"
        in session.execute(
            sa.text("SELECT event_payload FROM operations_event WHERE id=3")
        ).scalar_one()
    )


def test_sanitize_invalid_legacy_json_is_omitted_without_payload_in_errors(
    session: Session,
) -> None:
    session.execute(
        sa.text("UPDATE operations_event SET event_payload='bad old-secret' WHERE id=1")
    )
    result = sanitize_payloads(session, apply=True, limit=1)
    assert result.changed == 1
    assert (
        "old-secret"
        not in session.execute(
            sa.text("SELECT event_payload FROM operations_event WHERE id=1")
        ).scalar_one()
    )


def test_retention_keeps_referenced_rows_and_ancestors_until_next_pass(
    session: Session,
) -> None:
    before = datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    preview = prune_events(session, before=before, batch_size=10)
    assert (preview.eligible, preview.changed) == (2, 0)  # leaves 2 and 4
    assert (
        session.execute(sa.text("SELECT count(*) FROM operations_event")).scalar_one()
        == 5
    )
    applied = prune_events(session, before=before, apply=True, batch_size=10)
    assert applied.changed == 2
    assert list(
        session.execute(
            sa.text("SELECT id FROM operations_event ORDER BY id")
        ).scalars()
    ) == [1, 3, 5]
    assert (
        session.execute(
            sa.text("SELECT count(*) FROM operations_object_event")
        ).scalar_one()
        == 0
    )
    session.commit()
    assert prune_events(session, before=before, apply=True).changed == 1
    assert list(
        session.execute(
            sa.text("SELECT id FROM operations_event ORDER BY id")
        ).scalars()
    ) == [3, 5]


def test_retention_rejects_ambiguous_cutoff_and_bad_limits(session: Session) -> None:
    with pytest.raises(ValueError, match="timezone"):
        prune_events(session, before=datetime.datetime(2020, 1, 1))
    with pytest.raises(ValueError, match="past"):
        prune_events(
            session, before=datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        )
    with pytest.raises(ValueError):
        sanitize_payloads(session, batch_size=0)
    assert sanitize_payloads(session, limit=0).examined == 0
