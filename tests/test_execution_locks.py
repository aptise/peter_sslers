"""Duplicate workers cannot acquire critical sections across commits or crashes."""

from __future__ import annotations

from pathlib import Path
import sys
import threading
from types import SimpleNamespace
from typing import cast
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from peter_sslers.lib.errors import InvalidRequest
from peter_sslers.lib.errors import RoutineAlreadyRunning
from peter_sslers.lib.synchronization import execution_lock
from ._services import managed_service

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext


def make_context(engine: Engine) -> ApiContext:
    from peter_sslers.lib.context import ApiContext

    return ApiContext(dbSession=Session(engine))


@pytest.mark.parametrize("memory", [False, True])
def test_locks_are_reentrant_only_for_same_context_and_survive_transaction_end(
    tmp_path: Path, memory: bool
) -> None:
    engine = sa.create_engine(
        "sqlite://" if memory else "sqlite:///" + str(tmp_path / "locks.sqlite")
    )
    first, second = make_context(engine), make_context(engine)
    try:
        with execution_lock(first, "acme-orders"):
            with execution_lock(first, "acme-orders"):
                first.dbSession.commit()
                first.dbSession.rollback()
                with pytest.raises(RoutineAlreadyRunning):
                    with execution_lock(second, "acme-orders"):
                        pytest.fail("Overlapping context acquired execution lock")
            with execution_lock(second, "another-resource"):
                pass
        with execution_lock(second, "acme-orders"):
            pass
    finally:
        first.dbSession.close()
        second.dbSession.close()
        engine.dispose()


def test_same_database_different_engines_cannot_overlap(tmp_path: Path) -> None:
    url = "sqlite:///" + str(tmp_path / "locks.sqlite")
    first_engine, second_engine = sa.create_engine(url), sa.create_engine(url)
    first, second = make_context(first_engine), make_context(second_engine)
    try:
        with execution_lock(first, "acme-orders"):
            with pytest.raises(RoutineAlreadyRunning):
                with execution_lock(second, "acme-orders"):
                    pytest.fail("Independent engine acquired overlapping lock")
        with execution_lock(second, "acme-orders"):
            pass
    finally:
        first.dbSession.close()
        second.dbSession.close()
        first_engine.dispose()
        second_engine.dispose()


def test_lock_is_released_after_caller_error(tmp_path: Path) -> None:
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "locks.sqlite"))
    context = make_context(engine)
    try:
        with pytest.raises(RuntimeError):
            with execution_lock(context, "acme-orders"):
                raise RuntimeError("caller failed")
        with execution_lock(context, "acme-orders"):
            pass
    finally:
        context.dbSession.close()
        engine.dispose()


def test_other_thread_cannot_inherit_reentrant_ownership(tmp_path: Path) -> None:
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "locks.sqlite"))
    context = make_context(engine)
    result = []

    def run() -> None:
        try:
            with execution_lock(context, "acme-orders"):
                result.append("acquired")
        except RoutineAlreadyRunning:
            result.append("busy")

    try:
        with execution_lock(context, "acme-orders"):
            worker = threading.Thread(target=run)
            worker.start()
            worker.join(timeout=5)
            assert not worker.is_alive()
            assert result == ["busy"]
    finally:
        context.dbSession.close()
        engine.dispose()


def test_cross_process_lock_is_released_when_child_dies(tmp_path: Path) -> None:
    database = tmp_path / "locks.sqlite"
    ready = tmp_path / "ready"
    source = """import pathlib,time
import sqlalchemy as sa
from sqlalchemy.orm import Session
from types import SimpleNamespace
from peter_sslers.lib.synchronization import execution_lock
engine=sa.create_engine(%r)
ctx=SimpleNamespace(dbSession=Session(engine))
with execution_lock(ctx,"acme-orders"):
    pathlib.Path(%r).touch()
    time.sleep(60)
""" % ("sqlite:///" + str(database), str(ready))
    engine = sa.create_engine("sqlite:///" + str(database))
    context = make_context(engine)
    try:
        with managed_service(
            [sys.executable, "-c", source], ready=ready.exists, startup_timeout=30
        ):
            with pytest.raises(RoutineAlreadyRunning):
                with execution_lock(context, "acme-orders"):
                    pytest.fail("Another process acquired overlapping lock")
        with execution_lock(context, "acme-orders"):
            pass
    finally:
        context.dbSession.close()
        engine.dispose()


@pytest.mark.parametrize("dialect", ["postgresql", "mysql", "mariadb"])
def test_database_advisory_locks_use_one_connection_for_nested_resources(
    dialect: str,
) -> None:
    connection = Mock()
    connection.execute.return_value.scalar.return_value = True
    engine = cast(
        Engine,
        SimpleNamespace(
            dialect=SimpleNamespace(name=dialect),
            url=SimpleNamespace(host="db", port=5432, database="audit"),
            connect=Mock(return_value=connection),
        ),
    )
    context = cast(
        "ApiContext",
        SimpleNamespace(dbSession=SimpleNamespace(get_bind=Mock(return_value=engine))),
    )
    with execution_lock(context, "acme-orders"):
        with execution_lock(context, "configuration-1"):
            connection.close.assert_not_called()
    cast(Mock, engine.connect).assert_called_once()
    assert connection.execute.call_count == 4
    connection.invalidate.assert_not_called()
    connection.close.assert_called_once()
    for call in connection.execute.call_args_list:
        assert "audit" not in str(call.args[1]["key"])
        if dialect != "postgresql":
            assert len(call.args[1]["key"]) <= 64


@pytest.mark.parametrize("failure", ["acquire", "release", "lost_release"])
def test_uncertain_advisory_lock_ownership_invalidates_physical_connection(
    failure: str,
) -> None:
    connection = Mock()
    connection.execute.return_value.scalar.return_value = True
    if failure == "acquire":
        connection.execute.side_effect = RuntimeError("acquisition failed")
    elif failure == "release":
        connection.execute.side_effect = [
            Mock(scalar=Mock(return_value=True)),
            RuntimeError("release failed"),
        ]
    else:
        connection.execute.side_effect = [
            Mock(scalar=Mock(return_value=True)),
            Mock(scalar=Mock(return_value=False)),
        ]
    engine = cast(
        Engine,
        SimpleNamespace(
            dialect=SimpleNamespace(name="postgresql"),
            url=SimpleNamespace(host="db", port=5432, database="audit"),
            connect=Mock(return_value=connection),
        ),
    )
    context = cast(
        "ApiContext",
        SimpleNamespace(dbSession=SimpleNamespace(get_bind=Mock(return_value=engine))),
    )
    with pytest.raises((RuntimeError, InvalidRequest)):
        with execution_lock(context, "acme-orders"):
            pass
    assert connection.invalidate.called
    connection.close.assert_called_once()
