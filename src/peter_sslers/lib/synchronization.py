"""Crash-released execution locks independent of application transactions."""

from __future__ import annotations

from _thread import LockType
from contextlib import contextmanager
from contextlib import ExitStack
from contextvars import ContextVar
from functools import wraps
import hashlib
from inspect import BoundArguments
from inspect import signature
import os
from pathlib import Path
import re
import sys
import threading
from typing import Callable
from typing import cast
from typing import Dict
from typing import FrozenSet
from typing import Iterator
from typing import Sequence
from typing import Tuple
from typing import TYPE_CHECKING
from typing import TypeVar
from typing import Union
from weakref import WeakValueDictionary

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.engine import Engine
from typing_extensions import ParamSpec

from .errors import InvalidRequest
from .errors import RoutineAlreadyRunning

if TYPE_CHECKING:
    from .context import ApiContext

_P = ParamSpec("_P")
_R = TypeVar("_R")
_registry_guard = threading.Lock()
_thread_locks: WeakValueDictionary[str, LockType] = WeakValueDictionary()
_advisory_connections: ContextVar[Dict[Tuple[str, int, int], Connection]] = ContextVar(
    "sslers_advisory_connections", default={}
)
_held: ContextVar[FrozenSet[Tuple[str, int, int]]] = ContextVar(
    "sslers_execution_locks", default=frozenset()
)


def _thread_lock(name: str) -> LockType:
    with _registry_guard:
        lock = _thread_locks.get(name)
        if lock is None:
            lock = threading.Lock()
            _thread_locks[name] = lock
        return lock


def _engine(ctx: ApiContext) -> Engine:
    bind = ctx.dbSession.get_bind()
    return bind.engine if isinstance(bind, Connection) else bind


def _database_identity(engine: Engine) -> str:
    if engine.dialect.name == "sqlite":
        database = engine.url.database
        if database in (None, "", ":memory:") or (
            database.startswith("file:") and "mode=memory" in database
        ):
            return "sqlite-memory-%s" % id(engine)
        if engine.url.query.get("uri"):
            raise InvalidRequest(
                "SQLite URI databases need an explicit supported lock strategy"
            )
        return str(Path(database).resolve())
    return "%s:%s:%s:%s" % (
        engine.dialect.name,
        engine.url.host,
        engine.url.port,
        engine.url.database,
    )


@contextmanager
def _sqlite_file_lock(path: Path) -> Iterator[None]:
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        if sys.platform == "win32":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RoutineAlreadyRunning(
                    "Another process holds this execution lock"
                ) from exc
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RoutineAlreadyRunning(
                    "Another process holds this execution lock"
                ) from exc
        # Keep the inode in place: unlinking a lock file lets a new worker lock a
        # different inode while an older worker still owns the original one.
        yield
    finally:
        os.close(descriptor)  # Process death also releases the OS lock.


@contextmanager
def _advisory_session(
    ctx: ApiContext, engine: Engine, database: str
) -> Iterator[Connection]:
    owner = (database, id(ctx), threading.get_ident())
    connections = _advisory_connections.get()
    existing = connections.get(owner)
    if existing is not None:
        yield existing
        return
    connection = engine.connect()
    token = _advisory_connections.set({**connections, owner: connection})
    try:
        yield connection
    finally:
        _advisory_connections.reset(token)
        connection.close()


@contextmanager
def _database_advisory_lock(
    engine: Engine, connection: Connection, resource: str
) -> Iterator[None]:
    dialect = engine.dialect.name
    digest = hashlib.sha256(
        (str(engine.url.database) + ":" + resource).encode()
    ).digest()
    if dialect == "postgresql":
        acquire = text("SELECT pg_try_advisory_lock(:key)")
        release = text("SELECT pg_advisory_unlock(:key)")
        parameters: Dict[str, Union[str, int]] = {
            "key": int.from_bytes(digest[:8], "big", signed=True)
        }
    elif dialect in ("mysql", "mariadb"):
        acquire = text("SELECT GET_LOCK(:key, 0)")
        release = text("SELECT RELEASE_LOCK(:key)")
        parameters = {"key": "sslers-" + digest.hex()[:56]}
    else:
        raise InvalidRequest(
            "This database does not support the configured execution-lock strategy"
        )
    acquired = False
    try:
        try:
            result = connection.execute(acquire, parameters).scalar()
        except BaseException:
            # The server might have acquired the lock before the response failed.
            connection.invalidate()
            raise
        if result is None:
            connection.invalidate()
            raise InvalidRequest("Database execution-lock acquisition failed")
        if result not in (True, 1):
            raise RoutineAlreadyRunning("Another worker holds this execution lock")
        acquired = True
        yield
    finally:
        try:
            if acquired:
                released = connection.execute(release, parameters).scalar()
                if released not in (True, 1):
                    connection.invalidate()
                    raise InvalidRequest(
                        "Database execution lock could not be released"
                    )
        except BaseException:
            # Never return a still-locked physical connection to the pool.
            connection.invalidate()
            raise


@contextmanager
def execution_lock(ctx: ApiContext, resource: str) -> Iterator[None]:
    if re.fullmatch(r"[a-z][a-z0-9-]{0,95}", resource) is None:
        raise ValueError("Invalid execution lock resource")
    engine = _engine(ctx)
    if engine.dialect.name not in ("sqlite", "postgresql", "mysql", "mariadb"):
        raise InvalidRequest("Unsupported database execution-lock strategy")
    database = _database_identity(engine)
    identity = (database + ":" + resource, id(ctx), threading.get_ident())
    held = _held.get()
    if identity in held:
        yield  # Nested operations on the same context share their outer lock.
        return
    mutex = _thread_lock(identity[0])
    if not mutex.acquire(blocking=False):
        raise RoutineAlreadyRunning("Another worker holds execution lock %s" % resource)
    token = None
    try:
        with ExitStack() as stack:
            if engine.dialect.name == "sqlite":
                if not database.startswith("sqlite-memory-"):
                    stack.enter_context(
                        _sqlite_file_lock(
                            Path(database + ".sslers-" + resource + ".lock")
                        )
                    )
            else:
                connection = stack.enter_context(
                    _advisory_session(ctx, engine, database)
                )
                stack.enter_context(
                    _database_advisory_lock(engine, connection, resource)
                )
            token = _held.set(held | {identity})
            yield
    finally:
        if token is not None:
            _held.reset(token)
        mutex.release()


def serialized_execution(
    resources: Union[str, Callable[[BoundArguments], Sequence[str]]],
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]:
    def decorate(function: Callable[_P, _R]) -> Callable[_P, _R]:
        call_signature = signature(function)

        @wraps(function)
        def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            arguments = call_signature.bind(*args, **kwargs)
            context = cast("ApiContext", arguments.arguments["ctx"])
            selected = (
                [resources] if isinstance(resources, str) else resources(arguments)
            )
            with ExitStack() as stack:
                for name in selected:
                    stack.enter_context(execution_lock(context, name))
                return function(*args, **kwargs)

        return wrapper

    return decorate


def configuration_order_resources(arguments: BoundArguments) -> Sequence[str]:
    configuration = arguments.arguments.get("dbRenewalConfiguration")
    if configuration is None or configuration.id is None:
        raise InvalidRequest("A persisted renewal configuration is required")
    result = ["configuration-%s" % configuration.id]
    material = arguments.arguments.get("dbPrivateKey")
    if material is not None and material.id not in (None, 0):
        result.append("private-key-%s" % material.id)
    return result


def order_resources(arguments: BoundArguments) -> Sequence[str]:
    order = arguments.arguments.get("dbAcmeOrder")
    if order is None or order.id is None:
        raise InvalidRequest("A persisted ACME order is required")
    return ["order-%s" % order.id]
