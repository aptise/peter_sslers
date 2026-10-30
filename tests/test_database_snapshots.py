import sqlite3
from pathlib import Path

import pytest

from . import _utils


@pytest.mark.parametrize("savepoint", ["AppTestCore", "AppTest", "test_pyramid_app-setup_testing_data"])
def test_snapshot_restore_replaces_contents_and_preserves_source(tmp_path, savepoint):
    active = tmp_path / "test.sqlite"
    snapshot = Path(f"{active}-{savepoint}")
    with sqlite3.connect(snapshot) as connection:
        connection.execute("CREATE TABLE saved (value TEXT)")
        connection.execute("INSERT INTO saved VALUES ('original')")
    with sqlite3.connect(active) as connection:
        connection.execute("CREATE TABLE stale (value TEXT)")
    for _ in range(2):
        assert _utils._db_unfreeze__actual(str(active), savepoint) is True
        with sqlite3.connect(active) as connection:
            assert connection.execute("SELECT value FROM saved").fetchall() == [("original",)]
            assert connection.execute("SELECT name FROM sqlite_master WHERE name='stale'").fetchall() == []
            connection.execute("UPDATE saved SET value='changed'")


def test_failed_reset_removes_active_and_all_reusable_snapshots(tmp_path, monkeypatch):
    active = tmp_path / "test.sqlite"
    paths = []
    for suffix in ("", "-AppTestCore", "-AppTest", "-test_pyramid_app-setup_testing_data"):
        path = Path(str(active) + suffix)
        path.write_bytes(b"not a sqlite database")
        paths.append(path)
    monkeypatch.setattr(_utils, "DEBUG_DBFREEZE_ARCHIVE", False)
    monkeypatch.setattr(_utils.AppTestCore, "_DB_INTIALIZED", True)
    monkeypatch.setattr(_utils.AppTest, "_DB_SETUP_RECORDS", True)
    with pytest.raises(sqlite3.DatabaseError):
        _utils._db_unfreeze__actual(str(active), "AppTest")
    assert not any(path.exists() for path in paths)
    assert _utils.AppTestCore._DB_INTIALIZED is False
    assert _utils.AppTest._DB_SETUP_RECORDS is False


def test_missing_snapshot_does_not_delete_active_database(tmp_path):
    active = tmp_path / "test.sqlite"
    active.write_bytes(b"existing")
    assert _utils._db_unfreeze__actual(str(active), "AppTest") is False
    assert active.read_bytes() == b"existing"
