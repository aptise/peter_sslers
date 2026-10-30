from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa

from alembic.migration import MigrationContext
from alembic.operations import Operations


def test_root_trust_migration_preserves_rows_and_allows_explicit_distrust(
    tmp_path: Path,
) -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic/versions/7a3c9e82d041_independent_root_trust_flags.py"
    )
    spec = importlib.util.spec_from_file_location("root_trust_migration", path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'migration.sqlite'}")
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "CREATE TABLE x509_certificate_trusted ("
                "id INTEGER PRIMARY KEY, is_trusted_root BOOLEAN, is_untrusted_root BOOLEAN, "
                f"CONSTRAINT {migration.CONSTRAINT} CHECK ("
                "(is_untrusted_root IS NOT True) OR "
                "((is_untrusted_root IS True) AND (is_trusted_root IS True))))"
            )
        )
        connection.execute(
            sa.text("INSERT INTO x509_certificate_trusted VALUES (1, 1, NULL)")
        )
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        connection.execute(
            sa.text("INSERT INTO x509_certificate_trusted VALUES (2, 0, 1)")
        )
        assert connection.execute(
            sa.text(
                "SELECT id, is_trusted_root, is_untrusted_root FROM x509_certificate_trusted ORDER BY id"
            )
        ).all() == [(1, 1, None), (2, 0, 1)]
    engine.dispose()
