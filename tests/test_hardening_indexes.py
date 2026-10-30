"""New installs and migrated installs must expose the same query indexes."""

import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
import sqlalchemy as sa

from peter_sslers.model import objects  # noqa: F401
from peter_sslers.model.meta import metadata


def test_index_migration_round_trip_preserves_data_and_matches_models() -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic/versions/b6d82f9014ae_hardening_query_indexes.py"
    )
    spec = importlib.util.spec_from_file_location("hardening_indexes", path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            for table in sorted({table for _, table, _ in migration.INDEXES}):
                columns = sorted(
                    {"id"}
                    | {
                        column
                        for _, target, names in migration.INDEXES
                        if target == table
                        for column in names
                    }
                )
                definition = ", ".join('"%s" INTEGER' % column for column in columns)
                connection.exec_driver_sql(
                    'CREATE TABLE "%s" (%s)' % (table, definition)
                )
                connection.exec_driver_sql('INSERT INTO "%s" (id) VALUES (42)' % table)
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                for name, table, columns in migration.INDEXES:
                    actual = {
                        index["name"]: index["column_names"]
                        for index in sa.inspect(connection).get_indexes(table)
                    }
                    assert actual[name] == list(columns)
                    model_index = next(
                        index
                        for index in metadata.tables[table].indexes
                        if index.name == name
                    )
                    assert (
                        tuple(column.name for column in model_index.columns) == columns
                    )
                migration.downgrade()
            for table in {table for _, table, _ in migration.INDEXES}:
                assert sa.inspect(connection).get_indexes(table) == []
                assert (
                    connection.exec_driver_sql(
                        'SELECT id FROM "%s"' % table
                    ).scalar_one()
                    == 42
                )
    finally:
        engine.dispose()
