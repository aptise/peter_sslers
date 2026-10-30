"""Retain advertised ACME profile references without removing legacy names.

Revision ID: c2e6a4d891b0
Revises: b6d82f9014ae
"""

import json
from typing import Dict
from typing import Optional

from alembic import op
import sqlalchemy as sa

revision = "c2e6a4d891b0"
down_revision = "b6d82f9014ae"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Backfill known URLs from the active snapshot; retain unknown legacy names."""
    op.add_column("acme_server", sa.Column("profiles_data", sa.Text(), nullable=True))
    connection = op.get_bind()
    servers = sa.table(
        "acme_server",
        sa.column("id", sa.Integer),
        sa.column("profiles", sa.Text),
        sa.column("profiles_data", sa.Text),
    )
    configurations = sa.table(
        "acme_server_configuration",
        sa.column("acme_server_id", sa.Integer),
        sa.column("is_active", sa.Boolean),
        sa.column("directory_payload", sa.Text),
    )
    rows = connection.execute(
        sa.select(
            servers.c.id,
            servers.c.profiles,
            configurations.c.directory_payload,
        ).select_from(
            servers.outerjoin(
                configurations,
                sa.and_(
                    configurations.c.acme_server_id == servers.c.id,
                    configurations.c.is_active.is_(True),
                ),
            )
        )
    )
    for identity, names, raw in rows:
        values: Dict[str, Optional[str]] = {}
        if names:
            values = {name: None for name in names.split(",") if name}
        if raw:
            try:
                directory = json.loads(raw)
                meta = directory.get("meta", {}) if isinstance(directory, dict) else {}
                advertised = meta.get("profiles", {}) if isinstance(meta, dict) else {}
                if isinstance(advertised, dict):
                    for name in values:
                        reference = advertised.get(name)
                        if isinstance(reference, str):
                            values[name] = reference
            except (ValueError, TypeError, RecursionError):
                pass  # Keep names when a historical snapshot cannot supply URLs.
        if names is not None or raw is not None:
            connection.execute(
                servers.update()
                .where(servers.c.id == identity)
                .values(
                    profiles_data=json.dumps(values, sort_keys=True),
                )
            )


def downgrade() -> None:
    """Drop only the added metadata; legacy profile selections remain intact."""
    with op.batch_alter_table("acme_server") as batch:
        batch.drop_column("profiles_data")
