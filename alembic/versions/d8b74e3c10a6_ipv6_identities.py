"""Allow IPv6 identities and canonicalize IP names without merging histories.

Revision ID: d8b74e3c10a6
Revises: c2e6a4d891b0
"""

import ipaddress
from typing import Dict
from typing import List
from typing import Tuple

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import Connection

revision = "d8b74e3c10a6"
down_revision = "c2e6a4d891b0"
branch_labels = None
depends_on = None

CONSTRAINT = "ck_domain__domain_type_check"
OLD = "(address_type_id IN (1,2)) AND ((address_type_id=1 AND registered IS NOT NULL AND suffix IS NOT NULL) OR (address_type_id=2 AND registered IS NULL AND suffix IS NULL))"
NEW = "(address_type_id IN (1,2,3)) AND ((address_type_id=1 AND registered IS NOT NULL AND suffix IS NOT NULL) OR (address_type_id IN (2,3) AND registered IS NULL AND suffix IS NULL))"


def _canonical_updates(
    connection: Connection, table: str, typed: bool
) -> List[Tuple[int, str]]:
    """Preflight collisions and invalid stored IP types before changing any data."""
    columns = "id, domain_name, address_type_id" if typed else "id, domain_name"
    updates: List[Tuple[int, str]] = []
    owners: Dict[str, int] = {}
    for row in connection.exec_driver_sql("SELECT " + columns + " FROM " + table):
        identity, name = row[0], row[1]
        if typed and row[2] == 1:
            try:
                ipaddress.ip_address(name)
            except ValueError:
                continue
            raise ValueError(
                "Hostname row %s contains an IP address; review its type" % identity
            )
        try:
            if "%" in name:
                raise ValueError("Scoped addresses are not certificate identities")
            address = ipaddress.ip_address(name)
        except ValueError:
            if typed:
                raise ValueError(
                    "Invalid stored IP identity in domain row %s" % identity
                ) from None
            continue
        if typed and row[2] != (2 if address.version == 4 else 3):
            raise ValueError(
                "Stored IP identity type mismatch in domain row %s" % identity
            )
        canonical = address.compressed
        if canonical in owners and owners[canonical] != identity:
            raise ValueError(
                "Canonical IP collision in %s; resolve rows before upgrading" % table
            )
        owners[canonical] = identity
        conflict = connection.execute(
            sa.text(
                "SELECT id FROM "
                + table
                + " WHERE lower(domain_name)=:name AND id!=:id"
            ),
            {"name": canonical, "id": identity},
        ).first()
        if conflict is not None:
            raise ValueError(
                "Canonical IP collision in %s; resolve rows before upgrading" % table
            )
        if name != canonical:
            updates.append((identity, canonical))
    return updates


def _change_constraint(expression: str) -> None:
    """Preserve SQLite expression indexes which batch reflection cannot represent."""
    connection = op.get_bind()
    indexes: List[Tuple[str, str]] = []
    if connection.dialect.name == "sqlite":
        indexes = [
            (row[0], row[1])
            for row in connection.exec_driver_sql(
                "SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='domain' AND sql IS NOT NULL"
            )
        ]
    with op.batch_alter_table("domain") as batch:
        batch.drop_constraint(op.f(CONSTRAINT), type_="check")
        batch.create_check_constraint(op.f(CONSTRAINT), sa.text(expression))
    if indexes:
        existing = {
            row[0]
            for row in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='domain'"
            )
        }
        for name, ddl in indexes:
            if name not in existing:
                connection.exec_driver_sql(ddl)


def upgrade() -> None:
    """Keep domain IDs/set fingerprints stable, rejecting ambiguous merges."""
    connection = op.get_bind()
    updates = {"domain": _canonical_updates(connection, "domain", True)}
    if "domain_blocklisted" in sa.inspect(connection).get_table_names():
        updates["domain_blocklisted"] = _canonical_updates(
            connection, "domain_blocklisted", False
        )
    _change_constraint(NEW)
    for table, rows in updates.items():
        for identity, canonical in rows:
            connection.execute(
                sa.text("UPDATE " + table + " SET domain_name=:name WHERE id=:id"),
                {"name": canonical, "id": identity},
            )


def downgrade() -> None:
    """Refuse to erase IPv6 histories to restore the older constraint."""
    connection = op.get_bind()
    if connection.exec_driver_sql(
        "SELECT id FROM domain WHERE address_type_id=3 LIMIT 1"
    ).first():
        raise ValueError("Cannot downgrade while IPv6 identities exist")
    _change_constraint(OLD)
