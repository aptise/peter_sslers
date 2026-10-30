"""Index scheduler, private-key policy, and audit traversal queries.

Revision ID: b6d82f9014ae
Revises: 7a3c9e82d041
"""

from alembic import op

revision = "b6d82f9014ae"
down_revision = "7a3c9e82d041"
branch_labels = None
depends_on = None

INDEXES = (
    (
        "ix_private_key_policy_period",
        "private_key",
        (
            "private_key_type_id",
            "acme_account_id__owner",
            "key_technology_id",
            "timestamp_created",
        ),
    ),
    (
        "ix_acme_order_configuration_role",
        "acme_order",
        ("renewal_configuration_id", "certificate_type_id", "id"),
    ),
    (
        "ix_acme_order_key_status",
        "acme_order",
        ("private_key_id", "acme_status_order_id"),
    ),
    (
        "ix_acme_order_reconcile",
        "acme_order",
        ("acme_status_order_id", "x509_certificate_id", "id"),
    ),
    ("ix_certificate_private_key", "x509_certificate", ("private_key_id", "id")),
    (
        "ix_operations_event_parent",
        "operations_event",
        ("operations_event_id__child_of", "id"),
    ),
    ("ix_operations_event_time", "operations_event", ("timestamp_event", "id")),
    (
        "ix_operations_object_event_operation",
        "operations_object_event",
        ("operations_event_id", "id"),
    ),
    (
        "ix_coverage_assurance_resolution",
        "coverage_assurance_event",
        ("coverage_assurance_resolution_id", "id"),
    ),
    (
        "ix_coverage_assurance_parent",
        "coverage_assurance_event",
        ("coverage_assurance_event_id__parent", "id"),
    ),
)


def upgrade() -> None:
    for name, table, columns in INDEXES:
        op.create_index(name, table, list(columns), unique=False)


def downgrade() -> None:
    for name, table, columns in reversed(INDEXES):
        op.drop_index(name, table_name=table)
