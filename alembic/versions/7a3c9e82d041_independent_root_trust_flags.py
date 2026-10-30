"""Allow explicitly untrusted roots outside trusted root stores.

Revision ID: 7a3c9e82d041
Revises: 11f7a31fd3af
"""

from alembic import op
import sqlalchemy as sa

revision = "7a3c9e82d041"
down_revision = "11f7a31fd3af"
branch_labels = None
depends_on = None

CONSTRAINT = "ck_x509_certificate_trusted_ck_x509_certificate_trusted__untrusted_root"


def upgrade():
    with op.batch_alter_table("x509_certificate_trusted") as batch_op:
        batch_op.drop_constraint(op.f(CONSTRAINT), type_="check")


def downgrade():
    # Existing independent flags must be reconciled before restoring the old rule.
    with op.batch_alter_table("x509_certificate_trusted") as batch_op:
        batch_op.create_check_constraint(
            op.f(CONSTRAINT),
            sa.text(
                "(is_untrusted_root IS NOT True) OR "
                "((is_untrusted_root IS True) AND (is_trusted_root IS True))"
            ),
        )
