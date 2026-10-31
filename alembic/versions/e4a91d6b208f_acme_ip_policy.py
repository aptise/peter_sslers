"""Default ACME servers to publicly routable IP issuance policy."""

from alembic import op
import sqlalchemy as sa

revision = "e4a91d6b208f"
down_revision = "d8b74e3c10a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Enforce public IPs for existing and new issuers until explicitly opted out."""
    op.add_column(
        "acme_server",
        sa.Column(
            "require_public_ip", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )


def downgrade() -> None:
    """Remove issuance policy without changing certificate identities."""
    with op.batch_alter_table("acme_server") as batch:
        batch.drop_column("require_public_ip")
