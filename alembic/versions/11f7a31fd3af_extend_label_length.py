"""extend_label_length

Revision ID: 11f7a31fd3af
Revises: 308c8116cb36
Create Date: 2025-10-17 12:08:18.488331

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "11f7a31fd3af"
down_revision: Union[str, Sequence[str], None] = "308c8116cb36"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("renewal_configuration", schema=None) as batch_op:
        batch_op.alter_column(
            "label",
            existing_type=sa.VARCHAR(length=128),
            type_=sa.Unicode(length=256),
            existing_nullable=True,
        )


def downgrade() -> None:
    """Downgrade schema."""
    # this might not be possible due to db records
    if False:
        with op.batch_alter_table("renewal_configuration", schema=None) as batch_op:
            batch_op.alter_column(
                "label",
                existing_type=sa.Unicode(length=256),
                type_=sa.VARCHAR(length=128),
                existing_nullable=True,
            )
