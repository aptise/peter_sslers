"""acme_challenge_duplicate_strategy

Revision ID: d17010e3d5a6
Revises: 3d47851c18a1
Create Date: 2025-09-29 23:58:48.867730

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# edited template
from peter_sslers.model.utils import AcmeChallenge_DuplicateStrategy
from peter_sslers.model.utils import AcmeOrder_RetryStrategy
from peter_sslers.model.utils import AcmeOrder_Type

# revision identifiers, used by Alembic.
revision: str = "d17010e3d5a6"
down_revision: Union[str, Sequence[str], None] = "3d47851c18a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    #
    # acme_authorization_potential
    #

    with op.batch_alter_table("acme_authorization_potential", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("uidx_acme_authorization_potential"))
        batch_op.create_index(
            "uidx_acme_authorization_potential",
            ["acme_order_id", "domain_id", "acme_challenge_type_id"],
            unique=True,
        )

    op.execute(
        "UPDATE acme_order SET acme_order_type_id = %s WHERE acme_order_type_id = %s AND acme_order_id__retry_of IS NULL;"
        % (
            AcmeOrder_Type.RENEWAL_CONFIGURATION_REQUEST,
            AcmeOrder_Type.RETRY,
        )
    )

    with op.batch_alter_table("acme_order", schema=None) as batch_op:
        batch_op.create_index(
            "uidx_acme_order_id__retry_of",
            ["acme_order_id__retry_of"],
            unique=True,
        )
        batch_op.add_column(
            sa.Column("acme_order_retry_strategy_id", sa.Integer(), nullable=True)
        )

    # this needs to be done in a second migration
    with op.batch_alter_table("acme_order", schema=None) as batch_op:
        op.execute(
            "UPDATE acme_order SET acme_order_retry_strategy_id = %s WHERE acme_order_type_id = %s;"
            % (
                AcmeOrder_RetryStrategy.NORMAL,
                AcmeOrder_Type.RETRY,
            )
        )
        batch_op.create_check_constraint(
            batch_op.f("ck_acme_order_type_id"),
            sa.text(
                (
                    "((acme_order_id__retry_of IS NULL) AND (acme_order_type_id != %s) AND (acme_order_retry_strategy_id IS NULL))"
                    " OR "
                    "((acme_order_id__retry_of IS NOT NULL) AND (acme_order_type_id == %s) AND (acme_order_retry_strategy_id IS NOT NULL))"
                )
                % (AcmeOrder_Type.RETRY, AcmeOrder_Type.RETRY)
            ),
        )

    #
    # enrollment_factory
    #
    with op.batch_alter_table("enrollment_factory", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "acme_challenge_duplicate_strategy_id", sa.Integer(), nullable=True
            )
        )

    op.execute(
        "UPDATE enrollment_factory SET acme_challenge_duplicate_strategy_id = %s ;"
        % AcmeChallenge_DuplicateStrategy.from_string(
            AcmeChallenge_DuplicateStrategy._DEFAULT_EnrollmentFactory
        )
    )

    with op.batch_alter_table("enrollment_factory", schema=None) as batch_op:
        batch_op.alter_column(
            "acme_challenge_duplicate_strategy_id",
            nullable=False,
            existing_nullable=True,
        )

    #
    # renewal_configuration
    #

    with op.batch_alter_table("renewal_configuration", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "acme_challenge_duplicate_strategy_id", sa.Integer(), nullable=True
            )
        )

    op.execute(
        "UPDATE renewal_configuration SET acme_challenge_duplicate_strategy_id = %s ;"
        % AcmeChallenge_DuplicateStrategy.from_string(
            AcmeChallenge_DuplicateStrategy._DEFAULT_RenewalConfiguration
        )
    )

    with op.batch_alter_table("renewal_configuration", schema=None) as batch_op:
        batch_op.alter_column(
            "acme_challenge_duplicate_strategy_id",
            nullable=False,
            existing_nullable=True,
        )

    #
    # uniquely_challenged_fqdn_set_2_domain
    #

    with op.batch_alter_table(
        "uniquely_challenged_fqdn_set_2_domain", schema=None
    ) as batch_op:
        batch_op.create_primary_key(
            constraint_name="pkey_uniquely_challenged_fqdn_set_2_domain",
            columns=[
                "uniquely_challenged_fqdn_set_id",
                "domain_id",
                "acme_challenge_type_id",
            ],
        )


def downgrade() -> None:
    """Downgrade schema."""

    # uniquely_challenged_fqdn_set_2_domain

    if False:
        # this is not reversible, as new records are likely to violate this constraint
        with op.batch_alter_table(
            "uniquely_challenged_fqdn_set_2_domain", schema=None
        ) as batch_op:
            batch_op.create_primary_key(
                constraint_name="pkey_uniquely_challenged_fqdn_set_2_domain",
                columns=[
                    "uniquely_challenged_fqdn_set_id",
                    "domain_id",
                ],
            )

    with op.batch_alter_table("renewal_configuration", schema=None) as batch_op:
        batch_op.drop_column("acme_challenge_duplicate_strategy_id")

    with op.batch_alter_table("enrollment_factory", schema=None) as batch_op:
        batch_op.drop_column("acme_challenge_duplicate_strategy_id")

    with op.batch_alter_table("acme_order", schema=None) as batch_op:
        batch_op.drop_index("uidx_acme_order_id__retry_of")
        batch_op.drop_constraint("ck_acme_order_type_id")
        batch_op.drop_column("acme_order_retry_strategy_id")

    if False:
        # this is not reversible, as new records are likely to violate this constraint
        with op.batch_alter_table(
            "acme_authorization_potential", schema=None
        ) as batch_op:
            batch_op.drop_index(batch_op.f("uidx_acme_authorization_potential"))
            batch_op.create_index(
                "uidx_acme_authorization_potential",
                ["acme_order_id", "domain_id"],
                unique=True,
            )
