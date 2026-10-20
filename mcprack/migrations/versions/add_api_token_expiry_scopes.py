"""Add optional expiry and scope restriction to personal API tokens.

Revision ID: add_api_token_expiry_scopes
Revises: add_vault_item_id
Create Date: 2026-10-19 22:00:00.000000

Both columns are nullable and default to "no restriction", so tokens minted
before this migration behave exactly as before: they never expire and are
unrestricted.

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "add_api_token_expiry_scopes"
down_revision = "add_vault_item_id"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "api_tokens",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "api_tokens",
        sa.Column("scopes", sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_column("api_tokens", "scopes")
    op.drop_column("api_tokens", "expires_at")
