"""Add mcp_servers.vault_item_id.

Caches the (non-secret) Vaultwarden item id of each server's default
secrets note, so lookups can fetch that one cipher by id instead of having
`bw` search -- and decrypt -- the whole vault by name.

Revision ID: add_vault_item_id
Revises: add_config_templates
Create Date: 2026-10-01 10:30:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_vault_item_id"
down_revision = "add_config_templates"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.add_column(sa.Column("vault_item_id", sa.String(64), nullable=True))


def downgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.drop_column("vault_item_id")
