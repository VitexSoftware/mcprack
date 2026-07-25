"""Add env_config column to mcp_servers for storing environment variables.

Revision ID: add_env_config
Revises: 88e6fe369432
Create Date: 2026-07-25 09:45:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_env_config"
down_revision = "88e6fe369432"
branch_labels = None
depends_on = None


def upgrade():
    """Add env_config_json column to mcp_servers table."""
    with op.batch_operations.batch_alter_table("mcp_servers") as batch_op:
        batch_op.add_column(
            sa.Column(
                "env_config_json",
                sa.Text,
                nullable=True,
                default="{}",
                server_default="{}",
            )
        )


def downgrade():
    """Remove env_config_json column."""
    with op.batch_operations.batch_alter_table("mcp_servers") as batch_op:
        batch_op.drop_column("env_config_json")
