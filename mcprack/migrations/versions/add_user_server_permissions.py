"""Add explicit per-user MCP server permissions.

Revision ID: add_user_server_permissions
Revises: add_env_config
Create Date: 2026-07-25 15:05:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "add_user_server_permissions"
down_revision = "add_env_config"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_server_permissions",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("is_allowed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["server_id"], ["mcp_servers.id"], ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ),
        sa.PrimaryKeyConstraint("user_id", "server_id"),
    )


def downgrade():
    op.drop_table("user_server_permissions")
