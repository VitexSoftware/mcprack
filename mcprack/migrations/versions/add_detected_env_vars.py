"""Add detected_env_vars_json and required_env_keys_json columns to mcp_servers.

Revision ID: add_detected_env_vars
Revises: add_api_tokens
Create Date: 2026-08-07 21:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_detected_env_vars"
down_revision = "add_api_tokens"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.add_column(sa.Column("detected_env_vars_json", sa.Text, nullable=True))
        batch_op.add_column(sa.Column("required_env_keys_json", sa.Text, nullable=True))


def downgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.drop_column("required_env_keys_json")
        batch_op.drop_column("detected_env_vars_json")
