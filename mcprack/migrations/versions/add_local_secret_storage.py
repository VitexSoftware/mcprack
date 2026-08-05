"""Add local encrypted secret storage columns (Vaultwarden fallback).

Revision ID: add_local_secret_storage
Revises: add_user_server_permissions
Create Date: 2026-07-26 12:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "add_local_secret_storage"
down_revision = "add_user_server_permissions"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.add_column(sa.Column("env_secrets_encrypted", sa.Text(), nullable=True))
    with op.batch_alter_table("user_server_overrides") as batch_op:
        batch_op.add_column(sa.Column("env_secrets_encrypted", sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table("user_server_overrides") as batch_op:
        batch_op.drop_column("env_secrets_encrypted")
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.drop_column("env_secrets_encrypted")
