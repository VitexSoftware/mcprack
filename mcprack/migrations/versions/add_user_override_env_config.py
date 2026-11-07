"""Add user_server_overrides.env_config_json.

Allows non-sensitive environment configuration to be partially overridden
per-user directly in the database without touching Vaultwarden.

Revision ID: add_user_override_env_config
Revises: add_oauth_tables
Create Date: 2026-11-06 21:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_user_override_env_config"
down_revision = "add_oauth_tables"
branch_labels = None
depends_on = None


def upgrade():
    """Add the column. batch_alter_table because SQLite cannot ALTER a
    column in place and is a supported backend here."""
    with op.batch_alter_table("user_server_overrides") as batch_op:
        batch_op.add_column(
            sa.Column("env_config_json", sa.Text(), nullable=True, server_default="{}")
        )


def downgrade():
    """Drop the column, discarding every per-user non-secret override.
    Secrets are unaffected - they never lived in this column."""
    with op.batch_alter_table("user_server_overrides") as batch_op:
        batch_op.drop_column("env_config_json")
