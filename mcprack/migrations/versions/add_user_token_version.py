"""Add users.token_version.

Every MCP proxy path token embeds the owner's token_version; bumping the
column revokes all tokens minted before (docs/AUDIT-2026-11.md A-03).
Tokens issued by earlier releases carry no version and stay valid while the
column is still 0, so an upgrade breaks nobody's client configuration.

Revision ID: add_user_token_version
Revises: add_user_override_env_config
Create Date: 2026-11-10 10:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_user_token_version"
down_revision = "add_user_override_env_config"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("token_version", sa.Integer(), nullable=False, server_default="0")
        )


def downgrade():
    """Drop the column. Tokens revoked by a bump become valid again, because
    the previous release has no notion of a version."""
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("token_version")
