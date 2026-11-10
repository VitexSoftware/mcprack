"""Add the second-factor columns to users.

totp_secret (encrypted), totp_enabled, totp_last_step (replay protection) and
recovery_codes (keyed hashes) - docs/AUDIT-2026-11.md B-03. Every existing
account starts with MFA off; nothing changes for anybody until they enrol.

Revision ID: add_user_mfa
Revises: add_login_throttle
Create Date: 2026-11-10 20:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_user_mfa"
down_revision = "add_login_throttle"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("totp_secret", sa.String(length=255), nullable=True))
        batch_op.add_column(
            sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch_op.add_column(
            sa.Column("totp_last_step", sa.BigInteger(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("recovery_codes", sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("recovery_codes")
        batch_op.drop_column("totp_last_step")
        batch_op.drop_column("totp_enabled")
        batch_op.drop_column("totp_secret")
