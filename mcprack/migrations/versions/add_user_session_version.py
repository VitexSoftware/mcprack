"""Add users.session_version.

Embedded in the session cookie at login and compared on every request, so a
copy of a cookie can be killed server-side (logout, password change, account
disabled, tokens revoked - docs/AUDIT-2026-11.md B-05). Existing accounts
start at 0 and cookies without a version count as 0: the upgrade logs nobody
out.

Revision ID: add_user_session_version
Revises: materialize_server_permissions
Create Date: 2026-11-10 13:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_user_session_version"
down_revision = "materialize_server_permissions"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("session_version", sa.Integer(), nullable=False, server_default="0")
        )


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("session_version")
