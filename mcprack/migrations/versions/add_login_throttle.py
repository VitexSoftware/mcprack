"""Add login_throttle.

Failed-login counters shared by every gunicorn worker (the Flask-Limiter
budget lived in each worker's memory). Keys are hashes of the lower-cased
username and of the client address, never the values themselves
(docs/AUDIT-2026-11.md B-04).

Revision ID: add_login_throttle
Revises: add_user_session_version
Create Date: 2026-11-10 14:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_login_throttle"
down_revision = "add_user_session_version"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "login_throttle",
        sa.Column("scope", sa.String(length=8), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_failure_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lock_level", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("scope", "key"),
    )


def downgrade():
    op.drop_table("login_throttle")
