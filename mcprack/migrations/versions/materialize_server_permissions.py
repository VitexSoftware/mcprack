"""Materialize the effective server access of users that have no ACL rows.

STRICT_SERVER_PERMISSIONS now defaults to true: a user with no
user_server_permissions rows sees nothing. Until now such a user implicitly
saw every enabled server. To make the upgrade change nobody's access, every
user without any row is given an explicit "allowed" row for each server that
is enabled today (docs/AUDIT-2026-11.md A-06). Users that already have rows
are left alone, and so are servers that are disabled or created later: those
need an explicit grant, exactly as they already did for users with rows.

Revision ID: materialize_server_permissions
Revises: add_user_token_version
Create Date: 2026-11-10 12:00:00.000000

"""

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "materialize_server_permissions"
down_revision = "add_user_token_version"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    users = [
        row[0]
        for row in bind.execute(
            sa.text(
                "SELECT id FROM users WHERE id NOT IN "
                "(SELECT DISTINCT user_id FROM user_server_permissions)"
            )
        )
    ]
    servers = [
        row[0]
        for row in bind.execute(
            sa.text("SELECT id FROM mcp_servers WHERE enabled = :enabled").bindparams(
                sa.bindparam("enabled", True, type_=sa.Boolean)
            )
        )
    ]
    if not users or not servers:
        return

    permissions = sa.table(
        "user_server_permissions",
        sa.column("user_id", sa.Integer),
        sa.column("server_id", sa.Integer),
        sa.column("is_allowed", sa.Boolean),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    now = datetime.now(timezone.utc)
    op.bulk_insert(
        permissions,
        [
            {"user_id": user_id, "server_id": server_id, "is_allowed": True, "updated_at": now}
            for user_id in users
            for server_id in servers
        ],
    )


def downgrade():
    """Nothing to undo: the rows grant exactly what the previous behaviour
    granted implicitly, and cannot be told apart from rows an admin set."""
