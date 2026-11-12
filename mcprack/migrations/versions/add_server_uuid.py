"""Add mcp_servers.uuid.

A stable identity for each kind of MCP server that survives renaming (the
catalog `name` is mutable). Existing rows get a random UUID; a server whose
project declares one in its server.json adopts it the first time its page is
opened (server_info.sync_uuid).

Revision ID: add_server_uuid
Revises: add_user_mfa
Create Date: 2026-11-12 11:00:00.000000

"""

import uuid

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_server_uuid"
down_revision = "add_user_mfa"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.add_column(sa.Column("uuid", sa.String(36), nullable=True))

    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id FROM mcp_servers")).fetchall()
    for (server_id,) in rows:
        conn.execute(
            sa.text("UPDATE mcp_servers SET uuid = :u WHERE id = :i"),
            {"u": str(uuid.uuid4()), "i": server_id},
        )

    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.alter_column("uuid", existing_type=sa.String(36), nullable=False)
        batch_op.create_index("ix_mcp_servers_uuid", ["uuid"], unique=True)


def downgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.drop_index("ix_mcp_servers_uuid")
        batch_op.drop_column("uuid")
