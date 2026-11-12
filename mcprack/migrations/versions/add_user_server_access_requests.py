"""Store user requests for access to MCP servers.

Revision ID: add_user_server_access_requests
Revises: add_server_uuid
Create Date: 2026-11-12 15:40:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "add_user_server_access_requests"
down_revision = "add_server_uuid"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_server_access_requests",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by_id", sa.Integer(), nullable=True),
        sa.CheckConstraint("status IN ('pending', 'approved', 'denied')", name="ck_access_request_status"),
        sa.ForeignKeyConstraint(["resolved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["server_id"], ["mcp_servers.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("user_id", "server_id"),
    )
    op.create_index(
        "ix_access_requests_status_requested",
        "user_server_access_requests",
        ["status", "requested_at"],
    )


def downgrade():
    op.drop_index("ix_access_requests_status_requested", table_name="user_server_access_requests")
    op.drop_table("user_server_access_requests")