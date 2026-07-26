"""Add append-only audit_log_entries table.

Revision ID: add_audit_log_entries
Revises: add_local_secret_storage
Create Date: 2026-07-26 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "add_audit_log_entries"
down_revision = "add_local_secret_storage"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_log_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("server_id", sa.Integer(), nullable=True),
        sa.Column("server_name", sa.String(length=150), nullable=True),
        sa.Column("action", sa.String(length=30), nullable=False),
        sa.Column("result", sa.String(length=10), nullable=False),
        sa.Column("error_code", sa.String(length=50), nullable=True),
        sa.Column("error_message", sa.String(length=500), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("request_id", sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(["server_id"], ["mcp_servers.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_audit_log_entries_timestamp"), "audit_log_entries", ["timestamp"], unique=False
    )
    op.create_index(
        op.f("ix_audit_log_entries_user_id"), "audit_log_entries", ["user_id"], unique=False
    )
    op.create_index(
        op.f("ix_audit_log_entries_server_id"), "audit_log_entries", ["server_id"], unique=False
    )
    op.create_index(
        op.f("ix_audit_log_entries_request_id"), "audit_log_entries", ["request_id"], unique=False
    )
    op.create_index(
        "ix_audit_server_timestamp", "audit_log_entries", ["server_id", "timestamp"], unique=False
    )
    op.create_index(
        "ix_audit_user_timestamp", "audit_log_entries", ["user_id", "timestamp"], unique=False
    )


def downgrade():
    op.drop_index("ix_audit_user_timestamp", table_name="audit_log_entries")
    op.drop_index("ix_audit_server_timestamp", table_name="audit_log_entries")
    op.drop_index(op.f("ix_audit_log_entries_request_id"), table_name="audit_log_entries")
    op.drop_index(op.f("ix_audit_log_entries_server_id"), table_name="audit_log_entries")
    op.drop_index(op.f("ix_audit_log_entries_user_id"), table_name="audit_log_entries")
    op.drop_index(op.f("ix_audit_log_entries_timestamp"), table_name="audit_log_entries")
    op.drop_table("audit_log_entries")
