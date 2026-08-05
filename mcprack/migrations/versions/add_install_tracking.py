"""Add install-tracking columns to mcp_servers for the pip/npm/docker
installer subsystem.

Revision ID: add_install_tracking
Revises: add_audit_log_entries
Create Date: 2026-08-03 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_install_tracking"
down_revision = "add_audit_log_entries"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.add_column(sa.Column("install_method", sa.String(10), nullable=True))
        batch_op.add_column(sa.Column("package_spec", sa.String(500), nullable=True))
        batch_op.add_column(sa.Column("expected_binary", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("install_path", sa.String(500), nullable=True))
        batch_op.add_column(sa.Column("install_status", sa.String(20), nullable=True))
        batch_op.add_column(sa.Column("install_log_path", sa.String(500), nullable=True))
        batch_op.add_column(sa.Column("install_error", sa.String(500), nullable=True))
        batch_op.add_column(sa.Column("installed_version", sa.String(100), nullable=True))
        batch_op.add_column(sa.Column("installed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.drop_column("installed_at")
        batch_op.drop_column("installed_version")
        batch_op.drop_column("install_error")
        batch_op.drop_column("install_log_path")
        batch_op.drop_column("install_status")
        batch_op.drop_column("install_path")
        batch_op.drop_column("expected_binary")
        batch_op.drop_column("package_spec")
        batch_op.drop_column("install_method")
