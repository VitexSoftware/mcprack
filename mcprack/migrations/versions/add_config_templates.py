"""Add config_templates / config_template_servers and users.config_template_id.

Lets an admin define a reusable server ACL + selection preset ("template")
and apply it to a user in one step, instead of ticking Allow/Deny and
selection checkboxes by hand for every non-technical user. Templates never
store secret values.

Revision ID: add_config_templates
Revises: add_detected_env_vars
Create Date: 2026-08-26 13:10:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_config_templates"
down_revision = "add_detected_env_vars"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "config_templates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_config_templates_name"), "config_templates", ["name"], unique=True
    )

    op.create_table(
        "config_template_servers",
        sa.Column("template_id", sa.Integer(), nullable=False),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("is_allowed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_selected", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(["template_id"], ["config_templates.id"]),
        sa.ForeignKeyConstraint(["server_id"], ["mcp_servers.id"]),
        sa.PrimaryKeyConstraint("template_id", "server_id"),
    )

    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("config_template_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_users_config_template_id",
            "config_templates",
            ["config_template_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("fk_users_config_template_id", type_="foreignkey")
        batch_op.drop_column("config_template_id")

    op.drop_table("config_template_servers")
    op.drop_index(op.f("ix_config_templates_name"), table_name="config_templates")
    op.drop_table("config_templates")
