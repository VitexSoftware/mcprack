"""Add OAuth Authorization Server tables for optional MCP OAuth.

Revision ID: add_oauth_tables
Revises: add_api_token_expiry_scopes
Create Date: 2026-10-29 22:30:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "add_oauth_tables"
down_revision = "add_api_token_expiry_scopes"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("client_id", sa.String(length=48), nullable=True),
        sa.Column("client_secret", sa.String(length=120), nullable=True),
        sa.Column("client_id_issued_at", sa.Integer(), nullable=False),
        sa.Column("client_secret_expires_at", sa.Integer(), nullable=False),
        sa.Column("client_metadata", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_oauth_clients_client_id"), "oauth_clients", ["client_id"])

    op.create_table(
        "oauth_authorization_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=120), nullable=False),
        sa.Column("client_id", sa.String(length=48), nullable=True),
        sa.Column("redirect_uri", sa.Text(), nullable=True),
        sa.Column("response_type", sa.Text(), nullable=True),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("nonce", sa.Text(), nullable=True),
        sa.Column("auth_time", sa.Integer(), nullable=False),
        sa.Column("acr", sa.Text(), nullable=True),
        sa.Column("amr", sa.Text(), nullable=True),
        sa.Column("code_challenge", sa.Text(), nullable=True),
        sa.Column("code_challenge_method", sa.String(length=48), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )

    op.create_table(
        "oauth_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("client_id", sa.String(length=48), nullable=True),
        sa.Column("token_type", sa.String(length=40), nullable=True),
        sa.Column("access_token", sa.String(length=255), nullable=False),
        sa.Column("refresh_token", sa.String(length=255), nullable=True),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("access_token_revoked_at", sa.Integer(), nullable=False),
        sa.Column("refresh_token_revoked_at", sa.Integer(), nullable=False),
        sa.Column("expires_in", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("access_token"),
    )
    op.create_index(op.f("ix_oauth_tokens_user_id"), "oauth_tokens", ["user_id"])
    op.create_index(op.f("ix_oauth_tokens_refresh_token"), "oauth_tokens", ["refresh_token"])


def downgrade():
    op.drop_index(op.f("ix_oauth_tokens_refresh_token"), table_name="oauth_tokens")
    op.drop_index(op.f("ix_oauth_tokens_user_id"), table_name="oauth_tokens")
    op.drop_table("oauth_tokens")
    op.drop_table("oauth_authorization_codes")
    op.drop_index(op.f("ix_oauth_clients_client_id"), table_name="oauth_clients")
    op.drop_table("oauth_clients")
