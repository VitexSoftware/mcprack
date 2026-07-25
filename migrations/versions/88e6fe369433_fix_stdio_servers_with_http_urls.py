"""Fix stdio servers with incorrect HTTP URLs

Revision ID: 88e6fe369433
Revises: 88e6fe369432
Create Date: 2026-07-25 04:15:00.000000

Background:
Webdriver and mastodon were accidentally created with transport=stdio but url set to 
http://10.11.182.99:3100/mcp/, which caused VS Code Copilot to try connecting to a 
non-existent endpoint. This migration clears their URLs so they're properly treated 
as local stdio servers.

The HTTP proxy will be managed separately via fastmcp on port 3100, and clients 
will automatically receive the correct config based on whether they're local or remote.
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '88e6fe369433'
down_revision = '88e6fe369432'
branch_labels = None
depends_on = None


def upgrade():
    """Clear HTTP URLs from stdio servers that were misconfigured."""
    # Remove URL from webdriver and mastodon (stdio servers)
    # These should be spawned locally on the client, not connected to 3100
    op.execute("""
    UPDATE mcp_servers 
    SET url = NULL 
    WHERE name IN ('webdriver', 'mastodon') 
    AND transport = 'stdio'
    """)


def downgrade():
    """Restore the URLs (not recommended - this was a bug fix)."""
    # In case we need to revert, but this shouldn't be done in production
    # The URLs were incorrect anyway
    pass
