"""Every hardening migration must be reversible: downgrade to its parent and
upgrade again on a real (file) database, with the schema as expected."""

import pytest
from flask_migrate import downgrade, upgrade
from sqlalchemy import inspect

from mcprack.app import create_app
from mcprack.extensions import db

from conftest import TestConfig

# revision -> (parent revision, table, column added by the revision)
HARDENING_MIGRATIONS = [
    ("add_user_token_version", "add_user_override_env_config", "users", "token_version"),
    ("add_user_session_version", "materialize_server_permissions", "users", "session_version"),
]


@pytest.fixture
def file_app(tmp_path):
    class FileConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'migrate.db'}"

    app = create_app(FileConfig)
    with app.app_context():
        yield app
        db.session.remove()


def _columns(table):
    return {col["name"] for col in inspect(db.engine).get_columns(table)}


@pytest.mark.parametrize("revision,parent,table,column", HARDENING_MIGRATIONS)
def test_migration_round_trips(file_app, revision, parent, table, column):
    # create_app() bootstraps a fresh database at head
    assert column in _columns(table)

    downgrade(revision=parent)
    assert column not in _columns(table)

    upgrade()
    assert column in _columns(table)


def test_materialize_server_permissions_keeps_everybodys_current_access(file_app):
    """The data migration behind the fail-closed default (audit A-06): a user
    with no rows gets an explicit grant for every ENABLED server, a user that
    already has rows is untouched, and re-running does not duplicate."""
    from sqlalchemy import text

    downgrade(revision="add_user_token_version")
    with db.engine.begin() as conn:
        conn.execute(text("INSERT INTO users (id, username, auth_type, is_admin, is_active, token_version) VALUES "
                          "(1, 'open', 'local', 0, 1, 5), (2, 'curated', 'local', 0, 1, 6)"))
        conn.execute(text("INSERT INTO mcp_servers (id, name, label, transport, allow_user_override, enabled) VALUES "
                          "(10, 'a', 'A', 'stdio', 1, 1), (11, 'b', 'B', 'stdio', 1, 1), (12, 'off', 'Off', 'stdio', 1, 0)"))
        conn.execute(text("INSERT INTO user_server_permissions (user_id, server_id, is_allowed) VALUES (2, 10, 0)"))

    upgrade()

    def rows():
        with db.engine.connect() as conn:
            return sorted(
                (r[0], r[1], bool(r[2]))
                for r in conn.execute(text("SELECT user_id, server_id, is_allowed FROM user_server_permissions"))
            )

    assert rows() == [(1, 10, True), (1, 11, True), (2, 10, False)]

    downgrade(revision="add_user_token_version")  # a no-op for data
    upgrade()
    assert rows() == [(1, 10, True), (1, 11, True), (2, 10, False)]  # not duplicated
