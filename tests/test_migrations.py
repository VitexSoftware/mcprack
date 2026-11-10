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
