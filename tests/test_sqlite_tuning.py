"""The SQLite engine tuning applied by create_app (see app.py): WAL journal
mode plus a busy_timeout, so concurrent gunicorn workers writing audit rows
don't fail with "database is locked"."""

import pytest

from mcprack.app import create_app
from mcprack.config import Config
from mcprack.extensions import db

from sqlalchemy import text


class _FileDbConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret"
    # :memory: databases cannot switch to WAL - the pragmas only mean
    # anything on a real file-backed database, like production's
    # /var/lib/mcprack/mcprack.db.
    SQLALCHEMY_DATABASE_URI = None  # set per-test below


@pytest.fixture
def file_db_app(tmp_path):
    cfg = type("Cfg", (_FileDbConfig,), {})
    cfg.SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path/'mcprack.db'}"
    app = create_app(cfg)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_sqlite_uses_wal_and_busy_timeout(file_db_app):
    mode = db.session.execute(text("PRAGMA journal_mode")).scalar()
    timeout_ms = db.session.execute(text("PRAGMA busy_timeout")).scalar()
    assert str(mode).lower() == "wal"
    assert timeout_ms == 15000
