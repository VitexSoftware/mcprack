import pytest

from mcprack.app import create_app
from mcprack.config import Config
from mcprack.extensions import db as _db


class RateLimitedConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = True
    LOGIN_RATE_LIMIT = "3 per minute"


@pytest.fixture
def limited_app():
    application = create_app(RateLimitedConfig)
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def limited_client(limited_app):
    return limited_app.test_client()


def test_login_is_rate_limited_after_configured_threshold(limited_client):
    for _ in range(3):
        resp = limited_client.post(
            "/login", data={"username": "nobody", "password": "wrong"}
        )
        assert resp.status_code == 200

    resp = limited_client.post(
        "/login", data={"username": "nobody", "password": "wrong"}
    )
    assert resp.status_code == 429
