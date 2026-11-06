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


def test_rate_limited_response_keeps_the_retry_after_header(limited_client):
    """The 429 is rendered by app.py's own error handler; Flask-Limiter adds
    Retry-After from an after_request hook, which only fires when
    RATELIMIT_HEADERS_ENABLED stays on."""
    for _ in range(3):
        limited_client.post("/login", data={"username": "nobody", "password": "wrong"})

    resp = limited_client.post("/login", data={"username": "nobody", "password": "wrong"})

    assert resp.status_code == 429
    assert resp.headers.get("Retry-After")
    assert "Back to Catalog" in resp.get_data(as_text=True)


def test_password_change_is_rate_limited(limited_app, limited_client):
    """The form checks current_password, so it is the same brute-force
    surface as /login."""
    from mcprack.extensions import db
    from mcprack.models import User

    with limited_app.app_context():
        user = User(username="alice", auth_type="local")
        user.set_password("rightpass")
        db.session.add(user)
        db.session.commit()

    limited_client.post("/login", data={"username": "alice", "password": "rightpass"})

    statuses = [
        limited_client.post("/account/password", data={
            "current_password": "guess", "new_password": "newpass123", "confirm_password": "newpass123",
        }).status_code
        for _ in range(5)
    ]

    assert 429 in statuses
