import re

import pytest

from app import create_app
from config import Config
from extensions import db as _db


class CsrfEnabledConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    RATELIMIT_ENABLED = False
    # WTF_CSRF_ENABLED left at its default (True) - this is the whole point
    # of this test module, unlike conftest.py's TestConfig which disables it.


@pytest.fixture
def csrf_app():
    application = create_app(CsrfEnabledConfig)
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def csrf_client(csrf_app):
    return csrf_app.test_client()


def _extract_csrf_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "csrf_token hidden field not found in rendered form"
    return match.group(1)


def test_login_post_without_csrf_token_is_rejected(csrf_client):
    resp = csrf_client.post(
        "/login", data={"username": "nobody", "password": "irrelevant"}
    )
    assert resp.status_code == 400


def test_login_post_with_valid_csrf_token_is_accepted(csrf_client):
    get_resp = csrf_client.get("/login")
    token = _extract_csrf_token(get_resp.data.decode())

    resp = csrf_client.post(
        "/login",
        data={"username": "nobody", "password": "irrelevant", "csrf_token": token},
    )
    # Wrong credentials, but past CSRF validation - not a 400.
    assert resp.status_code == 200


def test_user_proxy_mcp_post_is_csrf_exempt(csrf_client):
    from catalog import _make_proxy_token
    from models import McpServer, User

    with csrf_client.application.app_context():
        user = User(username="alice", auth_type="local")
        user.set_password("pw")
        server = McpServer(
            name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True
        )
        _db.session.add_all([user, server])
        _db.session.commit()
        token = _make_proxy_token(user.id, server.id)

    # No csrf_token field at all - must not be rejected with 400 for CSRF
    # reasons (it may still 403 for other reasons, e.g. no selection row).
    resp = csrf_client.post(f"/proxy/mcp/{token}/{server.id}", data=b"{}")
    assert resp.status_code != 400
