"""The API-vs-browser split of the error handlers in app.py: every status
must come back as JSON for /api/, /proxy/ and OAuth callers (or anything
sending Accept: application/json) and as a rendered, translated page for
browsers - and the 500 page must never echo the exception text."""

import pytest
from flask import abort

from mcprack.app import create_app
from mcprack.config import Config
from mcprack.extensions import db as _db

JSON = {"Accept": "application/json"}


class ErrorPageConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False


class RateLimitedConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = True
    LOGIN_RATE_LIMIT = "1 per minute"


def _register_boom_routes(app):
    def boom_400():
        abort(400)

    def boom_502():
        abort(502)

    def boom_500():
        raise RuntimeError("db password hunter2 in /etc/mcprack/env")

    app.add_url_rule("/boom/400", "boom_400", boom_400)
    app.add_url_rule("/boom/502", "boom_502", boom_502)
    app.add_url_rule("/boom/500", "boom_500", boom_500)


@pytest.fixture
def error_app():
    application = create_app(ErrorPageConfig)
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def error_client(error_app):
    return error_app.test_client()


def test_400_json_branch_for_api_callers(error_app, error_client):
    _register_boom_routes(error_app)
    resp = error_client.get("/boom/400", headers=JSON)
    assert resp.status_code == 400
    assert resp.is_json
    assert resp.get_json()["error"] == "bad_request"


def test_400_html_branch_for_browsers(error_app, error_client):
    _register_boom_routes(error_app)
    resp = error_client.get("/boom/400")
    assert resp.status_code == 400
    body = resp.get_data(as_text=True)
    assert "400" in body
    assert "Back to Catalog" in body


def test_413_json_branch_for_api_callers(error_client):
    """The MAX_CONTENT_LENGTH cap raises before routing, so the handler's
    JSON branch is the one API clients see."""
    limit = error_client.application.config["MAX_CONTENT_LENGTH"]
    resp = error_client.post(
        "/login",
        data={"username": "x", "password": "y" * (limit + 1024)},
        headers=JSON,
    )
    assert resp.status_code == 413
    assert resp.is_json
    assert resp.get_json()["error"] == "payload_too_large"


def test_429_json_and_html_branches():
    application = create_app(RateLimitedConfig)
    with application.app_context():
        _db.create_all()
    client = application.test_client()
    try:
        first = client.post("/login", data={"username": "nobody", "password": "wrong"})
        assert first.status_code == 200

        resp = client.post("/login", data={"username": "nobody", "password": "wrong"}, headers=JSON)
        assert resp.status_code == 429
        assert resp.is_json
        assert resp.get_json()["error"] == "rate_limit_exceeded"

        resp = client.post("/login", data={"username": "nobody", "password": "wrong"})
        assert resp.status_code == 429
        body = resp.get_data(as_text=True)
        assert "429" in body
        assert "Back to Catalog" in body
    finally:
        with application.app_context():
            _db.session.remove()
            _db.drop_all()


def test_500_handler_withholds_exception_details_from_both_branches(error_app, error_client):
    _register_boom_routes(error_app)
    error_app.config["PROPAGATE_EXCEPTIONS"] = False

    resp = error_client.get("/boom/500", headers=JSON)
    assert resp.status_code == 500
    assert resp.is_json
    assert resp.get_json()["error"] == "internal_error"
    body = resp.get_data(as_text=True)
    assert "hunter2" not in body
    assert "/etc/mcprack" not in body

    resp = error_client.get("/boom/500")
    assert resp.status_code == 500
    body = resp.get_data(as_text=True)
    assert "500" in body
    assert "hunter2" not in body
    assert "Traceback" not in body


def test_502_handler_has_json_and_html_branches(error_app, error_client):
    _register_boom_routes(error_app)
    resp = error_client.get("/boom/502", headers=JSON)
    assert resp.status_code == 502
    assert resp.is_json
    assert resp.get_json()["error"] == "bad_gateway"

    resp = error_client.get("/boom/502")
    assert resp.status_code == 502
    assert "502" in resp.get_data(as_text=True)
