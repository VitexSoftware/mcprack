"""B-06 (docs/AUDIT-2026-11.md): the REST API is exempt from CSRF protection
(bearer tokens have no ambient credential), but it also accepts the session
cookie - so a cookie-authenticated mutation must carry a CSRF token. Bearer
requests stay token-free."""

import re

import pytest

from mcprack.extensions import db
from mcprack.models import ApiToken, User


@pytest.fixture
def csrf_app(app):
    app.config["WTF_CSRF_ENABLED"] = True
    with app.app_context():
        user = User(username="dave", auth_type="local")
        user.set_password("dave-long-password-1")
        db.session.add(user)
        db.session.commit()
    return app


def _token_from(html):
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html) or re.search(
        r'value="([^"]+)"[^>]*name="csrf_token"', html
    )
    assert match, "no csrf_token field on the page"
    return match.group(1)


def _logged_in(app):
    client = app.test_client()
    login_page = client.get("/login").get_data(as_text=True)
    client.post(
        "/login",
        data={"username": "dave", "password": "dave-long-password-1", "csrf_token": _token_from(login_page)},
    )
    # a page that carries a token for the now-authenticated session
    token = _token_from(client.get("/account/password").get_data(as_text=True))
    return client, token


def test_cookie_authenticated_api_mutation_without_a_token_is_refused(csrf_app):
    client, _ = _logged_in(csrf_app)

    resp = client.post("/api/v1/tokens", json={"name": "from-a-forged-request"})

    assert resp.status_code == 400
    with csrf_app.app_context():
        assert ApiToken.query.count() == 0


def test_cookie_authenticated_api_mutation_with_the_header_works(csrf_app):
    client, token = _logged_in(csrf_app)

    resp = client.post("/api/v1/tokens", json={"name": "legit"}, headers={"X-CSRFToken": token})

    assert resp.status_code == 201


def test_wrong_token_is_refused(csrf_app):
    client, _ = _logged_in(csrf_app)

    resp = client.post("/api/v1/tokens", json={"name": "x"}, headers={"X-CSRFToken": "not-the-token"})

    assert resp.status_code == 400


@pytest.mark.parametrize("method,path", [("put", "/api/v1/me/selections"), ("delete", "/api/v1/tokens/1")])
def test_every_mutating_method_is_covered(csrf_app, method, path):
    client, token = _logged_in(csrf_app)

    refused = getattr(client, method)(path, json={})
    allowed = getattr(client, method)(path, json={}, headers={"X-CSRFToken": token})

    assert refused.status_code == 400
    assert allowed.status_code != 400


def test_reads_with_a_cookie_need_no_token(csrf_app):
    client, _ = _logged_in(csrf_app)

    assert client.get("/api/v1/me").status_code == 200


def test_bearer_requests_need_no_csrf_token(csrf_app):
    with csrf_app.app_context():
        raw, token = ApiToken.generate("ci", User.query.filter_by(username="dave").first().id)
        db.session.add(token)
        db.session.commit()

    resp = csrf_app.test_client().post(
        "/api/v1/tokens", json={"name": "scripted"}, headers={"Authorization": f"Bearer {raw}"}
    )

    assert resp.status_code == 201


def test_unauthenticated_mutation_is_401_not_a_csrf_error(csrf_app):
    resp = csrf_app.test_client().post("/api/v1/tokens", json={"name": "x"})

    assert resp.status_code == 401
