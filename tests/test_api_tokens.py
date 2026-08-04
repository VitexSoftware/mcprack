from extensions import db
from models import ApiToken, User


def _create_user(app, username="alice", is_admin=False):
    with app.app_context():
        user = User(username=username, auth_type="local", is_admin=is_admin)
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        return user.id


def _login(client, username, password="pw"):
    return client.post("/login", data={"username": username, "password": password})


def test_token_issuance_returns_raw_token_once(app, client):
    _create_user(app, "alice")
    _login(client, "alice")

    resp = client.post("/api/v1/tokens", json={"name": "ci-script"})
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["data"]["name"] == "ci-script"
    assert body["data"]["token"].startswith("mcpk_")
    assert "token_hash" not in body["data"]

    with app.app_context():
        token = ApiToken.query.filter_by(name="ci-script").first()
        assert token is not None
        assert token.token_hash != body["data"]["token"]


def test_bearer_token_authenticates_without_cookies(app, client):
    user_id = _create_user(app, "alice")
    _login(client, "alice")

    raw_token = client.post("/api/v1/tokens", json={"name": "ci"}).get_json()["data"]["token"]

    # A fresh test_client has no cookies, but flask-login also caches the
    # resolved user on flask.g for the lifetime of the *app context* - and
    # the `app` fixture keeps one app context open for the whole test, so a
    # bare `app.test_client()` call here would still see alice's g-cached
    # identity from the request above rather than genuinely re-resolving
    # via the bearer token. Pushing a nested app context gives this request
    # its own flask.g, forcing a real re-authentication from the header.
    with app.app_context():
        fresh = app.test_client()
        resp = fresh.get("/api/v1/me", headers={"Authorization": f"Bearer {raw_token}"})
    assert resp.status_code == 200
    assert resp.get_json()["data"]["id"] == user_id


def test_missing_auth_returns_401_json_not_a_redirect(client):
    resp = client.get("/api/v1/me")
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "unauthorized"


def test_garbage_bearer_token_returns_401(client):
    resp = client.get("/api/v1/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_revoked_token_stops_working(app, client):
    _create_user(app, "alice")
    _login(client, "alice")

    data = client.post("/api/v1/tokens", json={"name": "ci"}).get_json()["data"]
    raw_token, token_id = data["token"], data["id"]

    resp = client.delete(f"/api/v1/tokens/{token_id}")
    assert resp.status_code == 204

    with app.app_context():
        fresh = app.test_client()
        resp = fresh.get("/api/v1/me", headers={"Authorization": f"Bearer {raw_token}"})
    assert resp.status_code == 401


def test_cannot_revoke_another_users_token(app, client):
    _create_user(app, "alice")
    _create_user(app, "bob")
    _login(client, "alice")
    token_id = client.post("/api/v1/tokens", json={"name": "ci"}).get_json()["data"]["id"]

    with app.app_context():
        other_client = app.test_client()
        _login(other_client, "bob")
        resp = other_client.delete(f"/api/v1/tokens/{token_id}")
    assert resp.status_code == 404
