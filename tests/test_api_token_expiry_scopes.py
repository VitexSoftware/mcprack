"""API token expiry and scope restriction.

POST /api/v1/tokens accepts optional `expires_in_days`/`expires_at` and
`scopes`; api_auth.py rejects expired tokens, and api.py's
api_scope_required/api_admin_required enforce scopes for bearer tokens.
"""

import json
from datetime import datetime, timedelta, timezone

from mcprack.extensions import db
from mcprack.models import ApiToken, McpServer, User, UserServerSelection


def _create_user(app, username="alice", is_admin=False):
    with app.app_context():
        user = User(username=username, auth_type="local", is_admin=is_admin)
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        return user.id


def _login(client, username, password="pw"):
    return client.post("/login", data={"username": username, "password": password})


def _mint_token(client, name="ci", **extra):
    payload = {"name": name}
    payload.update(extra)
    resp = client.post("/api/v1/tokens", json=payload)
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["data"]


def _bearer_request(app, method, path, raw_token, **kwargs):
    """A bearer-authenticated request needs a fresh app context and test
    client: the `app` fixture keeps one app context open for the whole test,
    and flask-login caches the resolved (cookie-authenticated) user on
    flask.g — without this the request would reuse that identity instead of
    genuinely authenticating from the Authorization header."""
    with app.app_context():
        fresh = app.test_client()
        return fresh.open(path, method=method, headers={"Authorization": f"Bearer {raw_token}"}, **kwargs)


def _bearer_get(app, path, raw_token):
    return _bearer_request(app, "GET", path, raw_token)


# --- expiry -----------------------------------------------------------------


def test_token_with_future_expiry_works(app, client):
    _create_user(app)
    _login(client, "alice")

    data = _mint_token(client, expires_in_days=30)
    assert data["expires_at"] is not None
    assert data["is_expired"] is False
    assert data["scopes"] == ["*"]

    resp = _bearer_get(app, "/api/v1/me", data["token"])
    assert resp.status_code == 200


def test_token_with_expires_at_iso_works(app, client):
    _create_user(app)
    _login(client, "alice")
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    data = _mint_token(client, expires_at=expires_at)
    assert data["expires_at"] is not None

    resp = _bearer_get(app, "/api/v1/me", data["token"])
    assert resp.status_code == 200


def test_expired_token_is_rejected(app, client):
    _create_user(app)
    _login(client, "alice")
    data = _mint_token(client, expires_in_days=30)

    with app.app_context():
        token = ApiToken.query.filter_by(name="ci").first()
        token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

    resp = _bearer_get(app, "/api/v1/me", data["token"])
    assert resp.status_code == 401


def test_expiry_payload_validation(app, client):
    _create_user(app)
    _login(client, "alice")

    for bad in (0, -5, "30", True, 1.5):
        resp = client.post("/api/v1/tokens", json={"name": "x", "expires_in_days": bad})
        assert resp.status_code == 400, bad

    resp = client.post(
        "/api/v1/tokens",
        json={
            "name": "x",
            "expires_in_days": 30,
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
    )
    assert resp.status_code == 400  # mutually exclusive

    resp = client.post("/api/v1/tokens", json={"name": "x", "expires_at": "not-a-date"})
    assert resp.status_code == 400

    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    resp = client.post("/api/v1/tokens", json={"name": "x", "expires_at": past})
    assert resp.status_code == 400


# --- scope validation ---------------------------------------------------------


def test_scope_payload_validation(app, client):
    _create_user(app)
    _login(client, "alice")

    resp = client.post("/api/v1/tokens", json={"name": "x", "scopes": ["bogus"]})
    assert resp.status_code == 400
    assert "bogus" in resp.get_json()["error"]["message"]

    for bad in ("config:read", [1], [None], 42):
        resp = client.post("/api/v1/tokens", json={"name": "x", "scopes": bad})
        assert resp.status_code == 400, bad


# --- scope enforcement --------------------------------------------------------


def test_legacy_token_without_expiry_or_scopes_is_unrestricted(app, client):
    """A token minted without the new options — i.e. every token that
    existed before this feature — must keep working exactly as before."""
    _create_user(app)
    _login(client, "alice")
    data = _mint_token(client)
    assert data["expires_at"] is None
    assert data["is_expired"] is False
    assert data["scopes"] == ["*"]

    raw = data["token"]
    assert _bearer_get(app, "/api/v1/me", raw).status_code == 200
    assert _bearer_get(app, "/api/v1/servers", raw).status_code == 200
    assert _bearer_get(app, "/api/v1/tokens", raw).status_code == 200
    assert _bearer_get(app, "/api/v1/me/selections", raw).status_code == 200


def test_scoped_token_is_limited_to_its_scopes(app, client):
    _create_user(app)
    _login(client, "alice")
    raw = _mint_token(client, scopes=["config:read"])["token"]

    resp = _bearer_get(app, "/api/v1/me", raw)
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "insufficient_scope"

    assert _bearer_get(app, "/api/v1/servers", raw).status_code == 403
    assert _bearer_get(app, "/api/v1/tokens", raw).status_code == 403
    assert _bearer_get(app, "/api/v1/me/selections", raw).status_code == 403
    resp = _bearer_request(app, "POST", "/api/v1/tokens", raw, json={"name": "x"})
    assert resp.status_code == 403


def test_scoped_token_can_call_its_own_endpoint(app, client):
    _create_user(app)
    _login(client, "alice")
    raw = _mint_token(client, scopes=["profile:read"])["token"]

    assert _bearer_get(app, "/api/v1/me", raw).status_code == 200
    assert _bearer_get(app, "/api/v1/servers", raw).status_code == 403


def test_config_read_scope_allows_config_download(app, client):
    user_id = _create_user(app)
    with app.app_context():
        server = McpServer(name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True)
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=server.id))
        db.session.commit()
    _login(client, "alice")

    raw = _mint_token(client, scopes=["config:read"])["token"]
    resp = _bearer_get(app, "/api/v1/me/config/claude", raw)
    assert resp.status_code == 200
    assert "svc" in resp.get_json()["data"]["config"]["mcpServers"]

    other = _mint_token(client, name="profile-only", scopes=["profile:read"])["token"]
    assert _bearer_get(app, "/api/v1/me/config/claude", other).status_code == 403


def test_admin_read_scope_allows_gets_but_not_writes(app, client):
    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    raw = _mint_token(client, scopes=["admin:read"])["token"]

    assert _bearer_get(app, "/api/v1/admin/users", raw).status_code == 200
    assert _bearer_get(app, "/api/v1/admin/servers", raw).status_code == 200

    resp = _bearer_request(
        app, "POST", "/api/v1/admin/users", raw, json={"username": "mallory", "password": "pw"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "insufficient_scope"


def test_admin_write_scope_covers_reads_and_writes(app, client):
    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    raw = _mint_token(client, scopes=["admin:write"])["token"]

    assert _bearer_get(app, "/api/v1/admin/users", raw).status_code == 200
    resp = _bearer_request(
        app, "POST", "/api/v1/admin/users", raw, json={"username": "mallory", "password": "pw"}
    )
    assert resp.status_code == 201


def test_scopes_never_grant_admin(app, client):
    """An unrestricted token of a non-admin user still fails the admin
    check — scopes restrict, they don't grant."""
    _create_user(app, "alice")
    _login(client, "alice")
    raw = _mint_token(client)["token"]

    resp = _bearer_get(app, "/api/v1/admin/users", raw)
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "forbidden"


def test_session_cookie_is_not_scope_limited(app, client):
    """Interactive session-cookie users keep full access — scopes are a
    property of API tokens, not of browser sessions."""
    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    assert client.get("/api/v1/admin/users").status_code == 200
    assert client.get("/api/v1/me").status_code == 200


# --- escalation guards ----------------------------------------------------------


def test_scoped_token_cannot_mint_unrestricted_or_broader_tokens(app, client):
    _create_user(app)
    _login(client, "alice")
    creator = _mint_token(client, name="limited", scopes=["tokens:manage", "config:read"])["token"]

    resp = _bearer_request(app, "POST", "/api/v1/tokens", creator, json={"name": "child"})
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "insufficient_scope"

    resp = _bearer_request(app, "POST", "/api/v1/tokens", creator, json={"name": "child", "scopes": ["*"]})
    assert resp.status_code == 403

    resp = _bearer_request(
        app, "POST", "/api/v1/tokens", creator, json={"name": "child", "scopes": ["admin:write"]}
    )
    assert resp.status_code == 403

    # A subset of the creator's own scopes is fine.
    resp = _bearer_request(
        app, "POST", "/api/v1/tokens", creator, json={"name": "child", "scopes": ["config:read"]}
    )
    assert resp.status_code == 201
    assert resp.get_json()["data"]["scopes"] == ["config:read"]


def test_scoped_token_cannot_mint_a_longer_lived_token(app, client):
    _create_user(app)
    _login(client, "alice")
    creator = _mint_token(
        client, name="limited", scopes=["tokens:manage", "config:read"], expires_in_days=30
    )["token"]

    resp = _bearer_request(
        app,
        "POST",
        "/api/v1/tokens",
        creator,
        json={"name": "child", "scopes": ["config:read"], "expires_in_days": 1},
    )
    assert resp.status_code == 201

    resp = _bearer_request(
        app,
        "POST",
        "/api/v1/tokens",
        creator,
        json={"name": "child", "scopes": ["config:read"], "expires_in_days": 60},
    )
    assert resp.status_code == 403

    # A no-expiry child would outlive the creator — rejected.
    resp = _bearer_request(
        app, "POST", "/api/v1/tokens", creator, json={"name": "child", "scopes": ["config:read"]}
    )
    assert resp.status_code == 403


# --- serialization + model helpers ----------------------------------------------


def test_token_list_shows_expiry_and_scopes(app, client):
    _create_user(app)
    _login(client, "alice")
    _mint_token(client, name="scoped", scopes=["config:read"], expires_in_days=30)
    _mint_token(client, name="plain")

    resp = client.get("/api/v1/tokens")
    assert resp.status_code == 200
    by_name = {t["name"]: t for t in resp.get_json()["data"]}
    assert by_name["scoped"]["scopes"] == ["config:read"]
    assert by_name["scoped"]["expires_at"] is not None
    assert by_name["scoped"]["is_expired"] is False
    assert by_name["plain"]["scopes"] == ["*"]
    assert by_name["plain"]["expires_at"] is None


def test_scope_list_parsing():
    _, token = ApiToken.generate("t", user_id=1)
    assert token.scope_list is None

    token.scopes = json.dumps(["config:read"])
    assert token.scope_list == ["config:read"]

    token.scopes = json.dumps(["*"])
    assert token.scope_list is None

    token.scopes = "not-json"
    assert token.scope_list is None

    token.scopes = json.dumps("config:read")  # valid JSON, but not a list
    assert token.scope_list is None


def test_is_expired_handles_naive_and_aware_datetimes():
    _, token = ApiToken.generate("t", user_id=1)
    assert token.is_expired is False

    # SQLite and MySQL don't round-trip tzinfo — a naive value is treated
    # as UTC rather than crashing on the comparison.
    token.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
    assert token.is_expired is True

    token.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1)
    assert token.is_expired is False

    token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert token.is_expired is True


def test_allows_any():
    _, unrestricted = ApiToken.generate("t", user_id=1)
    assert unrestricted.allows_any(("config:read",))
    assert unrestricted.allows_any(("admin:write",))

    _, token = ApiToken.generate("t", user_id=1, scopes=["config:read"])
    assert token.allows_any(("config:read",))
    assert token.allows_any(("profile:read", "config:read"))
    assert not token.allows_any(("profile:read",))
    assert not token.allows_any(("admin:read", "admin:write"))
