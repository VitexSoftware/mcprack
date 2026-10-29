"""Optional MCP OAuth: tokenless /proxy/mcp/<id> + discovery + DCR + code flow."""

import base64
import hashlib
import secrets
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest

from mcprack.config import Config
from mcprack.extensions import db
from mcprack.models import (
    OAUTH_MCP_SCOPE,
    ApiToken,
    McpServer,
    User,
    UserServerSelection,
)


class OAuthConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    OAUTH_ENABLED = True
    PUBLIC_BASE_URL = "https://mcprack.test"
    BW_SERVER = ""
    BW_CLIENTID = ""
    BW_CLIENTSECRET = ""
    BW_PASSWORD = ""


@pytest.fixture
def oauth_app(tmp_path, monkeypatch):
    from mcprack import installer, user_proxy
    from mcprack.app import create_app

    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "user-proxies")
    monkeypatch.setattr(installer, "STATE_DIR", tmp_path / "installs")
    application = create_app(OAuthConfig)
    application.config["BITWARDENCLI_APPDATA_DIR"] = str(tmp_path / "bw")
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def oauth_client(oauth_app):
    return oauth_app.test_client()


def _make_user(username="alice", password="secret"):
    user = User(username=username, auth_type="local", is_admin=False)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def _make_server(user, name="demo"):
    server = McpServer(
        name=name,
        label=name.title(),
        transport="http",
        url="http://127.0.0.1:9/mcp",
        enabled=True,
    )
    db.session.add(server)
    db.session.commit()
    db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
    db.session.commit()
    return server


def _login(client, username="alice", password="secret"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def _pkce_pair():
    verifier = secrets.token_urlsafe(32)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def test_tokenless_proxy_404_when_oauth_disabled(client, app):
    """Default installs leave OAUTH_ENABLED off — no tokenless route."""
    assert app.config.get("OAUTH_ENABLED") is False
    assert client.get("/proxy/mcp/1").status_code == 404
    assert client.get("/.well-known/oauth-authorization-server").status_code == 404


def test_discovery_metadata(oauth_client):
    as_meta = oauth_client.get("/.well-known/oauth-authorization-server").get_json()
    assert as_meta["issuer"] == "https://mcprack.test"
    assert as_meta["authorization_endpoint"].endswith("/oauth/authorize")
    assert as_meta["registration_endpoint"].endswith("/oauth/register")
    assert OAUTH_MCP_SCOPE in as_meta["scopes_supported"]
    assert "S256" in as_meta["code_challenge_methods_supported"]

    prm = oauth_client.get("/.well-known/oauth-protected-resource").get_json()
    assert prm["authorization_servers"] == ["https://mcprack.test"]

    prm_s = oauth_client.get("/.well-known/oauth-protected-resource/proxy/mcp/7").get_json()
    assert prm_s["resource"] == "https://mcprack.test/proxy/mcp/7"


def test_tokenless_proxy_challenges_without_bearer(oauth_app, oauth_client):
    with oauth_app.app_context():
        user = _make_user()
        server = _make_server(user)
        server_id = server.id

    resp = oauth_client.post(f"/proxy/mcp/{server_id}")
    assert resp.status_code == 401
    www = resp.headers.get("WWW-Authenticate", "")
    assert "resource_metadata=" in www
    assert f"/proxy/mcp/{server_id}" in www


def test_tokenless_proxy_accepts_api_token_with_proxy_scope(oauth_app, oauth_client):
    with oauth_app.app_context():
        user = _make_user()
        server = _make_server(user)
        raw, token = ApiToken.generate("proxy", user.id, scopes=["proxy:access"])
        db.session.add(token)
        db.session.commit()
        server_id = server.id

    with patch(
        "mcprack.catalog._forward_to_backend_url",
        return_value=oauth_app.response_class(b"ok", status=200),
    ):
        resp = oauth_client.post(
            f"/proxy/mcp/{server_id}",
            headers={"Authorization": f"Bearer {raw}"},
        )
    assert resp.status_code == 200


def test_tokenless_proxy_rejects_api_token_without_proxy_scope(oauth_app, oauth_client):
    with oauth_app.app_context():
        user = _make_user()
        server = _make_server(user)
        raw, token = ApiToken.generate("ro", user.id, scopes=["config:read"])
        db.session.add(token)
        db.session.commit()
        server_id = server.id

    resp = oauth_client.post(
        f"/proxy/mcp/{server_id}",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 401


def test_dynamic_client_registration_and_code_flow(oauth_app, oauth_client):
    with oauth_app.app_context():
        user = _make_user()
        server = _make_server(user)
        server_id = server.id

    reg = oauth_client.post(
        "/oauth/register",
        json={
            "client_name": "Test MCP Client",
            "redirect_uris": ["https://client.test/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": OAUTH_MCP_SCOPE,
        },
    )
    assert reg.status_code in (200, 201)
    client_info = reg.get_json()
    client_id = client_info["client_id"]

    verifier, challenge = _pkce_pair()
    _login(oauth_client)

    authorize = oauth_client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://client.test/cb",
            "scope": OAUTH_MCP_SCOPE,
            "state": "xyz",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code == 200
    assert b"Authorize application" in authorize.data

    consent = oauth_client.post(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://client.test/cb",
            "scope": OAUTH_MCP_SCOPE,
            "state": "xyz",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        data={"confirm": "yes"},
    )
    assert consent.status_code in (302, 303)
    location = consent.headers["Location"]
    assert location.startswith("https://client.test/cb")
    code = parse_qs(urlparse(location).query)["code"][0]
    assert parse_qs(urlparse(location).query)["state"] == ["xyz"]

    token_resp = oauth_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/cb",
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200
    tokens = token_resp.get_json()
    assert "access_token" in tokens
    assert tokens.get("token_type", "").lower() == "bearer"

    with patch(
        "mcprack.catalog._forward_to_backend_url",
        return_value=oauth_app.response_class(b"ok", status=200),
    ):
        proxied = oauth_client.post(
            f"/proxy/mcp/{server_id}",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
    assert proxied.status_code == 200


def test_config_download_omits_path_token_when_oauth_enabled(oauth_app, oauth_client):
    with oauth_app.app_context():
        user = _make_user()
        _make_server(user, name="svc")

    _login(oauth_client)
    resp = oauth_client.get("/download/claude")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "/proxy/mcp/" in body
    # Tokenless form: /proxy/mcp/<digits> with no intermediate signed segment.
    assert '"url": "https://mcprack.test/proxy/mcp/' in body or "/proxy/mcp/" in body
    # A signed itsdangerous token contains dots / hyphens and is longer than
    # a bare integer id — ensure we did not embed one.
    import json

    payload = json.loads(body)
    url = payload["mcpServers"]["svc"]["url"]
    assert url.rstrip("/").rsplit("/", 1)[-1].isdigit()
    assert url.count("/") >= 4  # scheme://host/proxy/mcp/<id>
