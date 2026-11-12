"""Claude Code integration (docs/AUDIT-2026-11.md section 8).

Claude Code reads `.mcp.json` (project scope, shared through git) and
`~/.claude.json` / `claude mcp add` (user and local scope). Remote servers are
`{"type": "http", "url": ..., "headers": {...}}`, and `${VAR}` is expanded in
`url` and `headers`. The old output put a signed secret inside the URL, which
leaks as soon as the file is committed. The `claude-code` format carries NO
secret: the URL is tokenless and the credential is read from the
MCPRACK_TOKEN environment variable (a name Claude Code does not blank out the
way it does ANTHROPIC_API_KEY & co. in remote headers)."""

import json
import shlex
from datetime import datetime, timedelta, timezone

import pytest

from mcprack import config_formats
from mcprack.extensions import db
from mcprack.models import ApiToken, McpServer, User, UserServerSelection

PW = "carol-long-password-1"


@pytest.fixture
def carol(app):
    app.config["PUBLIC_BASE_URL"] = "https://mcprack.example.com"
    with app.app_context():
        user = User(username="carol", auth_type="local")
        user.set_password(PW)
        server = McpServer(name="zabbix", label="Zabbix", transport="stdio", command="/bin/true", enabled=True)
        other = McpServer(name="evil name; rm -rf /", label="X", transport="http", url="http://127.0.0.1:9/mcp", enabled=True)
        db.session.add_all([user, server, other])
        db.session.commit()
        db.session.add_all([UserServerSelection(user_id=user.id, server_id=s.id) for s in (server, other)])
        db.session.commit()
        return {"user": user.id, "server": server.id, "other": other.id}


def _login(client):
    client.post("/login", data={"username": "carol", "password": PW})


def _api_token(app, scopes=None, expires_at=None, revoked=False, user="carol"):
    with app.app_context():
        owner = User.query.filter_by(username=user).first()
        raw, token = ApiToken.generate("claude-code", owner.id, expires_at=expires_at, scopes=scopes)
        if revoked:
            token.revoked_at = datetime.now(timezone.utc)
        db.session.add(token)
        db.session.commit()
    return raw


# --- the format ---------------------------------------------------------------------------


def test_claude_code_config_contains_no_secret(app, client, carol):
    _login(client)

    body = client.get("/api/v1/me/config/claude-code").get_json()["data"]

    assert body["filename"] == ".mcp.json"
    servers = body["config"]["mcpServers"]
    entry = servers["mcprack"]
    assert entry == {
        "type": "http",
        "url": "https://mcprack.example.com/proxy/mcp/aggregate",
        "headers": {"Authorization": "Bearer ${MCPRACK_TOKEN}"},
    }
    # nothing signed, nothing that could be replayed, if the file is committed
    raw = json.dumps(body["config"])
    assert "Ijo" not in raw and ".eJ" not in raw
    assert raw.count("/proxy/mcp/") == 1


def test_the_token_variable_is_not_one_claude_code_blanks_out(app, client, carol):
    """Claude Code reads credential-looking variables such as ANTHROPIC_API_KEY,
    NPM_TOKEN or HTTPS_PROXY as empty in the url/headers of a remote server, so
    the name must be our own."""
    _login(client)

    entry = client.get("/api/v1/me/config/claude-code").get_json()["data"]["config"]["mcpServers"]["mcprack"]

    variable = entry["headers"]["Authorization"].split("${")[1].rstrip("}")
    assert variable == "MCPRACK_TOKEN"


def test_with_oauth_enabled_the_file_has_no_header_at_all(app, client, carol):
    """Claude Code runs the OAuth login itself (/mcp or `claude mcp login`)."""
    app.config["OAUTH_ENABLED"] = True
    _login(client)

    entry = client.get("/api/v1/me/config/claude-code").get_json()["data"]["config"]["mcpServers"]["mcprack"]

    assert entry == {"type": "http", "url": "https://mcprack.example.com/proxy/mcp/aggregate"}


def test_the_token_variant_can_be_asked_for_even_with_oauth_enabled(app, client, carol):
    app.config["OAUTH_ENABLED"] = True
    _login(client)

    entry = client.get("/api/v1/me/config/claude-code?auth=token").get_json()["data"]["config"]["mcpServers"]["mcprack"]

    assert entry["headers"] == {"Authorization": "Bearer ${MCPRACK_TOKEN}"}


def test_download_is_a_dot_mcp_json_attachment(app, client, carol):
    _login(client)

    resp = client.get("/download/claude-code")

    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"] == "attachment; filename=.mcp.json"
    assert json.loads(resp.data)["mcpServers"]["mcprack"]["type"] == "http"


def test_the_view_page_offers_copyable_claude_commands(app, client, carol):
    _login(client)

    html = client.get("/view/claude-code").get_data(as_text=True)

    assert "claude mcp add --transport http --scope user" in html
    assert "MCPRACK_TOKEN" in html


def test_commands_quote_every_value_for_the_shell():
    servers = [{"name": "evil name; rm -rf /", "url": "https://h.example/proxy/mcp/3"}]

    lines = config_formats.claude_code_commands(servers, header=True)

    assert len(lines) == 1
    parts = shlex.split(lines[0])
    assert parts[:6] == ["claude", "mcp", "add", "--transport", "http", "--scope"]
    assert "evil name; rm -rf /" in parts  # one argument, not a shell command
    assert parts[-2:] == ["--header", "Authorization: Bearer $MCPRACK_TOKEN"]  # left for the user's shell to expand


def test_commands_without_a_header_for_oauth():
    lines = config_formats.claude_code_commands([{"name": "z", "url": "https://h/proxy/mcp/1"}], header=False)

    assert "--header" not in lines[0]
    assert lines[0].endswith("https://h/proxy/mcp/1")


# --- the bearer route no longer needs the OAuth server -------------------------------------


def _call(app, server_id, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return app.test_client().post(
        f"/proxy/mcp/{server_id}", data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        content_type="application/json", headers=headers,
    )


def test_an_api_token_with_the_proxy_scope_works_without_oauth(app, carol):
    token = _api_token(app, scopes=["proxy:access"])

    assert _call(app, carol["other"], token).status_code == 502  # authenticated; the backend is unreachable


def test_a_token_without_the_proxy_scope_is_refused(app, carol):
    token = _api_token(app, scopes=["profile:read"])

    assert _call(app, carol["other"], token).status_code == 401


def test_expired_and_revoked_tokens_are_refused(app, carol):
    expired = _api_token(app, scopes=["proxy:access"], expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    revoked = _api_token(app, scopes=["proxy:access"], revoked=True)

    assert _call(app, carol["other"], expired).status_code == 401
    assert _call(app, carol["other"], revoked).status_code == 401


def test_no_credential_is_a_401_with_a_bearer_challenge_not_a_404(app, carol):
    resp = _call(app, carol["other"])

    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"].startswith("Bearer")
    assert "resource_metadata" not in resp.headers["WWW-Authenticate"]  # there is no OAuth server to point at


def test_the_user_acl_and_selection_still_apply_on_the_bearer_route(app, carol):
    with app.app_context():
        stranger = McpServer(name="not-mine", label="N", transport="http", url="http://127.0.0.1:9/x", enabled=True)
        db.session.add(stranger)
        db.session.commit()
        stranger_id = stranger.id
    token = _api_token(app, scopes=["proxy:access"])

    assert _call(app, stranger_id, token).status_code == 403  # not selected


def test_the_bearer_route_can_be_switched_off(app, carol):
    app.config["PROXY_BEARER_ENABLED"] = False
    token = _api_token(app, scopes=["proxy:access"])

    assert _call(app, carol["other"], token).status_code == 404


# --- API tokens expire by default ------------------------------------------------------------


def test_new_api_tokens_expire_by_default(app, client, carol):
    _login(client)

    resp = client.post("/api/v1/tokens", json={"name": "ci", "scopes": ["proxy:access"]})

    expires = datetime.fromisoformat(resp.get_json()["data"]["expires_at"])
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    assert 88 <= days <= 90


def test_an_explicit_expiry_wins_and_the_default_can_be_turned_off(app, client, carol):
    _login(client)

    explicit = client.post("/api/v1/tokens", json={"name": "a", "expires_in_days": 7}).get_json()["data"]["expires_at"]
    assert 5 <= (datetime.fromisoformat(explicit).replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days <= 7

    app.config["API_TOKEN_DEFAULT_EXPIRY_DAYS"] = 0
    forever = client.post("/api/v1/tokens", json={"name": "b"}).get_json()["data"]["expires_at"]
    assert forever is None
