import html
import json
import os
from unittest.mock import patch

from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerPermission, UserServerSelection


def _login(client, username="alice"):
    with client.application.app_context():
        user = User(username=username, auth_type="local")
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    client.post("/login", data={"username": username, "password": "pw"})
    return user_id


def _add_selected_server(app, user_id):
    with app.app_context():
        server = McpServer(
            name="jenkins", label="Jenkins", transport="http",
            url="https://jenkins.example.test/mcp", auth_header_name="Authorization",
            auth_env_key="AUTH_TOKEN", enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=server.id))
        db.session.commit()
        return server.id


def _add_enabled_server(app, name="icon-test"):
    with app.app_context():
        server = McpServer(
            name=name,
            label=name,
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        return server.id


def test_view_renders_textarea_with_config_json(app, client):
    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("mcprack.catalog.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.catalog.vaultwarden.lock"), \
         patch("mcprack.catalog.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret-value"}):
        resp = client.get("/view/claude")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "<textarea" in body
    assert "mcpServers" in body
    assert "jenkins" in body
    assert "secret-value" in body
    assert "Copy to clipboard" in body


def test_view_redirects_with_flash_when_nothing_selected(app, client):
    _login(client)

    resp = client.get("/view/claude", follow_redirects=True)
    assert resp.status_code == 200
    assert b"haven&#39;t selected any MCP servers" in resp.data


def test_view_survives_vaultwarden_outage(app, client):
    from mcprack import vaultwarden

    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("mcprack.catalog.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")):
        resp = client.get("/view/claude", follow_redirects=True)

    assert resp.status_code == 200
    assert b"Could not reach Vaultwarden" in resp.data


def test_download_survives_vaultwarden_outage(app, client):
    from mcprack import vaultwarden

    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("mcprack.catalog.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")):
        resp = client.get("/download/claude", follow_redirects=True)

    assert resp.status_code == 200
    assert b"Could not reach Vaultwarden" in resp.data


def test_view_unknown_client_404s(app, client):
    _login(client)
    resp = client.get("/view/not-a-real-client")
    assert resp.status_code == 404


def _extract_textarea_text(html_body):
    marker = '<textarea id="config-json" rows="20" readonly onclick="this.select()">'
    raw = html_body.split(marker)[1].split("</textarea>")[0]
    # Jinja HTML-escapes the JSON by default (no |safe) — browsers decode
    # entities back to literal characters for a textarea's content, so this
    # mirrors what actually ends up in the user's clipboard.
    return html.unescape(raw)


def test_view_and_download_render_identical_payload(app, client):
    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("mcprack.catalog.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.catalog.vaultwarden.lock"), \
         patch("mcprack.catalog.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret-value"}):
        view_resp = client.get("/view/copilot")

    with patch("mcprack.catalog.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.catalog.vaultwarden.lock"), \
         patch("mcprack.catalog.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret-value"}):
        download_resp = client.get("/download/copilot")

    assert json.loads(download_resp.data) == json.loads(_extract_textarea_text(view_resp.data.decode()))


def test_view_escapes_html_sensitive_characters_in_resolved_values(app):
    """A resolved credential value containing '</textarea>' or other HTML
    metacharacters must not break out of the textarea — Jinja's default
    autoescaping must stay in effect (no |safe) so this can't become a
    stored-XSS vector via an admin- or user-supplied Vaultwarden value."""
    from mcprack.config_formats import render_claude_config
    from flask import render_template_string

    malicious = [
        {
            "name": "evil",
            "transport": "http",
            "command": None,
            "args": [],
            "url": "http://x/mcp",
            "auth_header_name": "Authorization",
            "auth_env_key": "AUTH_TOKEN",
            "env": {"AUTH_TOKEN": "</textarea><script>alert(1)</script>"},
        }
    ]
    payload_json = json.dumps(render_claude_config(malicious), indent=2)

    with app.app_context(), app.test_request_context():
        rendered = render_template_string("{{ config_json }}", config_json=payload_json)

    assert "</textarea><script>" not in rendered
    assert "&lt;/textarea&gt;" in rendered


def test_server_icon_falls_back_to_default_when_no_appstream_icon(app, client):
    _login(client)
    server_id = _add_enabled_server(app, name="no-icon")

    with patch("mcprack.catalog.appstream_icons.resolve_server_icon_path", return_value=None), \
         patch("mcprack.catalog.appstream_icons.is_safe_icon_path", return_value=False):
        resp = client.get(f"/icon/server/{server_id}")

    assert resp.status_code == 302
    assert "/static/mcprack-app-icon.svg" in (resp.headers.get("Location") or "")


def test_server_icon_serves_appstream_file_when_available(app, client):
    _login(client)
    server_id = _add_enabled_server(app, name="with-icon")

    icon_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "mcprack", "static", "mcprack-app-icon.svg",
    )
    with patch("mcprack.catalog.appstream_icons.resolve_server_icon_path", return_value=icon_path), \
         patch("mcprack.catalog.appstream_icons.is_safe_icon_path", return_value=True):
        resp = client.get(f"/icon/server/{server_id}")

    assert resp.status_code == 200
    assert resp.mimetype in ("image/svg+xml", "image/png", "image/x-icon", "image/x-xpixmap")


def test_user_proxy_route_requires_valid_token_and_selection(app, client):
    user_id = _login(client)
    with app.app_context():
        stdio = McpServer(
            name="proxy-stdio",
            label="Proxy stdio",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add(stdio)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=stdio.id))
        db.session.commit()
        server_id = stdio.id

    with app.app_context():
        from mcprack.catalog import _make_proxy_token

        token = _make_proxy_token(user_id, server_id)

    with patch("mcprack.catalog.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.catalog.vaultwarden.lock"), \
         patch("mcprack.catalog.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "x"}), \
         patch("mcprack.catalog.user_proxy.ensure_user_server_proxy", return_value=35123), \
         patch("mcprack.catalog._forward_to_user_proxy", return_value=app.response_class("ok", status=200)):
        resp = client.post(f"/proxy/mcp/{token}/{server_id}")

    assert resp.status_code == 200


def test_user_proxy_route_rejects_invalid_token(app, client):
    user_id = _login(client)
    server_id = _add_selected_server(app, user_id)

    resp = client.post(f"/proxy/mcp/not-a-token/{server_id}")
    assert resp.status_code == 403


def test_user_proxy_route_returns_clean_jsonrpc_error_on_broken_upstream(app, client):
    """A permanently broken upstream (e.g. a stdio command that crashes on
    every invocation) must fail deterministically with a proper JSON-RPC
    error body, not a bare 502 or an unbounded hang."""
    from mcprack import user_proxy

    user_id = _login(client)
    with app.app_context():
        stdio = McpServer(
            name="broken-proxy-stdio", label="Broken", transport="stdio",
            command="/bin/broken", enabled=True,
        )
        db.session.add(stdio)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=stdio.id))
        db.session.commit()
        server_id = stdio.id

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    body = json.dumps({"jsonrpc": "2.0", "id": 42, "method": "initialize"})
    with patch(
        "mcprack.catalog.user_proxy.ensure_user_server_proxy",
        side_effect=user_proxy.UserProxyError("Upstream MCP server 'broken' failed its startup handshake"),
    ):
        resp = client.post(f"/proxy/mcp/{token}/{server_id}", data=body, content_type="application/json")

    assert resp.status_code == 502
    payload = json.loads(resp.data)
    assert payload["jsonrpc"] == "2.0"
    assert payload["id"] == 42
    assert "failed its startup handshake" in payload["error"]["message"]


def test_forward_to_user_proxy_returns_clean_jsonrpc_error_on_timeout(app, client):
    import socket as _socket

    from mcprack import catalog

    user_id = _login(client)
    with app.app_context():
        stdio = McpServer(
            name="slow-proxy-stdio", label="Slow", transport="stdio",
            command="/bin/slow", enabled=True,
        )
        db.session.add(stdio)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=stdio.id))
        db.session.commit()
        server_id = stdio.id

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    body = json.dumps({"jsonrpc": "2.0", "id": "abc", "method": "initialize"})
    with patch("mcprack.catalog.user_proxy.ensure_user_server_proxy", return_value=35123), \
         patch("mcprack.catalog.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn_cls.return_value.request.side_effect = _socket.timeout("timed out")
        resp = client.post(f"/proxy/mcp/{token}/{server_id}", data=body, content_type="application/json")

    assert resp.status_code == 502
    payload = json.loads(resp.data)
    assert payload["id"] == "abc"
    assert "did not respond within" in payload["error"]["message"]


def test_view_always_uses_user_proxy_urls_for_stdio_servers(app, client):
    """Users always connect remotely — a stdio server never gets embedded
    into the config as a raw local spawn command, regardless of the
    requesting IP. It always gets a per-user proxy URL instead, and its
    credentials are resolved lazily at proxy-connect time, not here."""
    user_id = _login(client)
    with app.app_context():
        user = db.session.get(User, user_id)
        stdio = McpServer(
            name="local-stdio",
            label="Local stdio",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add(stdio)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=stdio.id))
        db.session.commit()

    # No Vaultwarden patches needed: a stdio server with no declared secrets
    # never touches Vaultwarden at view/download time.
    resp = client.get("/view/copilot", environ_base={"REMOTE_ADDR": "127.0.0.1"})

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "/proxy/mcp/" in body


def test_override_page_handles_malformed_env_var_names_json(app, client):
    user_id = _login(client)

    with app.app_context():
        server = McpServer(
            name="broken-override",
            label="Broken Override",
            transport="stdio",
            command="/bin/true",
            enabled=True,
            allow_user_override=True,
        )
        # Regression coverage for legacy bad data seen in production.
        server.env_var_names_json = "None"
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    resp = client.get(f"/override/{server_id}")
    assert resp.status_code == 200
    assert b"Your credentials for Broken Override" in resp.data


def test_catalog_hides_servers_explicitly_denied_for_user(app, client):
    user_id = _login(client)

    with app.app_context():
        allowed = McpServer(
            name="allowed-srv",
            label="Allowed",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        denied = McpServer(
            name="denied-srv",
            label="Denied",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add_all([allowed, denied])
        db.session.commit()

        db.session.add_all(
            [
                UserServerPermission(user_id=user_id, server_id=allowed.id, is_allowed=True),
                UserServerPermission(user_id=user_id, server_id=denied.id, is_allowed=False),
            ]
        )
        db.session.commit()

    resp = client.get("/")
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "Allowed" in body
    assert "Denied" not in body


def test_download_excludes_explicitly_denied_selected_server(app, client):
    user_id = _login(client)
    with app.app_context():
        allowed = McpServer(
            name="allowed-dl",
            label="Allowed DL",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        denied = McpServer(
            name="denied-dl",
            label="Denied DL",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add_all([allowed, denied])
        db.session.commit()

        db.session.add_all(
            [
                UserServerSelection(user_id=user_id, server_id=allowed.id),
                UserServerSelection(user_id=user_id, server_id=denied.id),
                UserServerPermission(user_id=user_id, server_id=allowed.id, is_allowed=True),
                UserServerPermission(user_id=user_id, server_id=denied.id, is_allowed=False),
            ]
        )
        db.session.commit()

    with patch("mcprack.catalog.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.catalog.vaultwarden.lock"), \
         patch("mcprack.catalog.vaultwarden.resolve_env", return_value={}):
        resp = client.get("/download/copilot")

    payload = resp.data.decode()
    assert resp.status_code == 200
    assert "allowed-dl" in payload
    assert "denied-dl" not in payload


def test_override_forbidden_when_server_denied_for_user(app, client):
    user_id = _login(client)

    with app.app_context():
        denied = McpServer(
            name="denied-override",
            label="Denied Override",
            transport="stdio",
            command="/bin/true",
            enabled=True,
            allow_user_override=True,
        )
        db.session.add(denied)
        db.session.commit()
        db.session.add(
            UserServerPermission(user_id=user_id, server_id=denied.id, is_allowed=False)
        )
        db.session.commit()
        denied_id = denied.id

    resp = client.get(f"/override/{denied_id}")
    assert resp.status_code == 403
