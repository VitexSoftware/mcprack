import html
import json
import os
import re
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


def _add_selected_stdio_server(app, user_id, name="retry-stdio"):
    with app.app_context():
        stdio = McpServer(
            name=name,
            label=name,
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add(stdio)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=stdio.id))
        db.session.commit()
        return stdio.id


def test_index_renders_copyable_name_and_url_for_each_configured_server(app, client):
    """The catalog page must offer a name+URL pair (with copy buttons) per
    selected server - the friendlier way to add a server to Claude
    Desktop's "Add custom connector" dialog, which wants those two fields
    rather than a JSON config file. A server the user hasn't selected must
    not appear here."""
    user_id = _login(client)
    server_id = _add_selected_server(app, user_id)

    resp = client.get("/")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert 'data-copy-value="jenkins"' in body
    assert f"/proxy/mcp/" in body
    assert f"/{server_id}\"" in body
    assert "copy-connector.js" in body
    assert f"/icon/server/{server_id}" in body
    assert 'class="connector-icon"' in body


def test_index_omits_connector_section_when_nothing_selected(app, client):
    """The "Add as Individual Connectors" bulk section only lists selected
    servers, but copy-connector.js still loads - it also powers the
    per-server "Connector" popup on the "Available Servers" list below,
    which works even for servers the user hasn't selected yet."""
    _login(client)

    resp = client.get("/")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "connector-row" not in body
    assert "copy-connector.js" in body


def test_index_renders_per_server_connector_popup_button(app, client):
    """Every server in the "Available Servers" list gets its own
    "Connector" button carrying that server's name+URL, even when the
    server isn't selected yet - the popup lets a user grab a single
    server's connector details without first saving a selection."""
    user_id = _login(client)
    server_id = _add_enabled_server(app, name="standalone-tool")

    resp = client.get("/")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert 'data-connector-name="standalone-tool"' in body
    assert f"/proxy/mcp/" in body
    assert f"/{server_id}&#34;" in body or f'/{server_id}"' in body
    assert 'id="connector-popup"' in body


def test_view_renders_textarea_with_config_json(app, client):
    """Every server — including one with a real network `url` of its own,
    like Jenkins here — is rendered as a /proxy/mcp/ relay URL, never its
    raw backend address or an embedded credential. See
    test_view_always_uses_user_proxy_urls_for_stdio_servers for the stdio
    equivalent."""
    user_id = _login(client)
    _add_selected_server(app, user_id)

    # No Vaultwarden patches needed: config generation no longer resolves
    # credentials eagerly (see _build_client_config_json).
    resp = client.get("/view/claude")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "<textarea" in body
    assert "mcpServers" in body
    assert "jenkins" in body
    assert "/proxy/mcp/" in body
    assert "secret-value" not in body
    assert "Copy to clipboard" in body


def test_view_redirects_with_flash_when_nothing_selected(app, client):
    _login(client)

    resp = client.get("/view/claude", follow_redirects=True)
    assert resp.status_code == 200
    assert b"haven&#39;t selected any MCP servers" in resp.data


def test_view_survives_vaultwarden_outage(app, client):
    """Config generation never touches Vaultwarden at all any more (every
    server renders as a /proxy/mcp/ relay URL; credentials are resolved
    lazily when that URL is first connected to), so a Vaultwarden outage
    must not affect /view."""
    from mcprack import vaultwarden

    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("mcprack.catalog.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")):
        resp = client.get("/view/claude", follow_redirects=True)

    assert resp.status_code == 200
    assert b"/proxy/mcp/" in resp.data


def test_download_survives_vaultwarden_outage(app, client):
    """Same as test_view_survives_vaultwarden_outage but for /download."""
    from mcprack import vaultwarden

    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("mcprack.catalog.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")):
        resp = client.get("/download/claude", follow_redirects=True)

    assert resp.status_code == 200
    assert b"/proxy/mcp/" in resp.data


def test_proxy_connect_surfaces_vaultwarden_outage(app, client):
    """The Vaultwarden-outage error now surfaces at proxy-connect time
    instead of at config-generation time — this is the equivalent of the
    old test_view_survives_vaultwarden_outage / test_download_..., moved to
    where the failure actually happens now."""
    from mcprack import vaultwarden

    user_id = _login(client)
    server_id = _add_selected_server(app, user_id)

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    with patch("mcprack.catalog.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")):
        resp = client.post(f"/proxy/mcp/{token}/{server_id}")

    assert resp.status_code == 502
    payload = json.loads(resp.data)
    assert "Could not resolve credentials" in payload["error"]["message"]


def test_view_unknown_client_404s(app, client):
    _login(client)
    resp = client.get("/view/not-a-real-client")
    assert resp.status_code == 404


def _extract_textarea_text(html_body):
    match = re.search(
        r'<textarea id="config-json"[^>]*>(.*?)</textarea>', html_body, re.DOTALL
    )
    raw = match.group(1)
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


def test_user_proxy_route_relays_to_backend_url_for_network_server(app, client):
    """A server registered with a fixed network `url` (e.g. mcp_rack's
    shared fastmcp proxy, possibly on a different host than mcprack) is
    relayed to directly by user_proxy_mcp - no per-user process spawn."""
    from mcprack import catalog

    user_id = _login(client)
    with app.app_context():
        server = McpServer(
            name="mcp-rack-abraflexi",
            label="AbraFlexi via mcp_rack",
            transport="http",
            url="http://10.11.25.175:3108/mcp",
            enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=server.id))
        db.session.commit()
        server_id = server.id

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    with patch("mcprack.catalog.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.catalog.vaultwarden.lock"), \
         patch("mcprack.catalog.vaultwarden.resolve_env", return_value={}), \
         patch.object(catalog, "_forward_to_backend_url", return_value=app.response_class("ok", status=200)) as mock_forward:
        resp = client.post(f"/proxy/mcp/{token}/{server_id}")

    assert resp.status_code == 200
    assert mock_forward.call_count == 1
    called_url = mock_forward.call_args[0][0]
    assert called_url == "http://10.11.25.175:3108/mcp"


def test_user_proxy_route_sends_cors_headers_for_browser_based_mcp_clients(app, client):
    """Claude Desktop and claude.ai are browser/Electron-based MCP clients
    and enforce CORS. Without Access-Control-* headers on /proxy/mcp/, their
    preflight OPTIONS (or the browser's block of the real request after a
    failed preflight) fails before mcprack's response is ever read - even
    though the request itself succeeds fine over plain HTTP (e.g. curl,
    which doesn't enforce CORS). The endpoint is bearer-token authenticated
    via the signed URL token, not cookies, so it's safe to open up."""
    from mcprack import catalog

    user_id = _login(client)
    with app.app_context():
        server = McpServer(
            name="mcp-rack-abraflexi",
            label="AbraFlexi via mcp_rack",
            transport="http",
            url="http://10.11.25.175:3108/mcp",
            enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=server.id))
        db.session.commit()
        server_id = server.id

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    preflight = client.options(
        f"/proxy/mcp/{token}/{server_id}",
        headers={
            "Origin": "https://claude.ai",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,mcp-session-id",
        },
    )
    assert preflight.headers.get("Access-Control-Allow-Origin") == "*"
    assert "POST" in preflight.headers.get("Access-Control-Allow-Methods", "")
    assert "Mcp-Session-Id" in preflight.headers.get("Access-Control-Allow-Headers", "")

    with patch("mcprack.catalog.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.catalog.vaultwarden.lock"), \
         patch("mcprack.catalog.vaultwarden.resolve_env", return_value={}), \
         patch.object(catalog, "_forward_to_backend_url", return_value=app.response_class("ok", status=200)):
        resp = client.post(f"/proxy/mcp/{token}/{server_id}")

    assert resp.headers.get("Access-Control-Allow-Origin") == "*"
    assert resp.headers.get("Access-Control-Expose-Headers") == "Mcp-Session-Id"


def test_forward_to_backend_url_connects_to_remote_host(app):
    """_forward_to_backend_url must not assume the backend is on
    127.0.0.1 - mcp_rack proxies (and genuinely network-native MCP
    servers) are very often registered on a different host than mcprack
    itself."""
    from mcprack import catalog
    from mcprack.models import McpServer

    server = McpServer(
        name="remote-svc", label="Remote", transport="http",
        url="http://10.11.25.175:3108/mcp", enabled=True,
    )

    with app.test_request_context("/", method="POST", data=b"{}"), \
         patch("mcprack.catalog.http.client.HTTPConnection") as mock_conn_cls:
        mock_conn = mock_conn_cls.return_value
        mock_conn.getresponse.return_value.status = 200
        mock_conn.getresponse.return_value.read.return_value = b"ok"
        mock_conn.getresponse.return_value.getheaders.return_value = []

        catalog._forward_to_backend_url("http://10.11.25.175:3108/mcp", {}, server)

    mock_conn_cls.assert_called_once_with("10.11.25.175", 3108, timeout=catalog._PROXY_REQUEST_TIMEOUT)
    mock_conn.request.assert_called_once()
    assert mock_conn.request.call_args[0][1] == "/mcp"


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


def test_user_proxy_route_retries_relay_once_when_proxy_dies_mid_request(app, client):
    """The per-user proxy can die between ensure_user_server_proxy and the
    relay (a cross-worker race with the health re-probe / idle reaper, or
    a fastmcp crash) - the relay then fails with mcprack's own 502. The
    route re-ensures (respawning the proxy) and retries the relay once, so
    the client sees a 200 instead of a spurious 502."""
    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id)

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "initialize"})
    with patch("mcprack.catalog.user_proxy.ensure_user_server_proxy", return_value=35123) as mock_ensure, \
         patch(
             "mcprack.catalog._forward_to_user_proxy",
             side_effect=[
                 app.response_class("proxy gone", status=502),
                 app.response_class("ok", status=200),
             ],
         ) as mock_forward:
        resp = client.post(f"/proxy/mcp/{token}/{server_id}", data=body, content_type="application/json")

    assert resp.status_code == 200
    assert resp.data == b"ok"
    assert mock_ensure.call_count == 2
    assert mock_forward.call_count == 2


def test_user_proxy_route_returns_502_when_relay_retry_also_fails(app, client):
    """If the retried relay fails too, the client gets the 502 JSON-RPC
    error as before - the retry must not loop or hang."""
    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id)

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    body = json.dumps({"jsonrpc": "2.0", "id": 8, "method": "initialize"})
    with patch("mcprack.catalog.user_proxy.ensure_user_server_proxy", return_value=35123) as mock_ensure, \
         patch(
             "mcprack.catalog._forward_to_user_proxy",
             side_effect=[
                 app.response_class("gone", status=502),
                 app.response_class("still gone", status=502),
             ],
         ) as mock_forward:
        resp = client.post(f"/proxy/mcp/{token}/{server_id}", data=body, content_type="application/json")

    assert resp.status_code == 502
    assert mock_ensure.call_count == 2
    assert mock_forward.call_count == 2


def test_user_proxy_route_retry_surfaces_ensure_error(app, client):
    """When the retry's re-ensure cannot (re)start the proxy, the client
    gets the UserProxyError as a JSON-RPC 502 - same as a first-attempt
    failure."""
    from mcprack import user_proxy

    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id)

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "initialize"})
    with patch(
        "mcprack.catalog.user_proxy.ensure_user_server_proxy",
        side_effect=[35123, user_proxy.UserProxyError("handshake failed again")],
    ) as mock_ensure, \
         patch(
             "mcprack.catalog._forward_to_user_proxy",
             return_value=app.response_class("gone", status=502),
         ) as mock_forward:
        resp = client.post(f"/proxy/mcp/{token}/{server_id}", data=body, content_type="application/json")

    assert resp.status_code == 502
    payload = json.loads(resp.data)
    assert payload["id"] == 9
    assert "handshake failed again" in payload["error"]["message"]
    assert mock_ensure.call_count == 2
    assert mock_forward.call_count == 1


def test_user_proxy_route_does_not_retry_non_502_upstream_status(app, client):
    """Only mcprack's own relay-failure 502 triggers the retry; a genuine
    upstream status (e.g. a 500 from the proxy) is passed through
    untouched."""
    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id)

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    body = json.dumps({"jsonrpc": "2.0", "id": 10, "method": "initialize"})
    with patch("mcprack.catalog.user_proxy.ensure_user_server_proxy", return_value=35123) as mock_ensure, \
         patch(
             "mcprack.catalog._forward_to_user_proxy",
             return_value=app.response_class("upstream error", status=500),
         ) as mock_forward:
        resp = client.post(f"/proxy/mcp/{token}/{server_id}", data=body, content_type="application/json")

    assert resp.status_code == 500
    assert mock_ensure.call_count == 1
    assert mock_forward.call_count == 1


def test_proxy_route_holds_relay_guard_during_post_relay(app, client, monkeypatch, tmp_path):
    """POST relays run under the pair's shared relay guard, so a stop
    path (idle reaper, health re-probe, server deletion) cannot SIGTERM
    the per-user proxy while a request is in flight against it."""
    from mcprack import user_proxy

    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "user-proxies")

    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id)

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    guard_state = {}

    def fake_forward(port, server_name=None):
        try:
            with user_proxy._serialized(user_id, server_id, wait_seconds=0):
                guard_state["held"] = False
        except user_proxy.UserProxyError:
            guard_state["held"] = True
        return app.response_class("ok", status=200)

    body = json.dumps({"jsonrpc": "2.0", "id": 11, "method": "initialize"})
    with patch("mcprack.catalog.user_proxy.ensure_user_server_proxy", return_value=35123), \
         patch("mcprack.catalog._forward_to_user_proxy", side_effect=fake_forward):
        resp = client.post(f"/proxy/mcp/{token}/{server_id}", data=body, content_type="application/json")

    assert resp.status_code == 200
    assert guard_state["held"] is True


def test_proxy_route_get_relay_not_guarded(app, client, monkeypatch, tmp_path):
    """GET relays carry a long-lived SSE stream; guarding them would hold
    the pair lock for minutes and block reaping, so they stay unguarded."""
    from mcprack import user_proxy

    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "user-proxies")

    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id)

    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    guard_state = {}

    def fake_forward(port, server_name=None):
        try:
            with user_proxy._serialized(user_id, server_id, wait_seconds=0):
                guard_state["held"] = False
        except user_proxy.UserProxyError:
            guard_state["held"] = True
        return app.response_class("stream", status=200)

    with patch("mcprack.catalog.user_proxy.ensure_user_server_proxy", return_value=35123), \
         patch("mcprack.catalog._forward_to_user_proxy", side_effect=fake_forward):
        resp = client.get(f"/proxy/mcp/{token}/{server_id}")

    assert resp.status_code == 200
    assert guard_state["held"] is False


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
