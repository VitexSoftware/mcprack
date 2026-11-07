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
    # The relay URL carries a URLSafeTimedSerializer token, whose payload
    # embeds a one-second-granularity timestamp. These are two separate
    # requests, so without pinning the token the assertion fails whenever
    # they happen to straddle a second boundary.
    with patch("mcprack.catalog._make_proxy_token", return_value="fixed-token"):
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

    payload = json.loads(download_resp.data)
    assert payload == json.loads(_extract_textarea_text(view_resp.data.decode()))
    # guard the pin itself: if the relay URL ever stops carrying the token,
    # the comparison above would pass for the wrong reason
    assert "fixed-token" in json.dumps(payload)


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
    assert b"Configuration for Broken Override" in resp.data


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


# --- user configuration editor ----------------------------------------------

def _initial_rows(body):
    """The rows the override editor was re-rendered with. They travel as
    JSON in the container's data-initial attribute, so a substring check
    against the page body proves nothing."""
    import html as html_mod
    import json as json_mod
    import re as re_mod

    match = re_mod.search(r"data-initial='([^']*)'", body)
    assert match, "no data-initial attribute in the rendered page"
    return json_mod.loads(html_mod.unescape(match.group(1)))


def _add_overridable_server(app, user_id, name="override-me"):
    """A server the user has selected, carrying one admin plain value
    (REGION) and one admin-declared secret (API_TOKEN) - enough to cover
    inherit, override and forced-secret behaviour in one fixture."""
    with app.app_context():
        server = McpServer(
            name=name, label=name, transport="stdio", command="/bin/true",
            enabled=True, allow_user_override=True,
        )
        server.env_config = {"REGION": "eu"}
        server.env_var_names = ["API_TOKEN"]
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=server.id))
        db.session.commit()
        return server.id


def test_override_page_lists_admin_keys_as_inheritable_rows(app, client):
    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    resp = client.get(f"/override/{server_id}")

    assert resp.status_code == 200
    body = resp.data.decode()
    # The known-keys panel and the row editor both need the admin's keys.
    assert "REGION" in body and "API_TOKEN" in body
    assert "data-known-keys=" in body
    assert "override-editor.js" in body and "env-parse.js" in body


def test_override_save_keeps_the_other_admin_values_inherited(app, client):
    """Submitting one row must not wipe the admin defaults for the rest -
    an empty value on an admin-defined key means "keep inheriting"."""
    from mcprack import secret_store

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.post(f"/override/{server_id}", data={
            "action": "save", "env_editor": "1",
            "env_key__r1": "REGION", "env_value__r1": "us",
            "env_key__r2": "API_TOKEN", "env_value__r2": "", "env_sensitive__r2": "on",
        }, follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            non_secret, secret = secret_store.load_user_override(server, user)

    assert non_secret == {"REGION": "us"}
    assert secret == {}


def test_override_save_rejects_duplicate_keys_without_losing_input(app, client):
    """Row ids are opaque, so two rows can carry the same key; saving would
    silently keep whichever came last. The JS warns, but it can be bypassed."""
    from mcprack.models import UserServerOverride

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.post(f"/override/{server_id}", data={
            "action": "save", "env_editor": "1",
            "env_key__r1": "REGION", "env_value__r1": "us",
            "env_key__r2": "REGION", "env_value__r2": "cz",
        })

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Duplicate key" in body
    # the submitted values come back rather than a blank form; the rows are
    # re-rendered into the editor's data-initial JSON, not as value="..."
    rows = _initial_rows(body)
    assert [(r["key"], r["value"]) for r in rows] == [("REGION", "us"), ("REGION", "cz")]
    with app.app_context():
        assert UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first() is None


def test_override_save_still_accepts_the_raw_key_value_textarea(app, client):
    """The row editor is JavaScript; with it disabled the form submits only
    the textarea, and that path must keep working (and classify secrets the
    same way the server-side detection does)."""
    from mcprack import secret_store

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.post(f"/override/{server_id}", data={
            "action": "save",
            "env_text": "REGION=us\nAPI_TOKEN=abc123\n# comment\n",
        })
        assert resp.status_code == 302

        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            non_secret, secret = secret_store.load_user_override(server, user)

    assert non_secret == {"REGION": "us"}
    assert secret == {"API_TOKEN": "abc123"}


def test_override_row_editor_cannot_store_an_admin_secret_in_plaintext(app, client):
    """An unchecked sensitive box submits nothing at all, so it cannot be
    told apart from a client that never sent the field. Trusting it alone
    let an admin-declared secret land in plain env_config_json."""
    from mcprack import secret_store
    from mcprack.models import UserServerOverride

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.post(f"/override/{server_id}", data={
            "action": "save", "env_editor": "1",
            "env_key__r1": "API_TOKEN", "env_value__r1": "abc123",
        })
        assert resp.status_code == 302

        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            non_secret, secret = secret_store.load_user_override(server, user)
            row = UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first()

    assert non_secret == {}
    assert secret == {"API_TOKEN": "abc123"}
    assert row.env_config == {}


def test_override_row_editor_forces_a_sensitive_looking_key_to_the_secret_store(app, client):
    """The same rule for a key the admin never declared: the name heuristic
    classifies it identically on every write path, so the row editor must
    not be the one place a credential-looking name stays in plaintext."""
    from mcprack import secret_store
    from mcprack.models import UserServerOverride

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.post(f"/override/{server_id}", data={
            "action": "save", "env_editor": "1",
            "env_key__r1": "SOME_TOKEN", "env_value__r1": "zzz",
            "env_key__r2": "REGION", "env_value__r2": "us",
        })
        assert resp.status_code == 302

        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            non_secret, secret = secret_store.load_user_override(server, user)
            row = UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first()

    assert non_secret == {"REGION": "us"}
    assert secret == {"SOME_TOKEN": "zzz"}
    assert row.env_config == {"REGION": "us"}


def test_override_save_with_no_rows_clears_the_override(app, client):
    """Removing every row with the ✕ button and saving must actually clear
    the override. It used to look identical to a no-JS submit, so the server
    fell back to the pre-filled textarea and saved the old values back."""
    from mcprack import secret_store
    from mcprack.models import UserServerOverride

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            secret_store.save_user_override(server, user, {"CUSTOM": "x"}, {})
            db.session.commit()

        resp = client.post(f"/override/{server_id}", data={
            "action": "save", "env_editor": "1",
            "env_text": "CUSTOM=x\n",
        })
        assert resp.status_code == 302

        with app.app_context():
            assert UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first() is None


def test_override_save_ignores_the_textarea_when_the_row_editor_ran(app, client):
    """The rows win over a stale textarea the browser submitted alongside
    them - otherwise the two inputs silently disagree."""
    from mcprack import secret_store

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.post(f"/override/{server_id}", data={
            "action": "save", "env_editor": "1",
            "env_key__r1": "REGION", "env_value__r1": "us",
            "env_text": "REGION=stale\nGHOST=1\n",
        })
        assert resp.status_code == 302

        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            non_secret, secret = secret_store.load_user_override(server, user)

    assert non_secret == {"REGION": "us"}
    assert secret == {}


def test_no_js_textarea_save_keeps_a_user_marked_secret_secret(app, client):
    """The textarea flattens both halves into KEY=value lines. Re-splitting
    by name alone would move a key the user marked sensitive - whose name
    matches nothing - into plain env_config_json."""
    from mcprack import secret_store
    from mcprack.models import UserServerOverride

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            secret_store.save_user_override(server, user, {}, {"JENKINS_PAT": "pat-123"})
            db.session.commit()

        # exactly what the no-JS form posts back: the rendered textarea
        # plus the hidden list of keys the page was rendered with
        resp = client.post(f"/override/{server_id}", data={
            "action": "save",
            "env_text": "JENKINS_PAT=pat-123\nREGION=us\n",
            "env_secret_keys": "JENKINS_PAT",
        })
        assert resp.status_code == 302

        with app.app_context():
            row = UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first()

    assert row.env_config == {"REGION": "us"}


def test_override_page_renders_the_secret_key_list_for_the_no_js_fallback(app, client):
    """The hidden field is what makes the textarea round-trip safe, so a
    template refactor dropping it must fail here rather than silently
    demote credentials."""
    from mcprack import secret_store

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            secret_store.save_user_override(server, user, {}, {"JENKINS_PAT": "pat-123"})
            db.session.commit()

        resp = client.get(f"/override/{server_id}")

    body = resp.data.decode()
    assert 'name="env_secret_keys"' in body
    assert "JENKINS_PAT" in body
    # the raw textarea must be reachable by assistive tech
    assert 'id="env_text"' in body and "aria-label=" in body


def test_override_page_does_not_prerender_the_js_editor_marker(app, client):
    """The marker only means anything when JavaScript put it there. Render
    it server-side and every no-JS save silently stops writing anything."""
    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    resp = client.get(f"/override/{server_id}")

    assert 'name="env_editor"' not in resp.data.decode()


def test_override_reset_removes_the_whole_override(app, client):
    from mcprack import secret_store
    from mcprack.models import UserServerOverride

    user_id = _login(client)
    server_id = _add_overridable_server(app, user_id)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            secret_store.save_user_override(server, user, {"REGION": "us"}, {})
            db.session.commit()

        resp = client.post(f"/override/{server_id}", data={"action": "reset"})
        assert resp.status_code == 302

        with app.app_context():
            assert UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first() is None


def test_proxy_error_to_the_client_masks_configured_values(app, client):
    """A UserProxyError carries the tail of the spawned server's own log. An
    MCP server that logs its connection string would otherwise hand the
    credential mcprack injected straight back to the end user's client."""
    from mcprack import catalog, user_proxy

    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id, name="leaky")
    with app.app_context():
        server = db.session.get(McpServer, server_id)
        server.env_config = {"DB_URL": "postgres://user:sup3rs3cret@db/x"}
        db.session.commit()
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    boom = user_proxy.UserProxyError(
        "Upstream MCP server 'leaky' failed its startup handshake\n"
        "Last log lines:\nauth failed for postgres://user:sup3rs3cret@db/x"
    )
    with patch.object(catalog.user_proxy, "ensure_user_server_proxy", side_effect=boom):
        resp = client.post(f"/proxy/mcp/{token}/{server_id}")

    body = resp.data.decode()
    assert "sup3rs3cret" not in body
    assert "***" in body
    assert "failed its startup handshake" in body


def test_proxy_error_in_the_log_masks_configured_values(app, client, caplog):
    """Masking only the client answer still leaves the credential in the
    persisted log, which is the copy that outlives the request."""
    import logging

    from mcprack import catalog, user_proxy

    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id, name="leaky-log")
    with app.app_context():
        server = db.session.get(McpServer, server_id)
        server.env_config = {"DB_URL": "postgres://user:sup3rs3cret@db/x"}
        db.session.commit()
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    boom = user_proxy.UserProxyError(
        "Upstream MCP server 'leaky-log' failed its startup handshake\n"
        "Last log lines:\nauth failed for postgres://user:sup3rs3cret@db/x"
    )
    with caplog.at_level(logging.ERROR, logger="mcprack.catalog"):
        with patch.object(catalog.user_proxy, "ensure_user_server_proxy", side_effect=boom):
            client.post(f"/proxy/mcp/{token}/{server_id}")

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "Proxy start failed" in logged
    assert "sup3rs3cret" not in logged
    assert "***" in logged


def test_proxy_error_to_the_client_is_length_bounded(app, client):
    from mcprack import catalog, user_proxy

    user_id = _login(client)
    server_id = _add_selected_stdio_server(app, user_id, name="chatty")
    with app.app_context():
        from mcprack.catalog import _make_proxy_token
        token = _make_proxy_token(user_id, server_id)

    boom = user_proxy.UserProxyError("x" * 5000)
    with patch.object(catalog.user_proxy, "ensure_user_server_proxy", side_effect=boom):
        resp = client.post(f"/proxy/mcp/{token}/{server_id}")

    payload = json.loads(resp.data.decode())
    assert len(payload["error"]["message"]) < 700
    assert "truncated" in payload["error"]["message"]
