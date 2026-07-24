import html
import json
from unittest.mock import patch

from extensions import db
from models import McpServer, User, UserServerSelection


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


def test_view_renders_textarea_with_config_json(app, client):
    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("catalog.vaultwarden.unlock", return_value="sess"), \
         patch("catalog.vaultwarden.lock"), \
         patch("catalog.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret-value"}):
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
    import vaultwarden

    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("catalog.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")):
        resp = client.get("/view/claude", follow_redirects=True)

    assert resp.status_code == 200
    assert b"Could not reach Vaultwarden" in resp.data


def test_download_survives_vaultwarden_outage(app, client):
    import vaultwarden

    user_id = _login(client)
    _add_selected_server(app, user_id)

    with patch("catalog.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")):
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

    with patch("catalog.vaultwarden.unlock", return_value="sess"), \
         patch("catalog.vaultwarden.lock"), \
         patch("catalog.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret-value"}):
        view_resp = client.get("/view/copilot")

    with patch("catalog.vaultwarden.unlock", return_value="sess"), \
         patch("catalog.vaultwarden.lock"), \
         patch("catalog.vaultwarden.resolve_env", return_value={"AUTH_TOKEN": "secret-value"}):
        download_resp = client.get("/download/copilot")

    assert json.loads(download_resp.data) == json.loads(_extract_textarea_text(view_resp.data.decode()))


def test_view_escapes_html_sensitive_characters_in_resolved_values(app):
    """A resolved credential value containing '</textarea>' or other HTML
    metacharacters must not break out of the textarea — Jinja's default
    autoescaping must stay in effect (no |safe) so this can't become a
    stored-XSS vector via an admin- or user-supplied Vaultwarden value."""
    from config_formats import render_claude_config
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
