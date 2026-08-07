import html
import json
import re
from unittest.mock import patch

from mcprack.extensions import db
from mcprack.models import McpServer, User


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def test_servers_list_flags_missing_credentials_and_unreachable(app, client):
    _login_admin(client)

    with app.app_context():
        broken = McpServer(
            name="broken-http", label="Broken HTTP", transport="http",
            url="http://example.invalid:9999/mcp", auth_header_name="Authorization",
            auth_env_key="AUTH_TOKEN", enabled=True,
        )
        broken.env_var_names = ["AUTH_TOKEN"]
        healthy = McpServer(
            name="healthy-stdio", label="Healthy stdio", transport="stdio",
            command="/bin/true", enabled=True,
        )
        db.session.add_all([broken, healthy])
        db.session.commit()

    with patch("mcprack.admin.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.admin.vaultwarden.lock"), \
         patch("mcprack.admin.vaultwarden.get_notes", return_value={}), \
         patch("mcprack.admin.health.check_reachable", side_effect=lambda s: s.name == "healthy-stdio"):
        resp = client.get("/admin/servers")

    body = resp.data.decode()
    assert "missing: AUTH_TOKEN" in body
    assert "unreachable" in body
    assert "ok" in body


def test_servers_list_flags_missing_required_default(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="needs-config", label="Needs Config", transport="stdio",
            command="/bin/true", enabled=True,
        )
        server.required_env_keys = ["API_KEY"]
        complete = McpServer(
            name="all-set", label="All Set", transport="stdio",
            command="/bin/true", enabled=True,
        )
        complete.required_env_keys = ["ALREADY_SET"]
        complete.env_config = {"ALREADY_SET": "value"}
        db.session.add_all([server, complete])
        db.session.commit()

    with patch("mcprack.admin.health.check_reachable", return_value=True):
        resp = client.get("/admin/servers")

    body = resp.data.decode()
    assert "1 required value(s) missing" in body


def test_servers_list_survives_vaultwarden_outage(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True)
        db.session.add(server)
        db.session.commit()

    from mcprack import vaultwarden

    with patch("mcprack.admin.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")), \
         patch("mcprack.admin.health.check_reachable", return_value=True):
        resp = client.get("/admin/servers")

    assert resp.status_code == 200
    assert b"missing:" not in resp.data


def test_server_edit_shows_icon_when_appstream_icon_found(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(name="mastodon", label="Mastodon", transport="stdio", command="/bin/true", enabled=True)
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    with patch("mcprack.admin.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.admin.vaultwarden.lock"), \
         patch("mcprack.admin.vaultwarden.get_notes", return_value={}), \
         patch("mcprack.admin.appstream_icons.resolve_server_icon_path", return_value="/usr/share/icons/hicolor/scalable/apps/mastodon-mcp-server.svg"), \
         patch("mcprack.admin.appstream_icons.is_safe_icon_path", return_value=True):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Detected from AppStream metadata" in body
    assert f"/icon/server/{server_id}" in body


def test_server_create_splits_sensitive_and_non_sensitive_rows(app, client):
    _login_admin(client)

    with patch("mcprack.admin.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.admin.vaultwarden.lock"), \
         patch("mcprack.admin.vaultwarden.set_notes") as mock_set_notes:
        resp = client.post(
            "/admin/servers/new",
            data={
                "name": "mastodon",
                "label": "Mastodon",
                "transport": "stdio",
                "command": "/usr/bin/mastodon-mcp",
                "args": "",
                "env_key__1": "MASTODON_INSTANCE",
                "env_value__1": "https://fosstodon.org",
                # not sensitive: no env_sensitive__1 field submitted
                "env_key__2": "MASTODON_ACCESS_TOKEN",
                "env_value__2": "topsecret",
                "env_sensitive__2": "on",
                "enabled": "on",
            },
        )

    assert resp.status_code == 302
    with app.app_context():
        server = McpServer.query.filter_by(name="mastodon").first()
        assert server is not None
        assert server.env_config == {"MASTODON_INSTANCE": "https://fosstodon.org"}
        assert server.env_var_names == ["MASTODON_ACCESS_TOKEN"]

    mock_set_notes.assert_called_once()
    saved_values = mock_set_notes.call_args[0][2]
    assert saved_values == {"MASTODON_ACCESS_TOKEN": "topsecret"}


def test_server_create_forces_auth_env_key_sensitive_even_if_unchecked(app, client):
    _login_admin(client)

    with patch("mcprack.admin.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.admin.vaultwarden.lock"), \
         patch("mcprack.admin.vaultwarden.set_notes") as mock_set_notes:
        resp = client.post(
            "/admin/servers/new",
            data={
                "name": "jenkins",
                "label": "Jenkins",
                "transport": "http",
                "url": "https://jenkins.example.test/mcp",
                "auth_header_name": "Authorization",
                "auth_env_key": "AUTH_TOKEN",
                "env_key__1": "AUTH_TOKEN",
                "env_value__1": "topsecret",
                # deliberately no env_sensitive__1 — auth_env_key forces it anyway
                "enabled": "on",
            },
        )

    assert resp.status_code == 302
    with app.app_context():
        server = McpServer.query.filter_by(name="jenkins").first()
        assert server.env_config == {}
        assert server.env_var_names == ["AUTH_TOKEN"]

    saved_values = mock_set_notes.call_args[0][2]
    assert saved_values == {"AUTH_TOKEN": "topsecret"}


def test_server_without_secrets_skips_vaultwarden_on_create(app, client):
    _login_admin(client)

    with patch("mcprack.admin.vaultwarden.unlock") as mock_unlock:
        resp = client.post(
            "/admin/servers/new",
            data={
                "name": "filesystem",
                "label": "Filesystem",
                "transport": "stdio",
                "command": "/bin/true",
                "env_key__1": "LOG_LEVEL",
                "env_value__1": "debug",
                "enabled": "on",
            },
        )

    assert resp.status_code == 302
    mock_unlock.assert_not_called()
    with app.app_context():
        server = McpServer.query.filter_by(name="filesystem").first()
        assert server.env_config == {"LOG_LEVEL": "debug"}
        assert server.env_var_names == []


def test_server_test_stdio_reports_broken_command(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="broken-mcp", label="Broken", transport="stdio",
            command="python3", enabled=True,
        )
        server.args = ["-c", "import nonexistent_module_xyz"]
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    resp = client.post(f"/admin/servers/{server_id}/test", follow_redirects=True)
    assert resp.status_code == 200
    assert b"failed to start" in resp.data


def test_server_test_stdio_reports_healthy_command(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="healthy-mcp", label="Healthy", transport="stdio",
            command="python3", enabled=True,
        )
        server.args = ["-c", "import time; time.sleep(30)"]
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    resp = client.post(f"/admin/servers/{server_id}/test", follow_redirects=True)
    assert resp.status_code == 200
    assert b"started successfully" in resp.data


def test_server_test_stdio_rejects_network_servers(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="http-svc", label="HTTP", transport="http",
            url="https://example.test/mcp", enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    resp = client.post(f"/admin/servers/{server_id}/test", follow_redirects=True)
    assert resp.status_code == 200
    assert b"nothing to test here" in resp.data


def test_server_edit_prefills_detected_but_unconfigured_rows(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="foo", label="Foo", transport="stdio", command="/bin/true", enabled=True,
        )
        server.detected_env_vars = [
            {"name": "API_KEY", "required": True, "secret": True, "description": None, "source": "registry"},
            {"name": "LOG_LEVEL", "required": False, "secret": False, "description": None, "source": "source-scan"},
        ]
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    with patch("mcprack.admin.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.admin.vaultwarden.lock"), \
         patch("mcprack.admin.vaultwarden.get_notes", return_value={}):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    body = resp.data.decode()
    match = re.search(r'id="env-rows"[^>]*data-initial=\'([^\']*)\'', body)
    assert match, body
    rows = json.loads(html.unescape(match.group(1)))
    by_key = {row["key"]: row for row in rows}

    # required=True is only pre-checked for the registry-sourced suggestion
    assert by_key["API_KEY"] == {"key": "API_KEY", "value": "", "sensitive": True, "required": True}
    assert by_key["LOG_LEVEL"] == {"key": "LOG_LEVEL", "value": "", "sensitive": False, "required": False}


def test_server_edit_excludes_already_configured_detected_suggestion(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="foo", label="Foo", transport="stdio", command="/bin/true", enabled=True,
        )
        server.env_config = {"ALREADY_SET": "value"}
        server.detected_env_vars = [
            {"name": "ALREADY_SET", "required": False, "secret": False, "description": None, "source": "source-scan"},
        ]
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    with patch("mcprack.admin.vaultwarden.unlock", return_value="sess"), \
         patch("mcprack.admin.vaultwarden.lock"), \
         patch("mcprack.admin.vaultwarden.get_notes", return_value={}):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    body = resp.data.decode()
    # Appears once (the real configured row), not duplicated as a suggestion.
    assert body.count("ALREADY_SET") == 1


def test_server_edit_persists_manually_checked_required_flag(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="foo", label="Foo", transport="stdio", command="/bin/true", enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    resp = client.post(
        f"/admin/servers/{server_id}/edit",
        data={
            "transport": "stdio",
            "command": "/bin/true",
            "args": "",
            "env_key__1": "SOME_VAR",
            "env_value__1": "x",
            "env_required__1": "on",
            "enabled": "on",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context():
        server = db.session.get(McpServer, server_id)
        assert server.required_env_keys == ["SOME_VAR"]
