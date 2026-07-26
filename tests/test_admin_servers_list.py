from unittest.mock import patch

from extensions import db
from models import McpServer, User


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

    with patch("admin.vaultwarden.unlock", return_value="sess"), \
         patch("admin.vaultwarden.lock"), \
         patch("admin.vaultwarden.get_notes", return_value={}), \
         patch("admin.health.check_reachable", side_effect=lambda s: s.name == "healthy-stdio"):
        resp = client.get("/admin/servers")

    body = resp.data.decode()
    assert "missing: AUTH_TOKEN" in body
    assert "unreachable" in body
    assert "ok" in body


def test_servers_list_survives_vaultwarden_outage(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True)
        db.session.add(server)
        db.session.commit()

    import vaultwarden

    with patch("admin.vaultwarden.unlock", side_effect=vaultwarden.VaultwardenError("down")), \
         patch("admin.health.check_reachable", return_value=True):
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

    with patch("admin.vaultwarden.unlock", return_value="sess"), \
         patch("admin.vaultwarden.lock"), \
         patch("admin.vaultwarden.get_notes", return_value={}), \
         patch("admin.appstream_icons.resolve_server_icon_path", return_value="/usr/share/icons/hicolor/scalable/apps/mastodon-mcp-server.svg"), \
         patch("admin.appstream_icons.is_safe_icon_path", return_value=True):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Detected from AppStream metadata" in body
    assert f"/icon/server/{server_id}" in body


def test_server_create_splits_sensitive_and_non_sensitive_rows(app, client):
    _login_admin(client)

    with patch("admin.vaultwarden.unlock", return_value="sess"), \
         patch("admin.vaultwarden.lock"), \
         patch("admin.vaultwarden.set_notes") as mock_set_notes:
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

    with patch("admin.vaultwarden.unlock", return_value="sess"), \
         patch("admin.vaultwarden.lock"), \
         patch("admin.vaultwarden.set_notes") as mock_set_notes:
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

    with patch("admin.vaultwarden.unlock") as mock_unlock:
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
