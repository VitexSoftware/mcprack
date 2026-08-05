from unittest.mock import patch

from mcprack import secret_store
from mcprack.extensions import db
from mcprack.models import McpServer, User


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def test_migrate_to_vaultwarden_moves_local_secrets_and_flashes_summary(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="jenkins", label="Jenkins", transport="http",
            url="https://jenkins.example.test/mcp", auth_header_name="Authorization",
            auth_env_key="AUTH_TOKEN", enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
            secret_store.save_server_secrets(server, {"AUTH_TOKEN": "topsecret"})
        db.session.commit()

    with patch("mcprack.admin.secret_store.is_vaultwarden_configured", return_value=True), \
         patch("mcprack.admin.secret_store.vaultwarden.session"), \
         patch("mcprack.admin.secret_store.vaultwarden.set_notes") as mock_set_notes:
        resp = client.post("/admin/vaultwarden/migrate-to-vaultwarden", follow_redirects=True)

    assert resp.status_code == 200
    mock_set_notes.assert_called_once()
    body = resp.data.decode()
    assert "Moved to Vaultwarden 1 item(s)" in body

    with app.app_context():
        refreshed = McpServer.query.filter_by(name="jenkins").first()
        assert refreshed.env_secrets_encrypted is None


def test_migrate_to_vaultwarden_refuses_when_not_configured(app, client):
    _login_admin(client)

    with patch("mcprack.admin.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.post("/admin/vaultwarden/migrate-to-vaultwarden", follow_redirects=True)

    assert resp.status_code == 200
    assert b"nothing to migrate to" in resp.data


def test_snapshot_to_local_copies_without_clearing_vaultwarden(app, client):
    _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="jenkins", label="Jenkins", transport="http",
            url="https://jenkins.example.test/mcp", auth_header_name="Authorization",
            auth_env_key="AUTH_TOKEN", enabled=True,
        )
        server.env_var_names = ["AUTH_TOKEN"]
        db.session.add(server)
        db.session.commit()

    with patch("mcprack.admin.secret_store.is_vaultwarden_configured", return_value=True), \
         patch("mcprack.admin.secret_store.vaultwarden.session"), \
         patch("mcprack.admin.secret_store.vaultwarden.set_notes") as mock_set_notes, \
         patch("mcprack.admin.secret_store.vaultwarden.get_notes", return_value={"AUTH_TOKEN": "topsecret"}):
        resp = client.post("/admin/vaultwarden/snapshot-to-local", follow_redirects=True)

    assert resp.status_code == 200
    mock_set_notes.assert_not_called()
    body = resp.data.decode()
    assert "Copied to local storage 1 item(s)" in body

    with app.app_context():
        refreshed = McpServer.query.filter_by(name="jenkins").first()
        assert refreshed.env_secrets_encrypted is not None
