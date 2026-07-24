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
