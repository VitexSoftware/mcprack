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


def test_autodetect_creates_new_servers(app, client):
    _login_admin(client)

    detected = [
        {
            "name": "zabbix-mcp-server",
            "label": "Zabbix MCP Server",
            "transport": "http",
            "url": "http://mcphost:3100/mcp/",
            "category": "mcp-rack",
        },
        {
            "name": "warden-mcp",
            "label": "Vaultwarden MCP",
            "transport": "stdio",
            "command": "/usr/bin/warden-mcp",
            "args": ["--stdio"],
            "category": "local-stdio",
        },
    ]

    with patch("admin.detection.detect_local_mcp_servers", return_value=detected):
        resp = client.post("/admin/servers/autodetect", follow_redirects=True)

    assert resp.status_code == 200
    assert b"Autodetected and registered 2 server" in resp.data

    with app.app_context():
        servers = {s.name: s for s in McpServer.query.all()}
        assert servers["zabbix-mcp-server"].transport == "http"
        assert servers["zabbix-mcp-server"].url == "http://mcphost:3100/mcp/"
        assert servers["warden-mcp"].transport == "stdio"
        assert servers["warden-mcp"].command == "/usr/bin/warden-mcp"
        assert servers["warden-mcp"].args == ["--stdio"]
        assert servers["warden-mcp"].enabled is True


def test_autodetect_skips_existing_servers(app, client):
    _login_admin(client)

    with app.app_context():
        existing = McpServer(name="warden-mcp", label="Already here", transport="stdio", command="/usr/bin/warden-mcp")
        existing.args = ["--stdio"]
        db.session.add(existing)
        db.session.commit()

    detected = [
        {
            "name": "warden-mcp",
            "label": "Vaultwarden MCP",
            "transport": "stdio",
            "command": "/usr/bin/warden-mcp",
            "args": ["--stdio"],
            "category": "local-stdio",
        }
    ]

    with patch("admin.detection.detect_local_mcp_servers", return_value=detected):
        resp = client.post("/admin/servers/autodetect", follow_redirects=True)

    assert b"No new MCP servers detected" in resp.data
    with app.app_context():
        assert McpServer.query.filter_by(name="warden-mcp").count() == 1
