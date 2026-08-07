from unittest.mock import MagicMock, patch

from mcprack.extensions import db
from mcprack.models import McpServer, User


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def test_install_wizard_requires_admin(client):
    resp = client.get("/admin/install", follow_redirects=True)
    assert resp.status_code in (200, 302, 401, 403)
    with client.application.app_context():
        assert McpServer.query.count() == 0


def test_install_pip_creates_queued_server_and_starts_install(app, client):
    _login_admin(client)

    with patch("mcprack.installer.start_pip_install", return_value="/var/lib/mcprack/installs/foo/venv") as mock_start:
        resp = client.post(
            "/admin/install/pip",
            data={
                "name": "foo",
                "label": "Foo MCP",
                "category": "",
                "package_spec": "foo-mcp-server==1.0",
                "expected_binary": "foo-mcp",
            },
            follow_redirects=True,
        )

    assert resp.status_code == 200
    mock_start.assert_called_once_with("foo", "foo-mcp-server==1.0", "foo-mcp")

    with app.app_context():
        server = McpServer.query.filter_by(name="foo").first()
        assert server is not None
        assert server.install_method == "pip"
        assert server.install_status == "queued"
        assert server.package_spec == "foo-mcp-server==1.0"
        assert server.expected_binary == "foo-mcp"


def test_install_pip_rejects_duplicate_name(app, client):
    _login_admin(client)
    with app.app_context():
        db.session.add(McpServer(name="foo", label="Foo", transport="stdio", command="/bin/foo"))
        db.session.commit()

    resp = client.post(
        "/admin/install/pip",
        data={"name": "foo", "package_spec": "foo-mcp==1.0", "expected_binary": "foo-mcp"},
        follow_redirects=True,
    )
    assert b"already registered" in resp.data


def test_install_docker_blocked_when_docker_not_available(app, client):
    _login_admin(client)

    with patch("mcprack.installer.docker_available", return_value=False):
        resp = client.post(
            "/admin/install/docker",
            data={"name": "foo", "image_ref": "ghcr.io/org/foo:latest"},
            follow_redirects=True,
        )

    assert b"docker" in resp.data.lower()
    with app.app_context():
        assert McpServer.query.filter_by(name="foo").count() == 0


def test_install_docker_registers_server_with_run_args(app, client):
    _login_admin(client)

    with patch("mcprack.installer.docker_available", return_value=True), \
         patch("mcprack.installer.start_docker_pull") as mock_pull:
        resp = client.post(
            "/admin/install/docker",
            data={"name": "foo", "image_ref": "ghcr.io/org/foo:latest"},
            follow_redirects=True,
        )

    assert resp.status_code == 200
    mock_pull.assert_called_once_with("foo", "ghcr.io/org/foo:latest")

    with app.app_context():
        server = McpServer.query.filter_by(name="foo").first()
        assert server.command == "docker"
        assert server.args == ["run", "--rm", "-i", "ghcr.io/org/foo:latest"]
        assert server.install_method == "docker"


def test_install_status_finalizes_success_and_sets_command(app, client):
    _login_admin(client)
    with app.app_context():
        server = McpServer(
            name="foo", label="Foo", transport="stdio",
            install_method="pip", install_status="queued",
            install_path="/tmp/does-not-matter", expected_binary="foo-mcp",
            package_spec="foo-mcp==1.0",
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    with patch("mcprack.installer.get_install_status", return_value={"status": "success", "log_tail": "", "error": None}), \
         patch("mcprack.installer.verify_pip_binary", return_value="/tmp/does-not-matter/bin/foo-mcp"), \
         patch("mcprack.installer.resolve_installed_version", return_value="1.0"):
        resp = client.get(f"/admin/install/{server_id}/status")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"

    with app.app_context():
        server = db.session.get(McpServer, server_id)
        assert server.install_status == "success"
        assert server.command == "/tmp/does-not-matter/bin/foo-mcp"
        assert server.installed_version == "1.0"


def test_install_status_runs_env_detection_once_on_success(app, client):
    _login_admin(client)
    with app.app_context():
        server = McpServer(
            name="foo", label="Foo", transport="stdio",
            install_method="pip", install_status="queued",
            install_path="/tmp/does-not-matter", expected_binary="foo-mcp",
            package_spec="foo-mcp==1.0",
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    detected = [{"name": "API_KEY", "required": True, "secret": True, "description": None, "source": "registry"}]
    with patch("mcprack.installer.get_install_status", return_value={"status": "success", "log_tail": "", "error": None}), \
         patch("mcprack.installer.verify_pip_binary", return_value="/tmp/does-not-matter/bin/foo-mcp"), \
         patch("mcprack.installer.resolve_installed_version", return_value="1.0"), \
         patch("mcprack.admin.env_detection.detect_env_vars", return_value=detected) as mock_detect:
        resp1 = client.get(f"/admin/install/{server_id}/status")
        resp2 = client.get(f"/admin/install/{server_id}/status")

    assert resp1.status_code == 200 and resp2.status_code == 200
    mock_detect.assert_called_once()

    with app.app_context():
        server = db.session.get(McpServer, server_id)
        assert server.detected_env_vars == detected


def test_install_status_finalizes_failed_when_binary_missing(app, client):
    _login_admin(client)
    with app.app_context():
        server = McpServer(
            name="foo", label="Foo", transport="stdio",
            install_method="pip", install_status="queued",
            install_path="/tmp/does-not-matter", expected_binary="foo-mcp",
            package_spec="foo-mcp==1.0",
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    with patch("mcprack.installer.get_install_status", return_value={"status": "success", "log_tail": "", "error": None}), \
         patch("mcprack.installer.verify_pip_binary", return_value=None):
        resp = client.get(f"/admin/install/{server_id}/status")

    data = resp.get_json()
    assert data["status"] == "failed"
    assert "not found" in data["error"]


def test_install_uninstall_stops_proxies_and_removes_server(app, client):
    _login_admin(client)
    with app.app_context():
        server = McpServer(
            name="foo", label="Foo", transport="stdio", command="/tmp/foo/bin/foo-mcp",
            install_method="pip", install_status="success", install_path="/tmp/foo",
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    with patch("mcprack.installer.uninstall") as mock_uninstall, \
         patch("mcprack.user_proxy.stop_user_server_proxy") as mock_stop:
        resp = client.post(f"/admin/install/{server_id}/uninstall", follow_redirects=True)

    assert resp.status_code == 200
    mock_uninstall.assert_called_once()
    with app.app_context():
        assert McpServer.query.filter_by(name="foo").count() == 0
