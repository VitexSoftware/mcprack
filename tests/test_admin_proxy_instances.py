from unittest.mock import patch

from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def test_proxy_instances_page_renders_rows(app, client):
    _login_admin(client)

    with app.app_context():
        user = User(username="alice", auth_type="local", is_admin=False)
        user.set_password("pw")
        server = McpServer(name="mastodon", label="Mastodon", transport="stdio", command="/bin/true", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()

        rows = [
            {
                "user_id": user.id,
                "server_id": server.id,
                "pid": 12345,
                "running": True,
                "port": 35123,
                "last_used": 0.0,
                "idle_seconds": 12,
                "log_path": "/var/lib/mcprack/user-proxies/u1-s1.log",
            }
        ]

    with patch("mcprack.admin.user_proxy.cleanup_idle_proxies"), \
         patch("mcprack.admin.user_proxy.list_proxy_instances", return_value=rows):
        resp = client.get("/admin/proxy-instances")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Running per-user proxy instances" in body
    assert "alice" in body
    assert "mastodon" in body
    assert "35123" in body
    assert f"/admin/users/{user.id}/edit" in body
    assert f"/admin/servers/{server.id}/edit" in body


def test_proxy_instances_page_shows_subscriptions_with_navigation_links(app, client):
    _login_admin(client)

    with app.app_context():
        user = User(username="bob", auth_type="local", is_admin=False)
        user.set_password("pw")
        server = McpServer(name="jenkins", label="Jenkins", transport="stdio", command="/bin/true", enabled=True)
        db.session.add_all([user, server])
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
        user_id, server_id = user.id, server.id

    with patch("mcprack.admin.user_proxy.cleanup_idle_proxies"), \
         patch("mcprack.admin.user_proxy.list_proxy_instances", return_value=[]):
        resp = client.get("/admin/proxy-instances")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Server subscriptions" in body
    assert "bob" in body
    assert "jenkins" in body
    assert f"/admin/users/{user_id}/edit" in body
    assert f"/admin/servers/{server_id}/edit" in body
    assert "not started yet" in body


def test_proxy_instance_stop_calls_manager(app, client):
    _login_admin(client)

    with patch("mcprack.admin.user_proxy.stop_user_server_proxy") as stop_mock:
        resp = client.post("/admin/proxy-instances/stop/7/9", follow_redirects=False)

    assert resp.status_code == 302
    stop_mock.assert_called_once_with(7, 9)
