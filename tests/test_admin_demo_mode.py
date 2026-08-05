from mcprack.extensions import db
from mcprack.models import McpServer, User


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def test_demo_mode_blocks_server_new(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    resp = client.post(
        "/admin/servers/new",
        data={"name": "evil", "transport": "stdio", "command": "/bin/sh", "args": "-c id"},
        follow_redirects=True,
    )

    assert resp.status_code == 200
    assert b"disabled" in resp.data.lower()
    with app.app_context():
        assert McpServer.query.filter_by(name="evil").first() is None


def test_demo_mode_blocks_server_edit(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    with app.app_context():
        server = McpServer(name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True)
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    resp = client.post(
        f"/admin/servers/{server_id}/edit",
        data={"name": "svc", "transport": "stdio", "command": "/bin/sh", "args": "-c id"},
        follow_redirects=True,
    )

    assert resp.status_code == 200
    with app.app_context():
        assert db.session.get(McpServer, server_id).command == "/bin/true"


def test_demo_mode_allows_viewing_server_edit_page(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    with app.app_context():
        server = McpServer(name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True)
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    resp = client.get(f"/admin/servers/{server_id}/edit")

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "/bin/true" in body
    assert "disabled" in body
    assert "Read-only" in body


def test_demo_mode_blocks_server_delete(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    with app.app_context():
        server = McpServer(name="svc", label="Svc", transport="stdio", command="/bin/true", enabled=True)
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    resp = client.post(f"/admin/servers/{server_id}/delete", follow_redirects=True)

    assert resp.status_code == 200
    with app.app_context():
        assert db.session.get(McpServer, server_id) is not None


def test_demo_mode_blocks_autodetect(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    resp = client.post("/admin/servers/autodetect", follow_redirects=True)

    assert resp.status_code == 200
    assert b"disabled" in resp.data.lower()


def test_demo_mode_off_allows_server_new(app, client):
    app.config["DEMO_MODE"] = False
    _login_admin(client)

    resp = client.post(
        "/admin/servers/new",
        data={"name": "svc", "transport": "stdio", "command": "/bin/true", "args": ""},
        follow_redirects=True,
    )

    assert resp.status_code == 200
    with app.app_context():
        assert McpServer.query.filter_by(name="svc").first() is not None
