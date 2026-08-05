from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerPermission


def _login_admin(client):
    with client.application.app_context():
        admin = User(username="admin", auth_type="local", is_admin=True)
        admin.set_password("adminpass")
        user = User(username="alice", auth_type="local", is_admin=False)
        user.set_password("alicepass")
        db.session.add_all([admin, user])
        db.session.commit()
        user_id = user.id
    client.post("/login", data={"username": "admin", "password": "adminpass"})
    return user_id


def test_user_edit_shows_allow_deny_controls(app, client):
    user_id = _login_admin(client)

    with app.app_context():
        server = McpServer(
            name="webdriver",
            label="Webdriver",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add(server)
        db.session.commit()

    resp = client.get(f"/admin/users/{user_id}/edit")
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "Server access" in body
    assert "server_access_" in body
    assert "Allow" in body
    assert "Deny" in body


def test_user_edit_persists_explicit_server_permissions(app, client):
    user_id = _login_admin(client)

    with app.app_context():
        allowed = McpServer(
            name="allowed",
            label="Allowed",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        denied = McpServer(
            name="denied",
            label="Denied",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add_all([allowed, denied])
        db.session.commit()
        allowed_id = allowed.id
        denied_id = denied.id

    resp = client.post(
        f"/admin/users/{user_id}/edit",
        data={
            "is_active": "on",
            "server_access_{}".format(allowed_id): "allow",
            "server_access_{}".format(denied_id): "deny",
        },
        follow_redirects=True,
    )

    assert resp.status_code == 200
    with app.app_context():
        rows = {
            row.server_id: row.is_allowed
            for row in UserServerPermission.query.filter_by(user_id=user_id).all()
        }
    assert rows[allowed_id] is True
    assert rows[denied_id] is False
