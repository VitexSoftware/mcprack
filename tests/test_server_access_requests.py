from mcprack.extensions import db
from mcprack.models import (
    McpServer,
    User,
    UserServerAccessRequest,
    UserServerPermission,
    UserServerSelection,
)


def _create_user(app, username):
    with app.app_context():
        user = User(username=username, auth_type="local")
        user.set_password("long-password-for-tests")
        db.session.add(user)
        db.session.commit()
        return user.id


def _create_server_and_deny(app, user_id):
    with app.app_context():
        server = McpServer(
            name="requestable",
            label="Requestable MCP",
            transport="stdio",
            command="/bin/true",
            enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerPermission(user_id=user_id, server_id=server.id, is_allowed=False))
        db.session.commit()
        return server.id


def _login(client, username):
    response = client.post("/login", data={"username": username, "password": "long-password-for-tests"})
    assert response.status_code == 302


def _submit_request(app, client, user_id, server_id):
    _login(client, "alice")
    response = client.post(f"/servers/{server_id}/request-access")
    assert response.status_code == 302
    client.post("/logout")
    admin_id = _create_user(app, "root")
    with app.app_context():
        db.session.get(User, admin_id).is_admin = True
        db.session.commit()
    _login(client, "root")
    return admin_id


def test_admin_can_approve_request_without_subscribing_user(app, client):
    user_id = _create_user(app, "alice")
    server_id = _create_server_and_deny(app, user_id)
    admin_id = _submit_request(app, client, user_id, server_id)

    queue = client.get("/admin/access-requests")
    assert queue.status_code == 200
    assert b"alice" in queue.data and b"Requestable MCP" in queue.data

    response = client.post(f"/admin/access-requests/{user_id}/{server_id}/approve")
    assert response.status_code == 302
    with app.app_context():
        access_request = db.session.get(UserServerAccessRequest, (user_id, server_id))
        permission = db.session.get(UserServerPermission, (user_id, server_id))
        assert access_request.status == "approved"
        assert permission.is_allowed is True
        assert db.session.get(UserServerSelection, (user_id, server_id)) is None

        db.session.delete(db.session.get(User, admin_id))
        db.session.commit()
        assert db.session.get(UserServerAccessRequest, (user_id, server_id)).resolved_by_id is None


def test_admin_can_deny_request_without_granting_access(app, client):
    user_id = _create_user(app, "alice")
    server_id = _create_server_and_deny(app, user_id)
    _submit_request(app, client, user_id, server_id)

    response = client.post(f"/admin/access-requests/{user_id}/{server_id}/deny")
    assert response.status_code == 302
    with app.app_context():
        access_request = db.session.get(UserServerAccessRequest, (user_id, server_id))
        permission = db.session.get(UserServerPermission, (user_id, server_id))
        assert access_request.status == "denied"
        assert permission.is_allowed is False