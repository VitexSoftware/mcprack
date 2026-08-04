from extensions import db
from models import McpServer, User, UserServerPermission


def _create_user(app, username, is_admin=False):
    with app.app_context():
        user = User(username=username, auth_type="local", is_admin=is_admin)
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        return user.id


def _login(client, username):
    return client.post("/login", data={"username": username, "password": "pw"})


def test_admin_server_crud_round_trip(app, client):
    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")

    resp = client.post(
        "/api/v1/admin/servers",
        json={"name": "svc", "label": "Svc", "transport": "stdio", "command": "/bin/true", "enabled": True},
    )
    assert resp.status_code == 201
    server_id = resp.get_json()["data"]["id"]

    resp = client.get(f"/api/v1/admin/servers/{server_id}")
    assert resp.status_code == 200
    assert resp.get_json()["data"]["name"] == "svc"

    resp = client.put(f"/api/v1/admin/servers/{server_id}", json={"label": "Updated Svc"})
    assert resp.status_code == 200
    assert resp.get_json()["data"]["label"] == "Updated Svc"

    resp = client.get(f"/api/v1/admin/servers/{server_id}")
    assert resp.get_json()["data"]["label"] == "Updated Svc"

    resp = client.delete(f"/api/v1/admin/servers/{server_id}")
    assert resp.status_code == 204

    resp = client.get(f"/api/v1/admin/servers/{server_id}")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "not_found"


def test_admin_server_create_requires_transport(app, client):
    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")

    resp = client.post("/api/v1/admin/servers", json={"name": "svc"})
    assert resp.status_code == 400


def test_non_admin_gets_json_403_not_html(app, client):
    _create_user(app, "alice", is_admin=False)
    _login(client, "alice")

    raw_token = client.post("/api/v1/tokens", json={"name": "ci"}).get_json()["data"]["token"]

    # See test_api_tokens.py::test_bearer_token_authenticates_without_cookies
    # for why this needs its own nested app context.
    with app.app_context():
        fresh = app.test_client()
        resp = fresh.get("/api/v1/admin/servers", headers={"Authorization": f"Bearer {raw_token}"})
    assert resp.status_code == 403
    body = resp.get_json()
    assert body["error"]["code"] == "forbidden"


def test_servers_list_respects_strict_permissions(app, client):
    user_id = _create_user(app, "alice", is_admin=False)
    _login(client, "alice")

    with app.app_context():
        app.config["STRICT_SERVER_PERMISSIONS"] = True
        allowed = McpServer(name="allowed", label="Allowed", transport="stdio", command="/bin/true", enabled=True)
        denied = McpServer(name="denied", label="Denied", transport="stdio", command="/bin/true", enabled=True)
        db.session.add_all([allowed, denied])
        db.session.commit()
        db.session.add(UserServerPermission(user_id=user_id, server_id=allowed.id, is_allowed=True))
        db.session.add(UserServerPermission(user_id=user_id, server_id=denied.id, is_allowed=False))
        db.session.commit()

    resp = client.get("/api/v1/servers")
    assert resp.status_code == 200
    names = {s["name"] for s in resp.get_json()["data"]}
    assert names == {"allowed"}
