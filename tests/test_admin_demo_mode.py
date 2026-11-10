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


# --- A-01: the demo write-guard must hold for the REST API too ---------------
# Regression for docs/AUDIT-2026-11.md A-01: the guard used to live only in
# the HTML routes, so a demo admin could register a server with an arbitrary
# `command` (executed as the service user) through /api/v1/admin/servers.

import pytest

from mcprack.models import ApiToken


def _api_server_payload(name="evil"):
    return {
        "name": name,
        "label": name,
        "transport": "stdio",
        "command": "/bin/sh",
        "args": ["-c", "id"],
        "enabled": True,
    }


def _make_server(app, command="/bin/true"):
    with app.app_context():
        server = McpServer(name="svc", label="Svc", transport="stdio", command=command, enabled=True)
        db.session.add(server)
        db.session.commit()
        return server.id


def test_demo_mode_blocks_api_server_create(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    resp = client.post("/api/v1/admin/servers", json=_api_server_payload())

    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "demo_mode"
    with app.app_context():
        assert McpServer.query.filter_by(name="evil").first() is None


def test_demo_mode_blocks_api_server_update(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)
    server_id = _make_server(app)

    resp = client.put(f"/api/v1/admin/servers/{server_id}", json={"command": "/bin/sh", "args": ["-c", "id"]})

    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "demo_mode"
    with app.app_context():
        assert db.session.get(McpServer, server_id).command == "/bin/true"


def test_demo_mode_blocks_api_server_delete(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)
    server_id = _make_server(app)

    resp = client.delete(f"/api/v1/admin/servers/{server_id}")

    assert resp.status_code == 403
    with app.app_context():
        assert db.session.get(McpServer, server_id) is not None


def test_demo_mode_blocks_api_server_create_with_admin_bearer_token(app):
    app.config["DEMO_MODE"] = True
    with app.app_context():
        admin = User(username="tokadmin", auth_type="local", is_admin=True)
        admin.set_password("pw")
        db.session.add(admin)
        db.session.commit()
        raw, token = ApiToken.generate("ci", admin.id)
        db.session.add(token)
        db.session.commit()

    resp = app.test_client().post(
        "/api/v1/admin/servers",
        json=_api_server_payload(),
        headers={"Authorization": f"Bearer {raw}"},
    )

    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "demo_mode"
    with app.app_context():
        assert McpServer.query.filter_by(name="evil").first() is None


def test_demo_mode_api_reads_still_work(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)
    _make_server(app)

    resp = client.get("/api/v1/admin/servers")

    assert resp.status_code == 200
    assert [s["name"] for s in resp.get_json()["data"]] == ["svc"]


def test_demo_mode_off_allows_api_server_create(app, client):
    app.config["DEMO_MODE"] = False
    _login_admin(client)

    resp = client.post("/api/v1/admin/servers", json=_api_server_payload("fine"))

    assert resp.status_code == 201


@pytest.mark.parametrize("kind", ["pip", "npm", "docker"])
def test_demo_mode_blocks_install_routes(app, client, kind):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    resp = client.post(
        f"/admin/install/{kind}",
        data={"name": "evil", "package_spec": "x", "expected_binary": "x", "image_ref": "x"},
        follow_redirects=True,
    )

    assert resp.status_code == 200
    with app.app_context():
        assert McpServer.query.filter_by(name="evil").first() is None


# A route added later that registers/edits/deletes/installs servers must not
# silently escape the demo guard: every mutating admin/API route whose name
# mentions "server" or "install" has to be either blocked or consciously
# reviewed as harmless.
_REVIEWED_DEMO_SAFE = {
    "admin.server_test_stdio",  # starts an *already registered* command, registers nothing
}


def test_demo_guard_covers_every_server_mutating_route(app):
    from mcprack.demo import BLOCKED_ENDPOINTS

    uncovered = []
    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        if not endpoint.startswith(("admin.", "api.")):
            continue
        if not (rule.methods & {"POST", "PUT", "PATCH", "DELETE"}):
            continue
        if "server" in endpoint or "install" in endpoint:
            if endpoint not in BLOCKED_ENDPOINTS and endpoint not in _REVIEWED_DEMO_SAFE:
                uncovered.append(endpoint)

    assert not uncovered, f"demo guard does not cover: {uncovered}"
