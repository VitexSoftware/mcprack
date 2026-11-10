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


# Default-deny: every mutating route must be either blocked in demo mode or
# explicitly reviewed (with a reason) in demo.REVIEWED_SAFE. A new route that
# is in neither fails here, so it cannot skip the review - and the check is
# not a name-substring match that a differently named route would dodge.
def test_demo_guard_classifies_every_mutating_route(app):
    from mcprack.demo import BLOCKED_ENDPOINTS, REVIEWED_SAFE

    mutating = {
        rule.endpoint
        for rule in app.url_map.iter_rules()
        if rule.endpoint != "static" and rule.methods & {"POST", "PUT", "PATCH", "DELETE"}
    }

    unclassified = sorted(mutating - BLOCKED_ENDPOINTS - set(REVIEWED_SAFE))
    assert not unclassified, f"classify these routes in mcprack/demo.py: {unclassified}"
    assert not (BLOCKED_ENDPOINTS & set(REVIEWED_SAFE)), "a route cannot be both blocked and reviewed-safe"
    # OAuth routes only exist when OAUTH_ENABLED, so tolerate those being absent
    stale = sorted(
        e for e in (BLOCKED_ENDPOINTS | set(REVIEWED_SAFE)) - mutating if not e.startswith("oauth.")
    )
    assert not stale, f"demo.py lists routes that no longer exist: {stale}"


# --- the shared demo login must not be takeover-able ----------------------


def test_demo_mode_blocks_changing_the_shared_account_password(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    client.post(
        "/account/password",
        data={"current_password": "adminpass", "new_password": "attacker-chosen", "confirm_password": "attacker-chosen"},
    )

    with app.app_context():
        assert User.query.filter_by(username="admin").first().check_password("adminpass")


def test_demo_mode_blocks_creating_and_editing_accounts(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    client.post("/admin/users/new", data={"username": "rogue", "password": "whatever-123", "is_admin": "on"})
    api = client.post("/api/v1/admin/users", json={"username": "rogue2", "password": "whatever-123", "is_admin": True})

    assert api.status_code == 403
    with app.app_context():
        assert User.query.filter(User.username.in_(["rogue", "rogue2"])).count() == 0
        admin_id = User.query.filter_by(username="admin").first().id

    # demoting / deactivating the demo admin is refused as well
    client.post(f"/admin/users/{admin_id}/edit", data={"password": "taken-over-1"})
    put = client.put(f"/api/v1/admin/users/{admin_id}", json={"password": "taken-over-2", "is_admin": False})
    delete = client.delete(f"/api/v1/admin/users/{admin_id + 1}")

    assert put.status_code == 403
    assert delete.status_code == 403
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin.check_password("adminpass")
        assert admin.is_admin


def test_demo_mode_blocks_secret_store_migration(app, client):
    app.config["DEMO_MODE"] = True
    _login_admin(client)

    resp = client.post("/admin/vaultwarden/migrate-to-vaultwarden", follow_redirects=True)

    assert resp.status_code == 200
    assert b"disabled" in resp.data.lower()
