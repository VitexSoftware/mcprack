from unittest.mock import patch

from mcprack.extensions import db
from mcprack.models import (
    ConfigTemplate,
    McpServer,
    User,
    UserServerOverride,
    UserServerPermission,
    UserServerSelection,
)


def _make_admin(app):
    with app.app_context():
        admin_user = User(username="admin", auth_type="local", is_admin=True)
        admin_user.set_password("adminpass")
        target = User(username="alice", auth_type="local")
        target.set_password("alicepass")
        db.session.add_all([admin_user, target])
        db.session.commit()
        return target.id


def _login_admin(client):
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def _make_server(name="jenkins", **kwargs):
    defaults = dict(label=name.title(), transport="stdio", command="/bin/true", enabled=True)
    defaults.update(kwargs)
    server = McpServer(name=name, **defaults)
    db.session.add(server)
    db.session.commit()
    return server


def test_admin_selections_get_and_put(app, client):
    user_id = _make_admin(app)
    with app.app_context():
        server = _make_server("jenkins")
        server_id = server.id
    _login_admin(client)

    resp = client.get(f"/api/v1/admin/users/{user_id}/selections")
    assert resp.status_code == 200
    assert resp.get_json()["data"] == []

    resp = client.put(f"/api/v1/admin/users/{user_id}/selections", json={"server_ids": [server_id]})
    assert resp.status_code == 200
    assert resp.get_json()["data"]["server_ids"] == [server_id]

    with app.app_context():
        assert UserServerSelection.query.filter_by(user_id=user_id, server_id=server_id).first() is not None

    resp = client.get(f"/api/v1/admin/users/{user_id}/selections")
    entries = resp.get_json()["data"]
    assert len(entries) == 1
    assert entries[0]["server_id"] == server_id
    assert entries[0]["server_name"] == "jenkins"


def test_admin_selections_drop_disallowed_ids(app, client):
    user_id = _make_admin(app)
    with app.app_context():
        server = _make_server("denied")
        server_id = server.id
        db.session.add(UserServerPermission(user_id=user_id, server_id=server_id, is_allowed=False))
        db.session.commit()
    _login_admin(client)

    resp = client.put(f"/api/v1/admin/users/{user_id}/selections", json={"server_ids": [server_id]})
    assert resp.status_code == 200
    assert resp.get_json()["data"]["server_ids"] == []


def test_admin_selections_requires_admin(app, client):
    user_id = _make_admin(app)
    with app.app_context():
        other = User(username="bob", auth_type="local")
        other.set_password("bobpass")
        db.session.add(other)
        db.session.commit()

    client.post("/login", data={"username": "bob", "password": "bobpass"})
    resp = client.get(f"/api/v1/admin/users/{user_id}/selections")
    assert resp.status_code == 403


def test_admin_override_get_set_reset_bypasses_allow_user_override(app, client):
    user_id = _make_admin(app)
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins", allow_user_override=False, env_var_names=["API_TOKEN"])
        server_id = server.id
    _login_admin(client)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.get(f"/api/v1/admin/users/{user_id}/overrides/{server_id}")
        assert resp.status_code == 200
        assert resp.get_json()["data"]["has_override"] is False

        resp = client.put(
            f"/api/v1/admin/users/{user_id}/overrides/{server_id}", json={"env": {"API_TOKEN": "abc123"}}
        )
        assert resp.status_code == 200
        assert resp.get_json()["data"]["env_keys"] == ["API_TOKEN"]

        resp = client.get(f"/api/v1/admin/users/{user_id}/overrides/{server_id}?reveal=1")
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["has_override"] is True
        assert data["env"] == {"API_TOKEN": "abc123"}

        resp = client.delete(f"/api/v1/admin/users/{user_id}/overrides/{server_id}")
        assert resp.status_code == 204

        with app.app_context():
            assert UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first() is None


def test_admin_config_get(app, client):
    user_id = _make_admin(app)
    with app.app_context():
        server = McpServer(
            name="httpsvc", label="HTTP Svc", transport="http", url="https://example.test/mcp", enabled=True
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user_id, server_id=server.id))
        db.session.commit()
    _login_admin(client)

    resp = client.get(f"/api/v1/admin/users/{user_id}/config/copilot")
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    assert data["filename"] == "mcp.json"
    assert "httpsvc" in data["config"]["servers"]


def test_admin_config_returns_404_when_nothing_selected(app, client):
    user_id = _make_admin(app)
    _login_admin(client)

    resp = client.get(f"/api/v1/admin/users/{user_id}/config/claude")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "no_config"


def test_admin_templates_crud_and_apply(app, client):
    user_id = _make_admin(app)
    with app.app_context():
        allowed = _make_server("allowed")
        denied = _make_server("denied")
        allowed_id, denied_id = allowed.id, denied.id
    _login_admin(client)

    resp = client.post(
        "/api/v1/admin/templates",
        json={
            "name": "basic",
            "label": "Basic",
            "servers": [
                {"server_id": allowed_id, "is_allowed": True, "is_selected": True},
                {"server_id": denied_id, "is_allowed": False},
            ],
        },
    )
    assert resp.status_code == 201, resp.get_json()
    created = resp.get_json()["data"]
    template_id = created["id"]
    assert {(e["server_id"], e["is_allowed"], e["is_selected"]) for e in created["servers"]} == {
        (allowed_id, True, True),
        (denied_id, False, False),
    }

    resp = client.get("/api/v1/admin/templates")
    assert resp.status_code == 200
    assert any(t["name"] == "basic" for t in resp.get_json()["data"])

    resp = client.get(f"/api/v1/admin/templates/{template_id}")
    assert resp.status_code == 200
    assert resp.get_json()["data"]["name"] == "basic"

    resp = client.put(
        f"/api/v1/admin/templates/{template_id}",
        json={"label": "Basic v2", "servers": [{"server_id": allowed_id, "is_allowed": True, "is_selected": False}]},
    )
    assert resp.status_code == 200
    assert resp.get_json()["data"]["label"] == "Basic v2"
    assert resp.get_json()["data"]["servers"] == [
        {"server_id": allowed_id, "is_allowed": True, "is_selected": False}
    ]

    resp = client.post(
        f"/api/v1/admin/users/{user_id}/apply-template", json={"template_id": template_id}
    )
    assert resp.status_code == 200
    assert resp.get_json()["data"]["config_template_id"] == template_id

    with app.app_context():
        assert (
            UserServerPermission.query.filter_by(user_id=user_id, server_id=allowed_id).first().is_allowed is True
        )

    resp = client.delete(f"/api/v1/admin/templates/{template_id}")
    assert resp.status_code == 204
    with app.app_context():
        assert ConfigTemplate.query.filter_by(name="basic").first() is None


def test_admin_template_create_requires_name(app, client):
    _make_admin(app)
    _login_admin(client)
    resp = client.post("/api/v1/admin/templates", json={})
    assert resp.status_code == 400


def test_admin_template_create_duplicate_conflicts(app, client):
    _make_admin(app)
    _login_admin(client)
    resp = client.post("/api/v1/admin/templates", json={"name": "dup"})
    assert resp.status_code == 201
    resp = client.post("/api/v1/admin/templates", json={"name": "dup"})
    assert resp.status_code == 409


def test_apply_template_requires_template_id(app, client):
    user_id = _make_admin(app)
    _login_admin(client)
    resp = client.post(f"/api/v1/admin/users/{user_id}/apply-template", json={})
    assert resp.status_code == 400
