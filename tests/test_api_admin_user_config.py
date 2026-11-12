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
    assert list(data["config"]["servers"]) == ["mcprack"]
    assert "/proxy/mcp/aggregate/" in data["config"]["servers"]["mcprack"]["url"]


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


def test_admin_override_api_handles_non_secret_and_secret_keys_together(app, client):
    """The JSON API, the CLI and the web editor all write the same override:
    plain keys land in the database, declared/sensitive-looking ones in the
    secret store, and a GET reports both."""
    from mcprack import secret_store

    user_id = _make_admin(app)
    with app.app_context():
        server = _make_server("jenkins", env_var_names=["API_TOKEN"])
        server_id = server.id
    _login_admin(client)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.put(
            f"/api/v1/admin/users/{user_id}/overrides/{server_id}",
            json={"env": {"API_TOKEN": "abc123", "REGION": "eu"}},
        )
        assert resp.status_code == 200

        resp = client.get(f"/api/v1/admin/users/{user_id}/overrides/{server_id}?reveal=1")
        assert resp.get_json()["data"]["env"] == {"API_TOKEN": "abc123", "REGION": "eu"}

        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            non_secret, secret = secret_store.load_user_override(server, user)
            row = UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first()

    assert non_secret == {"REGION": "eu"}
    assert secret == {"API_TOKEN": "abc123"}
    # the plain value really is in the row, not only in the secret store
    assert row.env_config == {"REGION": "eu"}


def test_admin_override_api_sees_a_value_set_through_the_web_editor(app, client):
    from mcprack import secret_store

    user_id = _make_admin(app)
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins", env_var_names=["API_TOKEN"])
        server_id = server.id
        user = db.session.get(User, user_id)
        secret_store.save_user_override(server, user, {"REGION": "eu"}, {})
        db.session.commit()
    _login_admin(client)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.get(f"/api/v1/admin/users/{user_id}/overrides/{server_id}?reveal=1")

    data = resp.get_json()["data"]
    assert data["has_override"] is True
    assert data["env"] == {"REGION": "eu"}


def test_override_put_keeps_an_existing_secret_key_out_of_the_database(app, client):
    """PUT replaces the whole override. A key the web editor stored as a
    secret because the user ticked the box matches no heuristic, so without
    the sticky classification a plain round-trip would rewrite a live
    credential into plain env_config_json."""
    from mcprack import secret_store

    user_id = _make_admin(app)
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins")
        server_id = server.id
        user = db.session.get(User, user_id)
        secret_store.save_user_override(server, user, {}, {"JENKINS_PAT": "pat-123"})
        db.session.commit()
    _login_admin(client)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.put(
            f"/api/v1/admin/users/{user_id}/overrides/{server_id}",
            json={"env": {"JENKINS_PAT": "pat-123", "REGION": "eu"}},
        )
        assert resp.status_code == 200

        with app.app_context():
            row = UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first()

    assert row.env_config == {"REGION": "eu"}


def test_override_put_can_demote_a_key_with_an_explicit_secret_keys_list(app, client):
    """The sticky rule must not become a one-way trap: an explicit
    secret_keys is the only way back to plain storage for a key that is
    secret purely because somebody ticked the box."""
    from mcprack import secret_store

    user_id = _make_admin(app)
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins")
        server_id = server.id
        user = db.session.get(User, user_id)
        secret_store.save_user_override(server, user, {}, {"JENKINS_PAT": "pat-123"})
        db.session.commit()
    _login_admin(client)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.put(
            f"/api/v1/admin/users/{user_id}/overrides/{server_id}",
            json={"env": {"JENKINS_PAT": "pat-123"}, "secret_keys": []},
        )
        assert resp.status_code == 200

        with app.app_context():
            row = UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first()

    assert row.env_config == {"JENKINS_PAT": "pat-123"}


def test_override_put_still_forces_an_admin_declared_secret(app, client):
    """An explicit secret_keys may add to the secret half, never shrink the
    part the server enforces."""
    from mcprack import secret_store

    user_id = _make_admin(app)
    with app.app_context():
        server = _make_server("jenkins", env_var_names=["API_TOKEN"])
        server_id = server.id
    _login_admin(client)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.put(
            f"/api/v1/admin/users/{user_id}/overrides/{server_id}",
            json={"env": {"API_TOKEN": "abc123"}, "secret_keys": []},
        )
        assert resp.status_code == 200

        with app.app_context():
            server = db.session.get(McpServer, server_id)
            user = db.session.get(User, user_id)
            non_secret, secret = secret_store.load_user_override(server, user)
            row = UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first()

    assert non_secret == {}
    assert secret == {"API_TOKEN": "abc123"}
    assert row.env_config == {}


def test_override_put_rejects_a_malformed_secret_keys_list(app, client):
    user_id = _make_admin(app)
    with app.app_context():
        server = _make_server("jenkins")
        server_id = server.id
    _login_admin(client)

    resp = client.put(
        f"/api/v1/admin/users/{user_id}/overrides/{server_id}",
        json={"env": {"REGION": "eu"}, "secret_keys": "REGION"},
    )

    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "invalid_request"


def test_override_put_reports_a_vaultwarden_failure_as_502(app, client):
    """The implicit path loads the existing override to learn which keys are
    secret. That load talks to Vaultwarden, so it has to sit inside the
    handler's try - outside it an outage turns the documented 502 into 500."""
    from mcprack import secret_store, vaultwarden

    user_id = _make_admin(app)
    with app.app_context():
        server = _make_server("jenkins")
        server_id = server.id
    _login_admin(client)

    with patch.object(
        secret_store, "load_user_override", side_effect=vaultwarden.VaultwardenError("vault down")
    ):
        resp = client.put(
            f"/api/v1/admin/users/{user_id}/overrides/{server_id}",
            json={"env": {"REGION": "eu"}},
        )

    assert resp.status_code == 502
    assert resp.get_json()["error"]["code"] == "vaultwarden_unreachable"


def test_override_get_reports_which_keys_are_secret(app, client):
    from mcprack import secret_store

    user_id = _make_admin(app)
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins", env_var_names=["API_TOKEN"])
        server_id = server.id
        user = db.session.get(User, user_id)
        secret_store.save_user_override(server, user, {"REGION": "eu"}, {"API_TOKEN": "abc123"})
        db.session.commit()
    _login_admin(client)

    with patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.get(f"/api/v1/admin/users/{user_id}/overrides/{server_id}")

    assert resp.get_json()["data"]["secret_keys"] == ["API_TOKEN"]
