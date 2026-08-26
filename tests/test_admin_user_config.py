from unittest.mock import patch

from mcprack.extensions import db
from mcprack.models import (
    ConfigTemplate,
    ConfigTemplateServer,
    McpServer,
    User,
    UserServerOverride,
    UserServerPermission,
    UserServerSelection,
)


def _login_admin(client):
    with client.application.app_context():
        admin_user = User(username="admin", auth_type="local", is_admin=True)
        admin_user.set_password("adminpass")
        target = User(username="alice", auth_type="local", is_admin=False)
        target.set_password("alicepass")
        db.session.add_all([admin_user, target])
        db.session.commit()
        target_id = target.id
    client.post("/login", data={"username": "admin", "password": "adminpass"})
    return target_id


def _make_server(name="jenkins", **kwargs):
    defaults = dict(
        label=name.title(),
        transport="stdio",
        command="/bin/true",
        enabled=True,
    )
    defaults.update(kwargs)
    server = McpServer(name=name, **defaults)
    db.session.add(server)
    db.session.commit()
    return server


def test_user_edit_saves_config_selection(app, client):
    user_id = _login_admin(client)
    with app.app_context():
        a = _make_server("alpha")
        b = _make_server("beta")
        a_id, b_id = a.id, b.id

    resp = client.post(
        f"/admin/users/{user_id}/edit",
        data={
            "is_active": "on",
            f"server_access_{a_id}": "allow",
            f"server_access_{b_id}": "allow",
            "selected_server_id": str(a_id),
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app.app_context():
        selected = {row.server_id for row in UserServerSelection.query.filter_by(user_id=user_id).all()}
    assert selected == {a_id}


def test_user_edit_denied_server_cannot_be_selected(app, client):
    """A server ticked 'included' but simultaneously set to 'deny' must not
    end up in the saved selection — the ACL just written always wins."""
    user_id = _login_admin(client)
    with app.app_context():
        denied = _make_server("denied")
        denied_id = denied.id

    resp = client.post(
        f"/admin/users/{user_id}/edit",
        data={
            "is_active": "on",
            f"server_access_{denied_id}": "deny",
            "selected_server_id": str(denied_id),
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app.app_context():
        assert UserServerSelection.query.filter_by(user_id=user_id, server_id=denied_id).first() is None
        row = UserServerPermission.query.filter_by(user_id=user_id, server_id=denied_id).first()
        assert row.is_allowed is False


def test_user_form_shows_override_link_and_state(app, client):
    user_id = _login_admin(client)
    with app.app_context():
        server = _make_server("jenkins", allow_user_override=False)
        server_id = server.id

    resp = client.get(f"/admin/users/{user_id}/edit")
    body = resp.data.decode()
    assert resp.status_code == 200
    assert f"/admin/users/{user_id}/override/{server_id}" in body
    assert "self-service override disabled" in body


def test_admin_can_set_and_reset_individual_credentials(app, client):
    user_id = _login_admin(client)
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        server = _make_server("jenkins", allow_user_override=False, env_var_names=["API_TOKEN"])
        server_id = server.id

        resp = client.get(f"/admin/users/{user_id}/override/{server_id}")
        assert resp.status_code == 200
        assert "Self-service override is disabled" in resp.data.decode()

        resp = client.post(
            f"/admin/users/{user_id}/override/{server_id}",
            data={"action": "save", "env_text": "API_TOKEN=abc123"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

        from mcprack import secret_store

        user = db.session.get(User, user_id)
        assert secret_store.load_user_override_secrets(server, user) == {"API_TOKEN": "abc123"}
        assert UserServerOverride.query.filter_by(user_id=user_id, server_id=server_id).first() is not None

        resp = client.post(
            f"/admin/users/{user_id}/override/{server_id}",
            data={"action": "reset"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert secret_store.load_user_override_secrets(server, user) == {}


def test_templates_crud_and_apply(app, client):
    user_id = _login_admin(client)
    with app.app_context():
        allowed = _make_server("allowed")
        denied = _make_server("denied")
        allowed_id, denied_id = allowed.id, denied.id

    resp = client.post(
        "/admin/templates/new",
        data={
            "name": "basic",
            "label": "Basic users",
            "description": "Minimal access",
            f"template_allow_{allowed_id}": "on",
            f"template_select_{allowed_id}": "on",
            # denied_id omitted -> not allowed
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context():
        template = ConfigTemplate.query.filter_by(name="basic").first()
        assert template is not None
        entries = {e.server_id: e for e in template.entries}
        assert entries[allowed_id].is_allowed is True
        assert entries[allowed_id].is_selected is True
        assert entries[denied_id].is_allowed is False
        template_id = template.id

    resp = client.post(
        f"/admin/users/{user_id}/apply-template",
        data={"template_id": str(template_id)},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context():
        permission_map = {
            row.server_id: row.is_allowed
            for row in UserServerPermission.query.filter_by(user_id=user_id).all()
        }
        assert permission_map[allowed_id] is True
        assert permission_map[denied_id] is False
        selected = {row.server_id for row in UserServerSelection.query.filter_by(user_id=user_id).all()}
        assert selected == {allowed_id}
        assert db.session.get(User, user_id).config_template_id == template_id

    resp = client.post(f"/admin/templates/{template_id}/delete", follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        assert ConfigTemplate.query.filter_by(name="basic").first() is None
        # Deleting the template must not retroactively touch users it was
        # already applied to.
        assert UserServerSelection.query.filter_by(user_id=user_id, server_id=allowed_id).first() is not None


def test_apply_template_preserves_existing_user_override(app, client):
    user_id = _login_admin(client)
    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        from mcprack import secret_store

        server = _make_server("jenkins", env_var_names=["API_TOKEN"])
        user = db.session.get(User, user_id)
        secret_store.save_user_override_secrets(server, user, {"API_TOKEN": "personal"})
        db.session.commit()

        template = ConfigTemplate(name="t1", label="T1")
        db.session.add(template)
        db.session.flush()
        db.session.add(
            ConfigTemplateServer(template_id=template.id, server_id=server.id, is_allowed=True, is_selected=True)
        )
        db.session.commit()
        template_id = template.id

    resp = client.post(
        f"/admin/users/{user_id}/apply-template",
        data={"template_id": str(template_id)},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context(), patch("mcprack.secret_store.is_vaultwarden_configured", return_value=False):
        from mcprack import secret_store

        user = db.session.get(User, user_id)
        server = McpServer.query.filter_by(name="jenkins").first()
        assert secret_store.load_user_override_secrets(server, user) == {"API_TOKEN": "personal"}
