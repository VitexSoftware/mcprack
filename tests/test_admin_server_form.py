import re

from mcprack.extensions import db
from mcprack.models import McpServer, User


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def _make_server(app, name="mail-box"):
    with app.app_context():
        server = McpServer(name=name, label="Mail box", transport="stdio", command="/bin/true")
        db.session.add(server)
        db.session.commit()
        return server.id


def _new_server_form(name="new-server", **overrides):
    data = {
        "name": name,
        "label": "New server",
        "description": "",
        "category": "",
        "transport": "stdio",
        "command": "/bin/true",
        "args": "",
        "url": "",
        "auth_header_name": "",
        "auth_env_key": "",
        "allow_user_override": "on",
        "enabled": "on",
    }
    data.update(overrides)
    return data


def test_check_name_requires_admin(client):
    resp = client.get("/admin/servers/check-name?name=x")
    assert resp.status_code in (302, 401, 403)


def test_check_name_available_and_taken(app, client):
    _login_admin(client)
    _make_server(app, name="taken")

    resp = client.get("/admin/servers/check-name?name=free")
    assert resp.status_code == 200
    assert resp.get_json() == {"available": True}

    resp = client.get("/admin/servers/check-name?name=taken")
    assert resp.get_json() == {"available": False}

    # Empty name is left to the field's own `required` validation.
    resp = client.get("/admin/servers/check-name?name=")
    assert resp.get_json() == {"available": True}


def test_check_name_exclude_for_edit(app, client):
    _login_admin(client)
    server_id = _make_server(app, name="taken")

    resp = client.get(f"/admin/servers/check-name?name=taken&exclude={server_id}")
    assert resp.get_json() == {"available": True}

    resp = client.get("/admin/servers/check-name?name=taken&exclude=999")
    assert resp.get_json() == {"available": False}


def test_server_new_rejects_duplicate_name(app, client):
    """The live check-name probe is only a UX hint — the POST handler must
    still reject a duplicate slug instead of dying on the unique constraint."""
    _login_admin(client)
    _make_server(app, name="taken")

    resp = client.post("/admin/servers/new", data=_new_server_form(name="taken"))
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "already registered" in body
    # Re-rendered on the step that owns the name field.
    assert 'data-active-step="1"' in body
    with app.app_context():
        assert McpServer.query.filter_by(name="taken").count() == 1


def test_server_new_requires_name(app, client):
    _login_admin(client)
    resp = client.post("/admin/servers/new", data=_new_server_form(name=""))
    assert resp.status_code == 200
    assert "Name is required." in resp.get_data(as_text=True)
    with app.app_context():
        assert McpServer.query.count() == 0


def test_server_new_endpoint_error_returns_to_transport_step(app, client):
    _login_admin(client)
    resp = client.post("/admin/servers/new", data=_new_server_form(transport="http", url=""))
    assert resp.status_code == 200
    assert 'data-active-step="2"' in resp.get_data(as_text=True)


def test_server_form_renders_stepper_and_live_checks(client):
    _login_admin(client)
    resp = client.get("/admin/servers/new")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Stepper nav (hidden until JS enables it) with four steps…
    assert 'id="form-stepper"' in body
    assert 'data-active-step="1"' in body
    for step in (1, 2, 3, 4):
        assert f'class="form-card" data-step="{step}"' in body

    # …live name-uniqueness probe wired on the name field…
    assert 'data-check-name-url="/admin/servers/check-name"' in body
    assert "data-msg-taken=" in body

    # …and the three scripts that drive the form.
    for script in ("env-rows.js", "server-name-check.js", "server-form-steps.js"):
        assert f'src="/static/{script}"' in body


def test_server_form_env_container_has_error_labels(client):
    """env-rows.js needs the duplicate/empty-key labels as data attributes."""
    _login_admin(client)
    resp = client.get("/admin/servers/new")
    body = resp.get_data(as_text=True)
    assert "data-duplicate-label=" in body
    assert "data-empty-key-label=" in body


def test_edit_form_keeps_name_readonly(app, client):
    _login_admin(client)
    server_id = _make_server(app)
    resp = client.get(f"/admin/servers/{server_id}/edit")
    assert resp.status_code == 200
    match = re.search(r'<input type="text" id="name"[^>]*>', resp.get_data(as_text=True))
    assert match, "name input not found"
    assert "readonly" in match.group(0)
