"""Catalog / consent / admin OAuth UX surfaces."""

from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection
from tests.test_oauth_proxy import OAuthConfig, _login, _make_server, _make_user


def test_catalog_shows_path_token_note_by_default(client, app):
    with app.app_context():
        user = User(username="alice", auth_type="local")
        user.set_password("secret")
        db.session.add(user)
        db.session.commit()
        server = McpServer(
            name="svc",
            label="Svc",
            transport="http",
            url="http://127.0.0.1:9/mcp",
            enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()

    client.post("/login", data={"username": "alice", "password": "secret"})
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"personal access token" in resp.data
    assert b"MCP OAuth is enabled" not in resp.data


def test_catalog_shows_oauth_note_when_enabled(tmp_path, monkeypatch):
    from mcprack import installer, user_proxy
    from mcprack.app import create_app

    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "user-proxies")
    monkeypatch.setattr(installer, "STATE_DIR", tmp_path / "installs")
    application = create_app(OAuthConfig)
    application.config["BITWARDENCLI_APPDATA_DIR"] = str(tmp_path / "bw")
    with application.app_context():
        db.create_all()
        user = _make_user()
        _make_server(user)
        client = application.test_client()
        _login(client)
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"MCP OAuth is enabled" in resp.data
        assert b"/proxy/mcp/" in resp.data
        db.session.remove()
        db.drop_all()


def test_oauth_wizard_shows_disabled_by_default(client, app):
    with app.app_context():
        admin = User(username="admin", auth_type="local", is_admin=True)
        admin.set_password("secret")
        db.session.add(admin)
        db.session.commit()

    client.post("/login", data={"username": "admin", "password": "secret"})
    resp = client.get("/admin/oauth/wizard")
    assert resp.status_code == 200
    assert b"OAUTH_ENABLED" in resp.data
    assert b"Disabled" in resp.data


def test_oauth_wizard_shows_enabled_state(tmp_path, monkeypatch):
    from mcprack import installer, user_proxy
    from mcprack.app import create_app

    monkeypatch.setattr(user_proxy, "STATE_DIR", tmp_path / "user-proxies")
    monkeypatch.setattr(installer, "STATE_DIR", tmp_path / "installs")

    class AdminOAuthConfig(OAuthConfig):
        pass

    application = create_app(AdminOAuthConfig)
    application.config["BITWARDENCLI_APPDATA_DIR"] = str(tmp_path / "bw")
    with application.app_context():
        db.create_all()
        admin = User(username="admin", auth_type="local", is_admin=True)
        admin.set_password("secret")
        db.session.add(admin)
        db.session.commit()
        client = application.test_client()
        client.post("/login", data={"username": "admin", "password": "secret"})
        resp = client.get("/admin/oauth/wizard")
        assert resp.status_code == 200
        assert b"Enabled" in resp.data
        assert b"oauth-authorization-server" in resp.data
        db.session.remove()
        db.drop_all()
