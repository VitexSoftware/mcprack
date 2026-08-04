from unittest.mock import patch

from extensions import db
from models import McpServer, User, UserServerSelection


def _create_user(app, username="alice"):
    with app.app_context():
        user = User(username=username, auth_type="local")
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        return user.id


def _login(client, username="alice"):
    return client.post("/login", data={"username": username, "password": "pw"})


def _add_server(app, **kwargs):
    with app.app_context():
        server = McpServer(
            name=kwargs.pop("name", "svc"),
            label=kwargs.pop("label", "Svc"),
            transport=kwargs.pop("transport", "stdio"),
            command=kwargs.pop("command", "/bin/true"),
            enabled=kwargs.pop("enabled", True),
            allow_user_override=kwargs.pop("allow_user_override", True),
            **kwargs,
        )
        db.session.add(server)
        db.session.commit()
        return server.id


def test_me_returns_current_user_profile(app, client):
    user_id = _create_user(app)
    _login(client)

    resp = client.get("/api/v1/me")
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    assert data["id"] == user_id
    assert data["username"] == "alice"
    assert "password_hash" not in data


def test_selections_round_trip(app, client):
    _create_user(app)
    server_id = _add_server(app)
    _login(client)

    resp = client.put("/api/v1/me/selections", json={"server_ids": [server_id]})
    assert resp.status_code == 200
    assert resp.get_json()["data"]["server_ids"] == [server_id]

    resp = client.get("/api/v1/me/selections")
    assert resp.status_code == 200
    entries = resp.get_json()["data"]
    assert len(entries) == 1
    assert entries[0]["server_id"] == server_id
    assert entries[0]["server_name"] == "svc"

    resp = client.put("/api/v1/me/selections", json={"server_ids": []})
    assert resp.status_code == 200
    with app.app_context():
        assert UserServerSelection.query.count() == 0


def test_overrides_round_trip(app, client):
    _create_user(app)
    server_id = _add_server(app)
    _login(client)

    with patch("secret_store.is_vaultwarden_configured", return_value=False):
        resp = client.get(f"/api/v1/me/overrides/{server_id}")
        assert resp.status_code == 200
        assert resp.get_json()["data"]["has_override"] is False

        resp = client.put(f"/api/v1/me/overrides/{server_id}", json={"env": {"TOKEN": "secret"}})
        assert resp.status_code == 200

        resp = client.get(f"/api/v1/me/overrides/{server_id}?reveal=1")
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["has_override"] is True
        assert data["env"] == {"TOKEN": "secret"}

        resp = client.delete(f"/api/v1/me/overrides/{server_id}")
        assert resp.status_code == 204

        resp = client.get(f"/api/v1/me/overrides/{server_id}")
        assert resp.get_json()["data"]["has_override"] is False


def test_override_forbidden_when_not_allowed(app, client):
    _create_user(app)
    server_id = _add_server(app, name="locked", allow_user_override=False)
    _login(client)

    resp = client.get(f"/api/v1/me/overrides/{server_id}")
    assert resp.status_code == 403


def test_config_returns_404_json_when_nothing_selected(app, client):
    _create_user(app)
    _login(client)

    resp = client.get("/api/v1/me/config/claude")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "no_config"


def test_config_returns_json_for_selected_server(app, client):
    _create_user(app)
    server_id = _add_server(app)
    _login(client)

    client.put("/api/v1/me/selections", json={"server_ids": [server_id]})

    resp = client.get("/api/v1/me/config/claude")
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    assert data["filename"] == "claude_desktop_config.json"
    assert "svc" in data["config"]["mcpServers"]
