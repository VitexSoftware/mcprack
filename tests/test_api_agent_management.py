import time

from mcprack import oauth
from mcprack.extensions import db
from mcprack.models import (
    ApiToken,
    McpServer,
    OAuthToken,
    User,
    UserServerPermission,
    UserServerSelection,
)


def _create_user(app, username, is_admin=False):
    with app.app_context():
        user = User(username=username, auth_type="local", is_admin=is_admin)
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        return user.id


def _login(client, username):
    return client.post("/login", data={"username": username, "password": "pw"})


def test_user_catalog_exposes_access_and_selection_state(app, client):
    user_id = _create_user(app, "alice")
    _login(client, "alice")
    with app.app_context():
        allowed = McpServer(
            name="allowed", label="Allowed", transport="stdio",
            command="/bin/true", enabled=True, allow_user_override=True,
        )
        denied = McpServer(
            name="denied", label="Denied", transport="stdio",
            command="/bin/true", enabled=True,
        )
        db.session.add_all([allowed, denied])
        db.session.commit()
        db.session.add_all(
            [
                UserServerPermission(
                    user_id=user_id, server_id=allowed.id, is_allowed=True
                ),
                UserServerPermission(
                    user_id=user_id, server_id=denied.id, is_allowed=False
                ),
                UserServerSelection(user_id=user_id, server_id=allowed.id),
            ]
        )
        db.session.commit()

    response = client.get("/api/v1/me/catalog")

    assert response.status_code == 200
    entries = {entry["name"]: entry for entry in response.get_json()["data"]}
    assert entries["allowed"]["permitted"] is True
    assert entries["allowed"]["selected"] is True
    assert entries["denied"]["permitted"] is False
    assert entries["denied"]["access_request_status"] is None


def test_user_can_request_denied_access_and_admin_can_approve(app, client):
    user_id = _create_user(app, "alice")
    _create_user(app, "admin", is_admin=True)
    _login(client, "alice")
    with app.app_context():
        app.config["STRICT_SERVER_PERMISSIONS"] = True
        server = McpServer(
            name="denied", label="Denied", transport="stdio",
            command="/bin/true", enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id
        db.session.add(
            UserServerPermission(
                user_id=user_id, server_id=server_id, is_allowed=False
            )
        )
        db.session.commit()

    response = client.post(f"/api/v1/me/access-requests/{server_id}")

    assert response.status_code == 201
    assert response.get_json()["data"]["status"] == "pending"

    admin_client = app.test_client()
    _login(admin_client, "admin")
    response = admin_client.post(
        f"/api/v1/admin/access-requests/{user_id}/{server_id}/approve"
    )
    assert response.status_code == 200
    assert response.get_json()["data"]["status"] == "approved"

    with app.app_context():
        permission = db.session.get(UserServerPermission, (user_id, server_id))
        assert permission.is_allowed is True


def test_non_admin_cannot_resolve_access_request(app, client):
    user_id = _create_user(app, "alice")
    _login(client, "alice")

    response = client.post(
        f"/api/v1/admin/access-requests/{user_id}/999/approve"
    )

    assert response.status_code == 403
    assert response.get_json()["error"]["code"] == "forbidden"


def test_configuration_schema_is_secret_free(app, client):
    user_id = _create_user(app, "alice")
    _login(client, "alice")
    with app.app_context():
        server = McpServer(
            name="configurable",
            label="Configurable",
            transport="stdio",
            command="/bin/true",
            enabled=True,
            allow_user_override=True,
            env_var_names_json='["SERVICE_TOKEN"]',
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id
        db.session.add(
            UserServerPermission(
                user_id=user_id, server_id=server_id, is_allowed=True
            )
        )
        db.session.commit()

    response = client.get(
        f"/api/v1/servers/{server_id}/configuration-schema"
    )

    assert response.status_code == 200
    properties = response.get_json()["data"]["properties"]
    token = next(item for item in properties if item["key"] == "SERVICE_TOKEN")
    assert token["sensitive"] is True
    assert "value" not in token


def test_management_mcp_lists_only_user_tools_and_dispatches_api(app):
    user_id = _create_user(app, "alice")
    with app.app_context():
        server = McpServer(
            name="visible", label="Visible", transport="stdio",
            command="/bin/true", enabled=True,
        )
        db.session.add(server)
        db.session.flush()
        db.session.add(
            UserServerPermission(
                user_id=user_id, server_id=server.id, is_allowed=True
            )
        )
        raw, token = ApiToken.generate(
            "agent", user_id, scopes=["profile:read", "servers:read"]
        )
        db.session.add(token)
        db.session.commit()

    with app.app_context():
        client = app.test_client()
        response = client.post(
            "/mcp/management",
            headers={"Authorization": f"Bearer {raw}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            },
        )
    assert response.status_code == 200
    names = [tool["name"] for tool in response.get_json()["result"]["tools"]]
    assert "mcprack_list_catalog" in names
    assert "mcprack_subscribe" not in names
    assert "mcprack_admin_list_servers" not in names

    with app.app_context():
        fresh = app.test_client()
        response = fresh.post(
            "/mcp/management",
            headers={"Authorization": f"Bearer {raw}"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "mcprack_list_catalog", "arguments": {}},
            },
        )
    assert response.status_code == 200
    result = response.get_json()["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["data"][0]["name"] == "visible"


def test_management_mcp_rejects_anonymous_and_cookie_sessions(app, client):
    response = client.post(
        "/mcp/management",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 401
    assert "resource_metadata" in response.headers["WWW-Authenticate"]

    _create_user(app, "alice")
    _login(client, "alice")
    response = client.post(
        "/mcp/management",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    assert response.status_code == 401


def test_management_mcp_does_not_return_override_values(app):
    user_id = _create_user(app, "alice")
    with app.app_context():
        server = McpServer(
            name="configured", label="Configured", transport="stdio",
            command="/bin/true", enabled=True, allow_user_override=True,
        )
        db.session.add(server)
        db.session.flush()
        db.session.add(
            UserServerPermission(
                user_id=user_id, server_id=server.id, is_allowed=True
            )
        )
        raw, token = ApiToken.generate(
            "agent", user_id, scopes=["overrides:manage"]
        )
        db.session.add(token)
        db.session.commit()
        server_id = server.id

    with app.app_context():
        client = app.test_client()
        response = client.post(
            "/mcp/management",
            headers={"Authorization": f"Bearer {raw}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "mcprack_get_configuration",
                    "arguments": {"server_id": server_id},
                },
            },
        )
    payload = response.get_json()["result"]
    assert payload["isError"] is False
    assert "env" not in payload["structuredContent"]["data"]


def test_oauth_management_scope_authenticates_management_endpoint(app):
    user_id = _create_user(app, "alice")
    raw = "oauth-management-token"
    with app.app_context():
        token = OAuthToken(
            user_id=user_id,
            client_id="agent-client",
            token_type="Bearer",
            access_token=oauth.hash_token(raw),
            scope="mcprack:read mcprack:manage",
            issued_at=int(time.time()),
            expires_in=3600,
        )
        db.session.add(token)
        db.session.commit()

    with app.app_context():
        client = app.test_client()
        response = client.post(
            "/mcp/management",
            headers={"Authorization": f"Bearer {raw}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    assert response.status_code == 200
    names = [tool["name"] for tool in response.get_json()["result"]["tools"]]
    assert "mcprack_list_catalog" in names


def test_management_oauth_metadata_advertises_control_scopes():
    from mcprack.app import create_app
    from tests.conftest import TestConfig

    class OAuthConfig(TestConfig):
        OAUTH_ENABLED = True
        PUBLIC_BASE_URL = "https://mcprack.example.test"

    oauth_app = create_app(OAuthConfig)
    with oauth_app.app_context():
        db.create_all()
        response = oauth_app.test_client().get(
            "/.well-known/oauth-protected-resource/mcp/management"
        )
        db.drop_all()

    assert response.status_code == 200
    assert response.get_json()["resource"] == (
        "https://mcprack.example.test/mcp/management"
    )
    assert "mcprack:read" in response.get_json()["scopes_supported"]


def test_management_tools_follow_scopes_and_have_complete_annotations():
    from mcprack.management_mcp import TOOLS

    expected_hints = {
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
    }
    for tool in TOOLS:
        assert tool["title"]
        assert tool["description"]
        assert set(tool["annotations"]) == expected_hints
        for parameter in tool["inputSchema"]["properties"].values():
            assert parameter.get("description")

