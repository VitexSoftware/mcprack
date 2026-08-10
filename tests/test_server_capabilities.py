"""Tests for server capabilities discovery endpoint."""

import json
import pytest
from unittest.mock import patch, MagicMock
from mcprack.models import McpServer, User
from mcprack.extensions import db


def _login_admin(client):
    """Helper to create and log in an admin user."""
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


@pytest.fixture
def admin_user(client):
    """Create an admin user and log in."""
    _login_admin(client)


@pytest.fixture
def test_server_stdio(app):
    """Create a test stdio server."""
    with app.app_context():
        server = McpServer(
            name="test-stdio",
            label="Test Stdio Server",
            command="echo",
            transport="stdio",
            category="test",
        )
        db.session.add(server)
        db.session.commit()
        return server.id


@pytest.fixture
def test_server_network(app):
    """Create a test network server."""
    with app.app_context():
        server = McpServer(
            name="test-network",
            label="Test Network Server",
            url="http://localhost:8000/mcp",
            transport="http",
            category="test",
        )
        db.session.add(server)
        db.session.commit()
        return server.id


def test_capabilities_endpoint_requires_admin(client):
    """Accessing capabilities endpoint without admin should fail."""
    response = client.get("/admin/servers/1/capabilities")
    assert response.status_code == 302  # Redirect to login


def test_capabilities_endpoint_404_for_missing_server(client, admin_user):
    """Accessing capabilities for non-existent server should return 404."""
    response = client.get("/admin/servers/999/capabilities")
    assert response.status_code == 404


def test_capabilities_returns_json(app, client, admin_user, test_server_stdio):
    """Capabilities endpoint should return valid JSON."""
    with patch("mcprack.admin.user_proxy.ensure_user_server_proxy") as mock_ensure:
        with patch("mcprack.health.get_server_capabilities") as mock_caps:
            mock_ensure.return_value = 35000  # Return port
            mock_caps.return_value = {
                "tools": [{"name": "tool1", "description": "Test tool"}],
                "resources": [{"uri": "resource://test"}],
            }
            
            response = client.get(f"/admin/servers/{test_server_stdio}/capabilities")
            assert response.status_code == 200
            assert response.content_type == "application/json"
            
            data = json.loads(response.data)
            assert "tools" in data
            assert "resources" in data
            assert len(data["tools"]) == 1
            assert len(data["resources"]) == 1


def test_capabilities_handles_empty_results(app, client, admin_user, test_server_stdio):
    """Capabilities endpoint should handle servers with no tools/resources."""
    with patch("mcprack.admin.user_proxy.ensure_user_server_proxy") as mock_ensure:
        with patch("mcprack.health.get_server_capabilities") as mock_caps:
            mock_ensure.return_value = 35000  # Return port
            mock_caps.return_value = {
                "tools": [],
                "resources": [],
            }
            
            response = client.get(f"/admin/servers/{test_server_stdio}/capabilities")
            assert response.status_code == 200
            
            data = json.loads(response.data)
            assert data["tools"] == []
            assert data["resources"] == []


def test_capabilities_handles_unreachable_server(app, client, admin_user, test_server_stdio):
    """Capabilities endpoint should return 503 if server is unreachable."""
    with patch("mcprack.admin.user_proxy.ensure_user_server_proxy") as mock_ensure:
        with patch("mcprack.health.get_server_capabilities") as mock_caps:
            mock_ensure.return_value = 35000  # Return port
            mock_caps.return_value = None
            
            response = client.get(f"/admin/servers/{test_server_stdio}/capabilities")
            assert response.status_code == 503
            
            data = json.loads(response.data)
            assert "error" in data


def test_capabilities_handles_credential_errors(app, client, admin_user, test_server_stdio):
    """Capabilities endpoint should handle credential resolution errors."""
    with patch("mcprack.secret_store.resolve_server_env") as mock_resolve:
        from mcprack.secret_store import SecretStoreError
        mock_resolve.side_effect = SecretStoreError("Test error")
        
        response = client.get(f"/admin/servers/{test_server_stdio}/capabilities")
        assert response.status_code == 500
        
        data = json.loads(response.data)
        assert "error" in data


def test_capabilities_network_server(app, client, admin_user, test_server_network):
    """Capabilities endpoint should query network servers directly."""
    with patch("mcprack.health.get_server_capabilities") as mock_caps:
        mock_caps.return_value = {
            "tools": [{"name": "remote_tool"}],
            "resources": [],
        }
        
        response = client.get(f"/admin/servers/{test_server_network}/capabilities")
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data["tools"]) == 1


def test_capabilities_spawns_stdio_server(app, client, admin_user, test_server_stdio):
    """Capabilities endpoint should spawn stdio servers via user_proxy."""
    with patch("mcprack.admin.user_proxy.ensure_user_server_proxy") as mock_ensure:
        with patch("mcprack.health.get_server_capabilities") as mock_caps:
            mock_ensure.return_value = 35000  # Return port
            mock_caps.return_value = {
                "tools": [{"name": "spawned_tool"}],
                "resources": [],
            }
            
            response = client.get(f"/admin/servers/{test_server_stdio}/capabilities")
            
            # Should have called ensure_user_server_proxy
            assert mock_ensure.called
            assert response.status_code == 200
