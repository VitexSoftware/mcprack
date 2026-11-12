"""A user can download a config with one URL per selected server (besides the
default single aggregate URL), through the web UI, the API and the CLI."""

import json
import re

import pytest

from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerSelection


def _setup(app, client, names=("alpha", "beta")):
    with app.app_context():
        user = User(username="alice", auth_type="local")
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        for name in names:
            server = McpServer(name=name, label=name.title(), transport="http", url=f"https://{name}.example.test/mcp", enabled=True)
            db.session.add(server)
            db.session.commit()
            db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
    client.post("/login", data={"username": "alice", "password": "pw"})


def _servers(response):
    return json.loads(response.get_data(as_text=True))["mcpServers"]


@pytest.mark.parametrize("path, client_name", [("claude", "claude"), ("vscode", "vscode"), ("cursor", "cursor")])
def test_download_defaults_to_the_aggregate_url(app, client, path, client_name):
    _setup(app, client)
    data = json.loads(client.get(f"/download/{path}").get_data(as_text=True))
    entries = data.get("mcpServers") or data.get("servers")
    assert list(entries) == ["mcprack"]
    assert "/proxy/mcp/aggregate/" in entries["mcprack"]["url"]


@pytest.mark.parametrize("path", ["claude", "cursor"])
def test_per_server_download_lists_every_selected_server(app, client, path):
    _setup(app, client)
    response = client.get(f"/download/{path}?mode=servers")
    assert response.status_code == 200 and "attachment" in response.headers["Content-Disposition"]
    entries = _servers(response)
    assert sorted(entries) == ["alpha", "beta"]
    urls = [e["url"] for e in entries.values()]
    assert all(re.search(r"/proxy/mcp/[^/]+/\d+$", u) for u in urls) and len(set(urls)) == 2
    assert not any("example.test" in u for u in urls), "raw backend URLs must never reach the user"


def test_claude_code_per_server_uses_secret_free_urls(app, client):
    _setup(app, client)
    entries = _servers(client.get("/download/claude-code?mode=servers"))
    assert sorted(entries) == ["alpha", "beta"]
    for entry in entries.values():
        assert re.search(r"/proxy/mcp/\d+$", entry["url"])  # tokenless Bearer URL
        assert "${MCPRACK_TOKEN}" in entry["headers"]["Authorization"]


def test_unknown_mode_falls_back_to_the_aggregate(app, client):
    _setup(app, client)
    assert list(_servers(client.get("/download/claude?mode=bogus"))) == ["mcprack"]


def test_view_page_offers_both_modes_and_lists_claude_commands(app, client):
    _setup(app, client)
    aggregate = client.get("/view/claude-code").get_data(as_text=True)
    assert "mode=servers" in aggregate and "Show one URL per server instead" in aggregate
    per_server = client.get("/view/claude-code?mode=servers").get_data(as_text=True)
    assert len(re.findall(r"claude mcp add --transport http --scope user (alpha|beta) ", per_server)) == 2
    assert "Show the single aggregate URL instead" in per_server
    assert "mode=servers" in per_server  # the download link keeps the mode


def test_catalog_links_to_the_per_server_config(app, client):
    _setup(app, client)
    body = client.get("/").get_data(as_text=True)
    for name in ("claude", "claude-code", "vscode", "cursor"):
        assert f"/download/{name}?mode=servers" in body


def test_nothing_selected_is_still_an_error(app, client):
    _setup(app, client, names=())
    response = client.get("/download/claude?mode=servers", follow_redirects=False)
    assert response.status_code == 302


def test_api_me_config_supports_the_mode(app, client):
    _setup(app, client)  # the API accepts the web session
    per = client.get("/api/v1/me/config/claude?mode=servers").get_json()
    assert sorted(per["data"]["config"]["mcpServers"]) == ["alpha", "beta"]
    agg = client.get("/api/v1/me/config/claude").get_json()
    assert list(agg["data"]["config"]["mcpServers"]) == ["mcprack"]


def test_cli_per_server_flag(app):
    with app.app_context():
        user = User(username="bob", auth_type="local")
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        server = McpServer(name="gamma", label="Gamma", transport="http", url="https://g.example.test/mcp", enabled=True)
        db.session.add(server)
        db.session.commit()
        db.session.add(UserServerSelection(user_id=user.id, server_id=server.id))
        db.session.commit()
    app.config["PUBLIC_BASE_URL"] = "https://mcprack.example.test"
    runner = app.test_cli_runner()
    per = runner.invoke(args=["user", "config", "show", "bob", "claude", "--per-server"])
    assert per.exit_code == 0, per.output
    assert list(json.loads(per.output)["mcpServers"]) == ["gamma"]
    agg = runner.invoke(args=["user", "config", "show", "bob", "claude"])
    assert list(json.loads(agg.output)["mcpServers"]) == ["mcprack"]
