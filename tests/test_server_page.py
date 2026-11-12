import json
import uuid as uuid_module

import pytest

from mcprack import appstream_icons, env_detection, server_info
from mcprack import manifest as manifest_mod
from mcprack.extensions import db
from mcprack.models import McpServer, User, UserServerPermission

DECLARED = "6f1c1d0e-7a53-4c0e-9d2e-3a1b9f4c2e10"


def _login(client, username="alice", admin=False):
    with client.application.app_context():
        user = User(username=username, auth_type="local", is_admin=admin)
        user.set_password("pw")
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    client.post("/login", data={"username": username, "password": "pw"})
    return user_id


def _server(app, name="semaphore", enabled=True, command="/usr/bin/semaphore-mcp", **kw):
    with app.app_context():
        s = McpServer(name=name, label=name.title(), transport="stdio", command=command, enabled=enabled, **kw)
        db.session.add(s)
        db.session.commit()
        return s.id, s.uuid


def _unified(**ext):
    block = {
        "uuid": DECLARED,
        "author": {"name": "Vítězslav Dvořák", "url": "https://vitexsoftware.com"},
        "category": "developer",
        "tags": ["mcp", "semaphore"],
        "tools": [{"name": "launch_task", "description": "Start a task"}],
        "prompts": [{"name": "diagnose", "description": "Why did it fail?"}],
    }
    block.update(ext)
    return {
        "name": "io.github.vitexsoftware/mcp-server-semaphore",
        "title": "Semaphore MCP Server",
        "description": "Drive Semaphore UI from an AI assistant.",
        "version": "1.2.3",
        "websiteUrl": "https://vitexsoftware.com/semaphore",
        "repository": {"url": "https://github.com/VitexSoftware/semaphore-mcp-server", "source": "github"},
        "packages": [{
            "registryType": "pypi", "identifier": "mcp-server-semaphore", "version": "1.2.3",
            "transport": {"type": "stdio"},
            "environmentVariables": [
                {"name": "SEMAPHORE_URL", "description": "Base URL", "isRequired": True, "isSecret": False},
                {"name": "SEMAPHORE_API_TOKEN", "description": "API token", "isSecret": True},
            ],
        }],
        "_meta": {manifest_mod.PUBLISHER_KEY: {manifest_mod.EXTENSION_KEY: block}},
    }


@pytest.fixture
def manifest(tmp_path, monkeypatch):
    """A unified server.json installed for /usr/bin/semaphore-mcp. Returns the
    dict; mutate it and call .write() to change the installed file."""
    path = tmp_path / "server.json"

    class Manifest(dict):
        def write(self):
            path.write_text(json.dumps(self), encoding="utf-8")

    result = Manifest(_unified())
    result.write()
    monkeypatch.setattr(server_info, "_plugin_candidates", lambda command: [])
    monkeypatch.setattr(env_detection, "_manifest_candidates", lambda command: [path] if command else [])
    return result


def test_new_servers_get_a_unique_uuid(app):
    _, a = _server(app, "a", command=None)
    _, b = _server(app, "b", command=None)
    assert str(uuid_module.UUID(a)) == a
    assert a != b


def test_uuid_survives_rename(app):
    server_id, original = _server(app, "old-name", command=None)
    with app.app_context():
        server = db.session.get(McpServer, server_id)
        server.name = "mcp-server-new-name"
        db.session.commit()
        assert db.session.get(McpServer, server_id).uuid == original


def test_page_requires_login(client, app):
    _, u = _server(app)
    assert client.get(f"/server/{u}").status_code in (302, 401)


def test_unknown_uuid_is_404(client, app):
    _login(client)
    assert client.get(f"/server/{uuid_module.uuid4()}").status_code == 404


def test_user_sees_page_with_manifest_info(client, app, manifest):
    _login(client)
    _, u = _server(app)
    resp = client.get(f"/server/{u}")
    body = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "Semaphore MCP Server" in body
    assert "Drive Semaphore UI from an AI assistant." in body
    assert "Vítězslav Dvořák" in body
    assert "https://github.com/VitexSoftware/semaphore-mcp-server" in body
    assert "SEMAPHORE_API_TOKEN" in body and "SEMAPHORE_URL" in body
    # tools come from lhm.plugin.json, so ordinary users see them without a live probe
    assert "launch_task" in body and "Start a task" in body and "diagnose" in body
    # admin-only operational details stay hidden from ordinary users
    assert "/usr/bin/semaphore-mcp" not in body


def test_declared_uuid_is_adopted_and_page_found_by_it(client, app, manifest):
    _login(client)
    _, random_uuid = _server(app)
    assert random_uuid != DECLARED
    resp = client.get(f"/server/{DECLARED}")
    assert resp.status_code == 200
    with app.app_context():
        assert McpServer.query.filter_by(name="semaphore").one().uuid == DECLARED


def test_declared_uuid_not_stolen_from_another_row(app, manifest):
    _server(app, "first")  # adopts DECLARED
    _, other = _server(app, "second")
    with app.app_context():
        first = McpServer.query.filter_by(name="first").one()
        assert server_info.sync_uuid(first) is True
        second = McpServer.query.filter_by(name="second").one()
        assert server_info.sync_uuid(second) is False
        assert second.uuid == other


def test_user_can_open_info_cards_for_disabled_or_forbidden_servers(client, app):
    user_id = _login(client)
    _, disabled = _server(app, "off", enabled=False, command=None)
    sid, forbidden = _server(app, "nope", command="/bin/true")
    with app.app_context():
        db.session.add(UserServerPermission(user_id=user_id, server_id=sid, is_allowed=False))
        db.session.commit()

    disabled_resp = client.get(f"/server/{disabled}")
    forbidden_resp = client.get(f"/server/{forbidden}")

    assert disabled_resp.status_code == 200
    assert "disabled by an administrator" in disabled_resp.get_data(as_text=True)
    assert forbidden_resp.status_code == 200
    body = forbidden_resp.get_data(as_text=True)
    assert "Administrator allows access" in body
    assert "Request access" in body
    assert "/proxy/mcp/" not in body


def test_admin_sees_operational_details(client, app, manifest):
    _login(client, "root", admin=True)
    _, u = _server(app, enabled=False)
    body = client.get(f"/server/{u}").get_data(as_text=True)
    assert "/usr/bin/semaphore-mcp" in body
    assert "data-capabilities-btn" in body


def test_page_degrades_without_any_metadata(client, app):
    _login(client)
    _, u = _server(app, "bare", command=None)
    resp = client.get(f"/server/{u}")
    assert resp.status_code == 200
    assert "has not published a description" in resp.get_data(as_text=True)


def test_untrusted_urls_are_not_linked(app, manifest):
    manifest["websiteUrl"] = "javascript:alert(1)"
    manifest["repository"]["url"] = "javascript:alert(3)"
    ext = manifest_mod.extension(manifest)
    ext["author"]["url"] = "data:text/html,x"
    manifest.write()
    sid, _ = _server(app, "zz-nonexistent", command="/opt/none/zz-nonexistent")
    with app.app_context():
        info = server_info.describe(db.session.get(McpServer, sid))
    assert info["repository"] is None and info["homepage"] is None
    assert info["author"]["url"] is None


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "data:text/html,x", "https://", "//evil.test/x", "HTTP:foo", "file:///etc/passwd", "", None, 5])
def test_http_url_rejects_everything_but_real_http_urls(bad):
    assert server_info._http_url(bad) is None


def test_http_url_accepts_http_and_https():
    assert server_info._http_url(" https://github.com/a/b ") == "https://github.com/a/b"
    assert server_info._http_url("http://localhost:8080/x") == "http://localhost:8080/x"


def test_legacy_lhm_plugin_still_read(app, tmp_path, monkeypatch):
    legacy = tmp_path / "lhm.plugin.json"
    legacy.write_text(json.dumps({"name": "Old", "description": "d", "author": "A", "homepage": "https://github.com/x/y", "uuid": DECLARED, "tools": [{"name": "t", "description": "td"}]}), encoding="utf-8")
    monkeypatch.setattr(server_info, "_plugin_candidates", lambda command: [legacy])
    monkeypatch.setattr(env_detection, "_manifest_candidates", lambda command: [])
    sid, _ = _server(app, "zz-nonexistent", command="/opt/none/zz-nonexistent")
    with app.app_context():
        info = server_info.describe(db.session.get(McpServer, sid))
    assert info["manifest_format"] == "lhm.plugin.json"
    assert info["title"] == "Old" and info["tools"][0]["name"] == "t"
    assert "server.json" in info["missing"]


def test_malformed_plugin_file_is_ignored(app, tmp_path, monkeypatch):
    bad = tmp_path / "lhm.plugin.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(server_info, "_plugin_candidates", lambda command: [bad])
    sid, _ = _server(app, "zz-nonexistent", command="/opt/none/zz-nonexistent")
    with app.app_context():
        info = server_info.describe(db.session.get(McpServer, sid))
    assert info["has_manifest"] is False
    assert "server.json" in info["missing"]


def test_icons_link_to_server_page(client, app):
    _login(client)
    _, u = _server(app, "linked", command=None)
    body = client.get("/servers").get_data(as_text=True)
    assert f"/server/{u}" in body


def test_appstream_metadata_extraction():
    import xml.etree.ElementTree as ET

    comp = ET.fromstring(
        """<component type="console-application"><id>x</id><name>X</name>
        <summary>Does X</summary><project_license>MIT</project_license>
        <description><p>Para <em>one</em>.</p><ul><li>a</li><li>b</li></ul></description>
        <categories><category>System</category></categories>
        <url type="homepage">https://h.example</url>
        <url type="vcs-browser">javascript:evil</url>
        <developer id="d"><name>Dev</name></developer>
        <releases><release version="2.0" date="2026-01-01"/></releases></component>"""
    )
    meta = appstream_icons._component_meta(comp)
    assert meta["summary"] == "Does X" and meta["developer"] == "Dev" and meta["license"] == "MIT"
    assert meta["description"] == ["Para one.", ["a", "b"]]
    assert meta["urls"] == {"homepage": "https://h.example"}
    assert meta["latest_release"]["version"] == "2.0"
