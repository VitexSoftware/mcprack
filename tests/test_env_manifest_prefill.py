import html
import json
import re
from unittest import mock

import pytest

from mcprack import env_detection, secret_store
from mcprack.extensions import db
from mcprack.models import McpServer, User

MANIFEST = {
    "environmentVariables": [
        {"name": "MAIL_IMAP_HOST", "description": "IMAP server", "isRequired": True, "default": "mail.example.com"},
        {"name": "MAIL_IMAP_PORT", "default": 993},
        {"name": "MAIL_TLS", "choices": ["ssl", "starttls"], "default": "ssl"},
        {"name": "MAIL_PASSWORD", "isRequired": True, "isSecret": True, "default": "hunter2"},
        {"name": "MAIL_CREDENTIAL_STORAGE", "isSecret": False, "choices": ["auto", "keyring"]},
    ]
}


@pytest.fixture
def manifest_dir(tmp_path, monkeypatch):
    (tmp_path / "mcp-server-demo").mkdir()
    (tmp_path / "mcp-server-demo" / "server.json").write_text(json.dumps(MANIFEST))
    monkeypatch.setattr(env_detection, "MANIFEST_DIRS", (str(tmp_path), str(tmp_path / "manifests")))
    return tmp_path


def _server(command="/usr/bin/mcp-server-demo"):
    return McpServer(name="demo", label="Demo", transport="stdio", command=command)


def test_manifest_defaults_choices_and_secret_handling(manifest_dir):
    by_name = {e["name"]: e for e in env_detection.from_system_manifest(_server())}

    assert by_name["MAIL_IMAP_HOST"]["default"] == "mail.example.com"
    assert by_name["MAIL_IMAP_HOST"]["required"] is True
    assert by_name["MAIL_IMAP_PORT"]["default"] == "993"
    assert by_name["MAIL_TLS"]["choices"] == ["ssl", "starttls"]
    # a secret never gets a pre-filled value, even if the manifest has one
    assert by_name["MAIL_PASSWORD"]["secret"] is True
    assert "default" not in by_name["MAIL_PASSWORD"]
    # explicit isSecret=false beats the name heuristic ("CREDENTIAL")
    assert by_name["MAIL_CREDENTIAL_STORAGE"]["secret"] is False
    assert all(e["source"] == "manifest" for e in by_name.values())


def test_registry_style_packages_section(manifest_dir):
    (manifest_dir / "mcp-server-demo" / "server.json").write_text(
        json.dumps({"packages": [{"environmentVariables": [{"name": "X_URL", "default": "http://x"}]}]})
    )
    assert env_detection.from_system_manifest(_server())[0]["default"] == "http://x"


def test_companion_manifest_location(manifest_dir):
    (manifest_dir / "mcp-server-demo" / "server.json").unlink()
    (manifest_dir / "manifests").mkdir()
    (manifest_dir / "manifests" / "mcp-server-demo.json").write_text(json.dumps(MANIFEST))
    assert env_detection.from_system_manifest(_server())


@pytest.mark.parametrize("command", [None, "", "../../etc/passwd", "/usr/bin/..", "/usr/bin/no-such-server"])
def test_unsafe_or_missing_command_yields_nothing(manifest_dir, command):
    assert env_detection.from_system_manifest(_server(command)) == []


def test_malformed_manifest_never_raises(manifest_dir):
    (manifest_dir / "mcp-server-demo" / "server.json").write_text("{not json")
    assert env_detection.from_system_manifest(_server()) == []


def test_detect_env_vars_uses_manifest_without_install_method(manifest_dir):
    assert {e["name"] for e in env_detection.detect_env_vars(_server())} >= {"MAIL_IMAP_HOST"}


def _login_admin(client):
    with client.application.app_context():
        user = User(username="admin", auth_type="local", is_admin=True)
        user.set_password("adminpass")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "admin", "password": "adminpass"})


def test_edit_form_prefills_manifest_keys_with_defaults(app, client, manifest_dir):
    _login_admin(client)
    with app.app_context():
        server = _server()
        server.env_config = {"MAIL_IMAP_PORT": "143"}  # already configured -> not suggested again
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    with mock.patch.object(secret_store, "load_server_secrets", return_value={}):
        resp = client.get(f"/admin/servers/{server_id}/edit")

    body = resp.get_data(as_text=True)
    rows = {r["key"]: r for r in json.loads(html.unescape(re.search(r"data-initial='([^']*)'", body).group(1)))}
    assert rows["MAIL_IMAP_HOST"]["value"] == "mail.example.com"
    assert rows["MAIL_IMAP_HOST"]["source"] == "manifest"
    assert rows["MAIL_TLS"]["value"] == "ssl"
    assert "one of: ssl, starttls" in rows["MAIL_TLS"]["description"]
    assert rows["MAIL_PASSWORD"]["value"] == "" and rows["MAIL_PASSWORD"]["sensitive"] is True
    assert rows["MAIL_IMAP_PORT"]["value"] == "143"  # the admin's own value wins
