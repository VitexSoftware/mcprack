"""B-08 (docs/AUDIT-2026-11.md): the audit trail says WHAT changed on a server
registration - the command and URL in particular - without ever writing an
argument or an environment value into it."""

import pytest

from mcprack import server_changes
from mcprack.extensions import db
from mcprack.models import AuditLogEntry, McpServer, User

PW = "admin-long-password-1"


def _server(**kwargs):
    defaults = dict(name="zabbix", label="Z", transport="stdio", command="/usr/bin/zabbix-mcp", enabled=True)
    defaults.update(kwargs)
    server = McpServer(**defaults)
    return server


# --- the description ----------------------------------------------------------------------------


def test_a_changed_command_names_the_old_and_the_new_one():
    before = server_changes.snapshot(_server())
    after = server_changes.snapshot(_server(command="/opt/evil/run"))

    text = server_changes.describe(before, after)

    assert "command '/usr/bin/zabbix-mcp' -> '/opt/evil/run'" in text and text.startswith("server updated: ")


def test_arguments_are_fingerprinted_never_written():
    secret = "--token=SUPER-SECRET-VALUE"
    before = server_changes.snapshot(_server(args=["--ok"]))
    after = server_changes.snapshot(_server(args=["--ok", secret]))

    text = server_changes.describe(before, after)

    assert "args 1 -> 2 item(s)" in text and "sha256:" in text
    assert "SUPER-SECRET-VALUE" not in text and "--token" not in text
    assert server_changes.describe(after, after).startswith("server updated (no change")


def test_the_fingerprint_changes_when_one_argument_does():
    a = server_changes.snapshot(_server(args=["--mode", "a"]))
    b = server_changes.snapshot(_server(args=["--mode", "b"]))

    assert server_changes.describe(a, b) != server_changes.describe(a, a)
    assert "sha256:" in server_changes.describe(a, b)


def test_a_url_loses_its_credentials_and_query_string():
    snap = server_changes.snapshot(_server(command=None, transport="http", url="https://user:pw@mcp.example.com:8443/api/mcp?key=abc123#frag"))

    assert snap["url"] == "https://mcp.example.com:8443/api/mcp"
    text = server_changes.describe(None, snap)
    assert "pw" not in text.replace("mcp.example", "") and "abc123" not in text and "user" not in text


def test_an_unparseable_url_does_not_break_auditing():
    assert server_changes.snapshot(_server(url="http://host:notaport/x"))["url"] == "(invalid URL)"


def test_environment_changes_name_the_keys_only():
    server = _server()
    server.env_config = {"ZABBIX_URL": "https://zbx.example/api", "REGION": "eu"}
    server.env_var_names = ["ZABBIX_TOKEN"]
    before = server_changes.snapshot(server)
    server.env_config = {"ZABBIX_URL": "https://attacker.invalid/steal", "NEW_ONE": "x"}
    server.env_var_names = ["ZABBIX_TOKEN", "EXTRA_SECRET"]

    text = server_changes.describe(before, server_changes.snapshot(server))

    assert "env keys +NEW_ONE -REGION" in text and "secret keys +EXTRA_SECRET" in text
    assert "attacker.invalid" not in text and "zbx.example" not in text  # values never


def test_other_fields_are_reported_plainly():
    before = server_changes.snapshot(_server())
    after = server_changes.snapshot(_server(enabled=False, transport="http", auth_header_name="X-Api-Key"))

    text = server_changes.describe(before, after)

    assert "enabled True -> False" in text and "transport stdio -> http" in text and "auth_header_name (none) -> X-Api-Key" in text


def test_a_command_added_to_a_server_without_one_reads_clearly():
    before = server_changes.snapshot(_server(command=None, transport="http", url="https://a.example/mcp"))
    after = server_changes.snapshot(_server(command="/bin/sh", transport="http", url="https://a.example/mcp"))

    assert "command (none) -> '/bin/sh'" in server_changes.describe(before, after)


def test_a_new_server_is_described_with_its_command():
    server = _server(args=["-m", "srv"])
    server.env_var_names = ["TOKEN"]

    text = server_changes.describe(None, server_changes.snapshot(server))

    assert text.startswith("server created: ") and "command='/usr/bin/zabbix-mcp'" in text
    assert "args: 2 item(s)" in text and "TOKEN (secret)" in text
    assert "'-m'" not in text and "srv" not in text  # the arguments themselves are not written


def test_the_description_fits_the_audit_column():
    server = _server(command="/usr/bin/" + "x" * 300)
    server.env_config = {f"KEY_{i}": "v" for i in range(80)}

    assert len(server_changes.describe(None, server_changes.snapshot(server))) <= 470


# --- in the audit trail --------------------------------------------------------------------------


@pytest.fixture
def admin_client(app, client):
    with app.app_context():
        admin = User(username="root", auth_type="local", is_admin=True)
        admin.set_password(PW)
        db.session.add(admin)
        db.session.commit()
    client.post("/login", data={"username": "root", "password": PW})
    return client


def _changes(app):
    with app.app_context():
        return [row.error_message for row in AuditLogEntry.query.filter_by(action="admin_change").order_by(AuditLogEntry.id)]


def test_editing_the_command_over_the_api_is_recorded_with_both_values(app, admin_client):
    created = admin_client.post("/api/v1/admin/servers", json={
        "name": "svc", "transport": "stdio", "command": "/usr/bin/svc-mcp", "args": ["--port", "1"], "enabled": True,
    })
    server_id = created.get_json()["data"]["id"]

    admin_client.put(f"/api/v1/admin/servers/{server_id}", json={
        "transport": "stdio", "command": "/opt/other/binary", "args": ["--port", "1", "--password=hunter2"],
    })

    created_note, updated_note = _changes(app)[-2:]
    assert created_note.startswith("server created: ") and "/usr/bin/svc-mcp" in created_note and created_note.endswith("(via API)")
    assert "command '/usr/bin/svc-mcp' -> '/opt/other/binary'" in updated_note and "args 2 -> 3 item(s)" in updated_note
    assert "hunter2" not in updated_note and updated_note.endswith("(via API)")


def test_editing_a_server_in_the_admin_form_is_recorded_too(app, admin_client):
    with app.app_context():
        server = McpServer(name="web", label="W", transport="stdio", command="/usr/bin/web-mcp", enabled=True)
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    admin_client.post(f"/admin/servers/{server_id}/edit", data={
        "label": "W", "transport": "stdio", "command": "/usr/local/bin/replacement", "args": "--flag secretvalue", "enabled": "on",
    })

    note = _changes(app)[-1]
    assert "command '/usr/bin/web-mcp' -> '/usr/local/bin/replacement'" in note and "secretvalue" not in note


def test_creating_a_server_in_the_admin_form_is_recorded(app, admin_client):
    admin_client.post("/admin/servers/new", data={
        "name": "fresh", "label": "F", "transport": "stdio", "command": "/usr/bin/fresh-mcp", "args": "", "enabled": "on",
    })

    assert any(note.startswith("server created: ") and "/usr/bin/fresh-mcp" in note for note in _changes(app))


def test_the_env_value_set_through_the_api_never_reaches_the_audit_trail(app, admin_client):
    created = admin_client.post("/api/v1/admin/servers", json={
        "name": "envy", "transport": "stdio", "command": "/usr/bin/envy", "enabled": True,
        "env": {"ENDPOINT": "https://attacker.invalid/x"}, "secrets": {},
    })

    note = _changes(app)[-1]
    assert created.status_code == 201 and "ENDPOINT" in note and "attacker.invalid" not in note
