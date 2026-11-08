"""Tests for the CLI server probes: `mcprack server test NAME` (registered
catalog server) and `mcprack server probe COMMAND [ARGS...]` (raw stdio
command, no catalog entry — the form used by autopkgtest smoke tests of
mcp-server-* deb packages).

The probes are exercised end to end against a tiny stub MCP server that
speaks newline-delimited JSON-RPC on stdio, plus crashing/sleeping stubs
for the failure paths.
"""

import json
import stat
from unittest.mock import patch

from mcprack.extensions import db
from mcprack.models import McpServer

# A minimal but real MCP stdio server: answers initialize / tools/list /
# resources/list / prompts/list and ignores notifications. The marker env
# var and argv are echoed into serverInfo.name so tests can prove the spawn
# environment and arguments actually reach the server process.
STUB_MCP_SERVER = r'''#!/usr/bin/env python3
import json
import os
import sys

TOOLS = [{"name": "ping", "description": "Ping the server", "inputSchema": {"type": "object", "properties": {}}}]
RESOURCES = [{"uri": "stub://config", "name": "Config", "description": "Stub config resource"}]
PROMPTS = [{"name": "hello", "description": "Say hello"}]

name = "stub-mcp-" + os.environ.get("STUB_MARKER", "none")
if len(sys.argv) > 1:
    name += "/" + "/".join(sys.argv[1:])

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": name, "version": "0.1"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "resources/list":
        result = {"resources": RESOURCES}
    elif method == "prompts/list":
        result = {"prompts": PROMPTS}
    elif "id" in msg:
        result = {}
    else:
        continue  # notification - no response
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\n")
    sys.stdout.flush()
'''

CRASH_STUB = r'''#!/usr/bin/env python3
import sys
sys.stderr.write("Traceback (most recent call last):\nImportError: No module named 'fastmcp'\n")
sys.exit(1)
'''

SLEEP_STUB = r'''#!/usr/bin/env python3
import time
time.sleep(60)
'''


def _write_stub(tmp_path, name, source=STUB_MCP_SERVER):
    path = tmp_path / name
    path.write_text(source)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def _output(result):
    parts = [result.output]
    try:
        parts.append(result.stderr or "")
    except ValueError:
        pass  # older click mixes stderr into output already
    return "\n".join(parts)


def test_server_probe_lists_tools_resources_prompts(app, tmp_path):
    stub = _write_stub(tmp_path, "stub-mcp")
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "probe", stub])
        assert result.exit_code == 0, result.output
        assert "stub-mcp-none" in result.output
        assert "tools (1):" in result.output
        assert "ping" in result.output
        assert "resources (1):" in result.output
        assert "stub://config" in result.output
        assert "prompts (1):" in result.output
        assert "hello" in result.output
        assert result.output.rstrip().endswith("OK")


def test_server_probe_json_output(app, tmp_path):
    stub = _write_stub(tmp_path, "stub-mcp")
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "probe", "--json", stub])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is True
        assert payload["serverInfo"]["name"] == "stub-mcp-none"
        assert payload["tools"][0]["name"] == "ping"
        assert payload["resources"][0]["uri"] == "stub://config"
        assert payload["prompts"][0]["name"] == "hello"


def test_server_probe_set_env_and_args_reach_server(app, tmp_path):
    stub = _write_stub(tmp_path, "stub-mcp")
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(
            args=["server", "probe", "--set-env", "STUB_MARKER=xyz", stub, "--flag", "value"]
        )
        assert result.exit_code == 0, result.output
        assert "stub-mcp-xyz/--flag/value" in result.output


def test_server_probe_crashing_command_fails(app, tmp_path):
    stub = _write_stub(tmp_path, "crash-mcp", CRASH_STUB)
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "probe", stub])
        assert result.exit_code == 1
        out = _output(result)
        assert "FAIL" in out
        assert "ImportError" in out  # stderr tail is shown for diagnosis


def test_server_probe_missing_command_fails(app):
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "probe", "/nonexistent/mcp-server-xyz"])
        assert result.exit_code == 1
        assert "not found or not executable" in _output(result)


def test_server_probe_timeout_fails(app, tmp_path):
    stub = _write_stub(tmp_path, "sleep-mcp", SLEEP_STUB)
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "probe", "--timeout", "2", stub])
        assert result.exit_code == 1
        assert "timed out" in _output(result)


def test_server_test_registered_stdio_server(app, tmp_path):
    stub = _write_stub(tmp_path, "stub-mcp")
    with app.app_context():
        server = McpServer(
            name="stub", label="Stub", transport="stdio", command=stub, enabled=True,
            env_config={"STUB_MARKER": "fromdb"},
        )
        db.session.add(server)
        db.session.commit()
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "test", "stub"])
        assert result.exit_code == 0, result.output
        # env_config from the catalog row reached the spawned server
        assert "stub-mcp-fromdb" in result.output
        assert "ping" in result.output
        assert "stub://config" in result.output


def test_server_test_unknown_server_fails(app):
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "test", "no-such-server"])
        assert result.exit_code != 0
        assert "No such MCP server" in _output(result)


def test_server_test_broken_stdio_server_fails(app, tmp_path):
    stub = _write_stub(tmp_path, "crash-mcp", CRASH_STUB)
    with app.app_context():
        server = McpServer(name="broken", label="Broken", transport="stdio", command=stub, enabled=True)
        db.session.add(server)
        db.session.commit()
        runner = app.test_cli_runner()
        result = runner.invoke(args=["server", "test", "broken"])
        assert result.exit_code == 1
        assert "FAIL" in _output(result)


def test_server_test_http_server_uses_http_probe(app):
    fake_result = {
        "serverInfo": {"name": "web-mcp", "version": "1.0"},
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}},
        "tools": [{"name": "fetch", "description": "Fetch a page"}],
        "resources": [{"uri": "https://example.test/", "name": "site"}],
        "prompts": [],
    }
    with app.app_context():
        server = McpServer(
            name="web", label="Web", transport="http", url="http://127.0.0.1:9/mcp", enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        with patch("mcprack.cli.health.probe_http_capabilities", return_value=(True, fake_result)) as mock_probe:
            runner = app.test_cli_runner()
            result = runner.invoke(args=["server", "test", "web"])
            assert result.exit_code == 0, result.output
            assert "web-mcp" in result.output
            assert "fetch" in result.output
            assert "https://example.test/" in result.output
            mock_probe.assert_called_once()
            assert mock_probe.call_args.args[0] == "http://127.0.0.1:9/mcp"
