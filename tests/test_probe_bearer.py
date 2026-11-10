"""`mcprack-mcp-probe --bearer`: probing the tokenless URL a Claude Code
.mcp.json uses. The token comes from MCPRACK_TOKEN - never from argv, where
`ps` would show it - and must never be echoed."""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

PROBE = str(Path(__file__).resolve().parent.parent / "bin" / "mcprack-mcp-probe")
TOKEN = "tok-9f2c1e7a-do-not-print"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "invalid_token"}')
            return
        results = {
            "initialize": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "fake", "version": "1"}},
            "tools/list": {"tools": [{"name": "t1"}]},
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": results.get(body.get("method"), {})}).encode())


@pytest.fixture
def backend():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/proxy/mcp/3"
    server.shutdown()


def _probe(url, *flags, token=None):
    env = {k: v for k, v in os.environ.items() if k != "MCPRACK_TOKEN"}
    if token is not None:
        env["MCPRACK_TOKEN"] = token
    return subprocess.run([sys.executable, "-I", PROBE, *flags, url], capture_output=True, text=True, env=env, timeout=30)


def test_bearer_probe_succeeds_with_the_right_token(backend):
    result = _probe(backend, "--bearer", "--tools", token=TOKEN)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "tools/list: OK" in result.stdout


def test_the_token_is_never_printed(backend):
    for flags, token in ((("--bearer",), TOKEN), (("--bearer",), "wrong-" + TOKEN)):
        result = _probe(backend, *flags, token=token)
        assert TOKEN not in result.stdout + result.stderr


def test_a_rejected_token_says_so(backend):
    result = _probe(backend, "--bearer", token="nope")

    assert result.returncode == 1
    assert "proxy:access" in result.stdout


def test_without_bearer_the_401_hint_points_at_the_flag(backend):
    result = _probe(backend)

    assert result.returncode == 1
    assert "--bearer" in result.stdout


def test_bearer_without_the_environment_variable_is_a_usage_error(backend):
    result = _probe(backend, "--bearer")

    assert result.returncode == 2
    assert "MCPRACK_TOKEN" in result.stdout
