"""Best-effort, side-effect-free health checks for the admin servers list:
can the stdio command actually be found/executed, and is the http/sse
endpoint's host:port reachable at all? Neither check speaks MCP itself (no
handshake) — they only rule out the obvious "this will definitely not
start" cases without needing to actually spawn a process or hold Vaultwarden
credentials.
"""

import http.client
import json
import os
import shutil
import socket
import subprocess
import time
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


def check_stdio_command(command):
    if not command:
        return False
    if "/" in command:
        return os.path.isfile(command) and os.access(command, os.X_OK)
    return shutil.which(command) is not None


def check_http_reachable(url, timeout=1.5):
    if not url:
        return False
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return False
    port = parts.port or DEFAULT_PORTS.get(parts.scheme, 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_stdio_startup(command, args=None, env=None, timeout=2.0):
    """Actually try to start a stdio command and see if it survives its own
    import/startup phase — `check_stdio_command` alone only proves the file
    exists and is executable, not that it actually runs (a missing runtime
    dependency, e.g., produces exactly this: a valid, executable script
    that crashes on the first line of real code).

    Unlike the rest of this module, this has a real (bounded, brief) side
    effect: it spawns the real process for up to `timeout` seconds with
    stdin closed. Only call this on-demand (an admin "Test" action), never
    automatically on every page load.

    Returns (ok: bool, detail: str).
    """
    if not command:
        return False, "No command configured."

    full_env = dict(os.environ)
    if env:
        full_env.update(env)

    try:
        proc = subprocess.Popen(
            [command, *(args or [])],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=full_env,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        return False, f"Could not start '{command}': {exc}"

    try:
        _, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Still running after the grace period — for an MCP stdio server
        # this is the expected, healthy state (it's waiting on stdin for a
        # JSON-RPC request that will never come from this probe).
        proc.kill()
        proc.communicate()
        return True, f"Started and was still running after {timeout:.0f}s (expected for a stdio server waiting on input)."

    if proc.returncode == 0:
        return True, "Exited cleanly (return code 0)."

    tail = "\n".join((stderr or "").strip().splitlines()[-5:])
    detail = f"Exited with code {proc.returncode} within {timeout:.0f}s — likely broken."
    if tail:
        detail += f"\n{tail}"
    return False, detail


def check_reachable(server):
    """server: anything with .command, .url (duck-typed — works with
    McpServer instances without importing models here).

    A server with a network `url` is reachable the same way regardless of
    how it's actually implemented (native http/sse, or a stdio server
    proxied onto the network e.g. via mcp_rack) — only a server with no url
    at all falls back to checking whether its local stdio command exists."""
    if server.url:
        return check_http_reachable(server.url)
    return check_stdio_command(server.command)


def _send_jsonrpc_request(host, port, method, params=None, timeout=5.0):
    """Send a JSON-RPC request to an MCP server and return the response.
    
    Returns (success: bool, data: dict or str).
    On success, data is the response object (tools/resources list, etc).
    On error, data is an error message string.
    """
    request_id = f"mcprack-{method}"
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params or {},
    }).encode('utf-8')
    
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("POST", "/mcp", body=payload, headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        response = conn.getresponse()
        data = response.read().decode('utf-8')
        conn.close()
        
        if response.status != 200:
            return False, f"HTTP {response.status}: {data}"
        
        try:
            result = json.loads(data)
            if "error" in result:
                return False, f"MCP Error: {result['error'].get('message', str(result['error']))}"
            if "result" in result:
                return True, result["result"]
            return False, f"Unexpected response: {data}"
        except json.JSONDecodeError:
            return False, f"Invalid JSON response: {data}"
    except (socket.timeout, OSError) as e:
        return False, f"Connection failed: {e}"


def get_server_capabilities(host, port, timeout=8.0):
    """Query an MCP server for its list of tools and resources.
    
    First initializes the connection via handshake, then requests tools/list
    and resources/list. Returns a dict with 'tools' and 'resources' keys,
    or None on failure.
    """
    # Step 1: Initialize handshake
    init_payload = json.dumps({
        "jsonrpc": "2.0",
        "id": "mcprack-init",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcprack-admin", "version": "1.0"},
        }
    }).encode('utf-8')
    
    deadline = time.monotonic() + timeout
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("POST", "/mcp", body=init_payload, headers={
            "Content-Type": "application/json",
        })
        response = conn.getresponse()
        init_response = json.loads(response.read().decode('utf-8'))
        conn.close()
        
        if "error" in init_response:
            return None
    except (socket.timeout, OSError, json.JSONDecodeError):
        return None
    
    # Step 2: Get tools list
    tools = []
    remaining = deadline - time.monotonic()
    if remaining > 0.5:
        success, data = _send_jsonrpc_request(
            host, port, "tools/list", {}, timeout=remaining
        )
        if success and isinstance(data, dict):
            tools = data.get("tools", [])
    
    # Step 3: Get resources list
    resources = []
    remaining = deadline - time.monotonic()
    if remaining > 0.5:
        success, data = _send_jsonrpc_request(
            host, port, "resources/list", {}, timeout=remaining
        )
        if success and isinstance(data, dict):
            resources = data.get("resources", [])
    
    return {
        "tools": tools,
        "resources": resources,
    }

