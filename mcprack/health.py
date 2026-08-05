"""Best-effort, side-effect-free health checks for the admin servers list:
can the stdio command actually be found/executed, and is the http/sse
endpoint's host:port reachable at all? Neither check speaks MCP itself (no
handshake) — they only rule out the obvious "this will definitely not
start" cases without needing to actually spawn a process or hold Vaultwarden
credentials.
"""

import os
import shutil
import socket
import subprocess
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
