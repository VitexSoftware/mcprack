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
