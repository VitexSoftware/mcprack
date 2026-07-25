"""Pure, framework-free renderers for MCP client config files.

Callers pass a list of plain dicts (already resolved — enabled-filtering and
Vaultwarden secret resolution both happen upstream in catalog.py) shaped as:

    {
        "name": str,
        "transport": "stdio" | "http" | "sse",  # how the server is actually run
        "command": str | None,          # stdio — only used as a fallback, see below
        "args": list[str],              # stdio
        "url": str | None,              # network endpoint, if one exists
        "auth_header_name": str | None, # network
        "auth_env_key": str | None,     # network — which key in `env` holds the token
        "env": dict[str, str],          # merged default+override values
    }

`transport` records how the underlying MCP server communicates, but that's an
implementation detail of the admin's deployment — it does not by itself
determine what a remote user gets. Both stdio-implemented and natively
network-native servers are meant to be reachable over the network the same
way (e.g. a stdio server proxied via mcp_rack's fastmcp proxy is just as
network-accessible as one that speaks HTTP directly). So: whenever `url` is
set, every entry — regardless of `transport` — is rendered as a network
entry. Only a server with no `url` at all (a stdio tool meant to be spawned
directly on the user's own machine, with nothing proxying it) falls back to
a local stdio spawn command.

No Flask, DB, or Vaultwarden imports here — keeps this trivially unit-testable.
"""

_NETWORK_TYPES = {"http", "sse"}


def _stdio_entry(server, include_type):
    entry = {}
    if include_type:
        entry["type"] = "stdio"
    entry["command"] = server["command"]
    entry["args"] = server.get("args") or []
    env = server.get("env") or {}
    if env:
        entry["env"] = env
    return entry


def _network_entry(server, proxy_url=None):
    """Render a server as a network entry.
    
    If proxy_url is provided (e.g. "http://10.11.182.99:3100/mcp"), use that
    instead of server["url"] — this handles proxied stdio servers.
    """
    url = proxy_url or server["url"]
    network_type = server["transport"] if server["transport"] in _NETWORK_TYPES else "http"
    entry = {
        "type": network_type,
        "url": url,
    }
    header_name = server.get("auth_header_name")
    auth_key = server.get("auth_env_key")
    env = server.get("env") or {}
    if header_name and auth_key and auth_key in env:
        entry["headers"] = {header_name: env[auth_key]}
    return entry


def _render(servers, include_stdio_type, proxy_host=None, proxy_port=3100):
    """Render servers as client config entries.
    
    Args:
        servers: List of server dicts
        include_stdio_type: Whether to include "type": "stdio" in entries
        proxy_host: If set (e.g. "10.11.182.99"), proxied stdio servers become HTTP
        proxy_port: Port for proxy endpoint (default 3100)
    
    Logic:
    - If server has url, use _network_entry with that url
    - Else if proxy_host is set and server has command, use _network_entry with proxy url
    - Else use _stdio_entry (local spawn)
    """
    result = {}
    proxy_url = f"http://{proxy_host}:{proxy_port}/mcp" if proxy_host else None
    
    for server in servers:
        if server.get("url"):
            result[server["name"]] = _network_entry(server)
        elif proxy_url and server.get("command"):
            # Proxied stdio server: expose via fastmcp
            result[server["name"]] = _network_entry(server, proxy_url=proxy_url)
        else:
            # Local stdio server
            result[server["name"]] = _stdio_entry(server, include_stdio_type)
    return result


def render_claude_config(servers, proxy_host=None, proxy_port=3100):
    return {"mcpServers": _render(servers, include_stdio_type=True, proxy_host=proxy_host, proxy_port=proxy_port)}


def render_copilot_config(servers, proxy_host=None, proxy_port=3100):
    return {"servers": _render(servers, include_stdio_type=False, proxy_host=proxy_host, proxy_port=proxy_port)}
