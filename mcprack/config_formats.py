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


def _normalized_url(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.lower() in {"none", "null"}:
        return None
    return text


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


def _network_entry(server):
    url = _normalized_url(server.get("url"))
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


def _render(servers, include_stdio_type):
    """Render servers as client config entries.

    Every server is expected to carry a `url` by the time it reaches this
    module — callers resolve per-user proxy URLs for stdio-implemented
    servers upstream (see catalog.py). A server with no url at all falls
    back to a local stdio spawn entry, purely as a defensive default for
    direct/test use of this module.
    """
    result = {}
    for server in servers:
        if _normalized_url(server.get("url")):
            result[server["name"]] = _network_entry(server)
        else:
            result[server["name"]] = _stdio_entry(server, include_stdio_type)
    return result


def render_claude_config(servers):
    return {"mcpServers": _render(servers, include_stdio_type=True)}


# The environment variable a Claude Code configuration reads the credential
# from. Claude Code reads credential-looking names (ANTHROPIC_API_KEY,
# NPM_TOKEN, HTTPS_PROXY, ...) as empty inside the url/headers of a remote
# server, so this one is deliberately our own.
CLAUDE_CODE_TOKEN_VARIABLE = "MCPRACK_TOKEN"


def render_claude_code_config(servers, header=True):
    """A Claude Code `.mcp.json`: remote HTTP servers whose URL carries NO
    secret. With `header` the credential is `Authorization: Bearer
    ${MCPRACK_TOKEN}`, expanded by Claude Code from the environment - the file
    can be committed. Without it (OAuth) Claude Code runs the login itself."""
    result = {}
    for server in servers:
        entry = {"type": "http", "url": _normalized_url(server.get("url"))}
        if header:
            entry["headers"] = {"Authorization": f"Bearer ${{{CLAUDE_CODE_TOKEN_VARIABLE}}}"}
        result[server["name"]] = entry
    return {"mcpServers": result}


def claude_code_commands(servers, header=True, scope="user"):
    """`claude mcp add` command lines equivalent to the `.mcp.json`. Every
    value is shell-quoted; the header is double-quoted so the user's own shell
    expands $MCPRACK_TOKEN when they run it."""
    import shlex

    lines = []
    for server in servers:
        command = [
            "claude", "mcp", "add", "--transport", "http", "--scope", scope,
            shlex.quote(server["name"]), shlex.quote(server["url"]),
        ]
        line = " ".join(command)
        if header:
            line += f' --header "Authorization: Bearer ${CLAUDE_CODE_TOKEN_VARIABLE}"'
        lines.append(line)
    return lines


def render_copilot_config(servers):
    return {"servers": _render(servers, include_stdio_type=False)}
