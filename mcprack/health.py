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
import select
import shutil
import signal
import socket
import subprocess
import tempfile
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


# The streamable-HTTP MCP transport (what fastmcp's proxy speaks - see
# user_proxy.py's _spawn) rejects any request whose Accept header doesn't
# list *both* of these, and replies to `initialize` with a session id that
# every subsequent request in the same session must echo back in this
# header - both requirements come straight from a live 406/400 observed
# against a real server, not from the spec alone.
_MCP_ACCEPT = "application/json, text/event-stream"
_MCP_SESSION_HEADER = "mcp-session-id"


def _parse_mcp_body(raw):
    """The same transport can reply with a plain JSON body or a single SSE
    event wrapping the identical JSON payload in a `data:` line, depending
    on how the server negotiates the response - a plain json.loads() alone
    fails on the latter with a JSONDecodeError."""
    text = raw.strip()
    if text.startswith("event:") or text.startswith("data:"):
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                return json.loads(line[len("data:"):].strip())
        raise ValueError("SSE response had no data: line")
    return json.loads(text)


def _connection(host, port, timeout, https=False):
    cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
    return cls(host, port, timeout=timeout)


def _send_jsonrpc_request(
    host, port, method, params=None, timeout=5.0, session_id=None,
    path="/mcp", https=False, extra_headers=None,
):
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

    headers = {"Content-Type": "application/json", "Accept": _MCP_ACCEPT}
    if session_id:
        headers[_MCP_SESSION_HEADER] = session_id
    if extra_headers:
        headers.update(extra_headers)

    try:
        conn = _connection(host, port, timeout, https)
        conn.request("POST", path, body=payload, headers=headers)
        response = conn.getresponse()
        data = response.read().decode('utf-8')
        conn.close()

        if response.status != 200:
            return False, f"HTTP {response.status}: {data}"

        try:
            result = _parse_mcp_body(data)
            if "error" in result:
                err = result["error"]
                if isinstance(err, dict):
                    code = err.get("code")
                    message = err.get("message", str(err))
                    return False, f"MCP Error {code}: {message}" if code is not None else f"MCP Error: {message}"
                return False, f"MCP Error: {err}"
            if "result" in result:
                return True, result["result"]
            return False, f"Unexpected response: {data}"
        except (json.JSONDecodeError, ValueError):
            return False, f"Invalid JSON response: {data}"
    except (socket.timeout, OSError) as e:
        return False, f"Connection failed: {e}"


def probe_tools(host, port, timeout=8.0, path="/mcp", https=False, extra_headers=None):
    """Deep liveness check: initialize, then tools/list, against a local
    fastmcp proxy instance. Returns (ok, tool_count, error).

    A fastmcp stdio proxy answers `initialize` on its own and only talks
    to the wrapped backend lazily, so a backend that crashes on import
    still gets a green handshake - and then `tools/list` comes back empty
    (fastmcp only logs "Connection closed"). An empty tool list is
    therefore treated as a failure here.
    """
    deadline = time.monotonic() + timeout
    try:
        conn = _connection(host, port, timeout, https)
        init_headers = {"Content-Type": "application/json", "Accept": _MCP_ACCEPT}
        if extra_headers:
            init_headers.update(extra_headers)
        conn.request("POST", path, body=json.dumps({
            "jsonrpc": "2.0",
            "id": "mcprack-probe-init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcprack-probe", "version": "1.0"},
            },
        }).encode("utf-8"), headers=init_headers)
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        session_id = response.getheader(_MCP_SESSION_HEADER)
        conn.close()
        if response.status != 200:
            return False, 0, f"initialize returned HTTP {response.status}"
        init_response = _parse_mcp_body(raw)
    except (socket.timeout, OSError, http.client.HTTPException, ValueError) as exc:
        return False, 0, f"initialize failed: {exc}"
    if "error" in init_response:
        return False, 0, "initialize returned a JSON-RPC error"

    remaining = deadline - time.monotonic()
    if remaining <= 0.2:
        return False, 0, "timed out before tools/list"
    success, data = _send_jsonrpc_request(
        host, port, "tools/list", {}, timeout=remaining, session_id=session_id,
        path=path, https=https, extra_headers=extra_headers,
    )
    if not success:
        return False, 0, str(data)[:200]
    tools = data.get("tools", []) if isinstance(data, dict) else []
    if not tools:
        return False, 0, "backend serves no tools (it probably crashed on startup)"
    return True, len(tools), None


def get_server_capabilities(host, port, timeout=8.0):
    """Query an MCP server for its list of tools and resources.

    First initializes the connection via handshake, then requests tools/list
    and resources/list (reusing the session id the handshake returned -
    the streamable-HTTP transport rejects follow-up requests without it).
    Returns a dict with 'tools' and 'resources' keys, or None on failure.
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
            "Accept": _MCP_ACCEPT,
        })
        response = conn.getresponse()
        raw = response.read().decode('utf-8')
        session_id = response.getheader(_MCP_SESSION_HEADER)
        conn.close()

        init_response = _parse_mcp_body(raw)
        if "error" in init_response:
            return None
    except (socket.timeout, OSError, json.JSONDecodeError, ValueError):
        return None

    # Step 2: Get tools list
    tools = []
    remaining = deadline - time.monotonic()
    if remaining > 0.5:
        success, data = _send_jsonrpc_request(
            host, port, "tools/list", {}, timeout=remaining, session_id=session_id
        )
        if success and isinstance(data, dict):
            tools = data.get("tools", [])

    # Step 3: Get resources list
    resources = []
    remaining = deadline - time.monotonic()
    if remaining > 0.5:
        success, data = _send_jsonrpc_request(
            host, port, "resources/list", {}, timeout=remaining, session_id=session_id
        )
        if success and isinstance(data, dict):
            resources = data.get("resources", [])

    return {
        "tools": tools,
        "resources": resources,
    }


# ---------------------------------------------------------------------------
# Full capability probes (used by the CLI `server test` / `server probe`
# commands and reusable by the web UI). Unlike the checks above, these speak
# the MCP protocol all the way to listing what the server offers, so they
# catch a server that starts but is broken at runtime (e.g. a missing
# dependency that crashes on import makes the process exit before answering).
# ---------------------------------------------------------------------------

_PROBE_PROTOCOL_VERSION = "2024-11-05"
_PROBE_CLIENT_INFO = {"name": "mcprack-cli", "version": "1.0"}
_LIST_METHODS = (
    ("tools/list", "tools"),
    ("resources/list", "resources"),
    ("prompts/list", "prompts"),
)


def _empty_capability_result(init_result):
    return {
        "serverInfo": init_result.get("serverInfo", {}),
        "protocolVersion": init_result.get("protocolVersion"),
        "capabilities": init_result.get("capabilities", {}),
        "tools": [],
        "resources": [],
        "prompts": [],
    }


def _list_call_error(method, error):
    """A JSON-RPC error on one of the list calls. -32601 (method not found)
    just means the server does not implement that capability - that is an
    empty list, not a probe failure; anything else is a real failure."""
    if isinstance(error, dict) and error.get("code") == -32601:
        return None
    if isinstance(error, dict):
        return f"{method} returned a JSON-RPC error: {error.get('message', error)}"
    return f"{method} returned a JSON-RPC error: {error}"


def probe_stdio_capabilities(command, args=None, env=None, timeout=15.0):
    """Spawn a stdio MCP server and ask it what it provides.

    Speaks the MCP stdio transport (newline-delimited JSON-RPC on the
    child's stdin/stdout) directly: initialize handshake,
    notifications/initialized, then tools/list, resources/list and
    prompts/list. Returns (ok, result) - result is a dict with
    serverInfo/protocolVersion/capabilities/tools/resources/prompts on
    success, or an error string on failure.

    Deliberately stdlib-only (like bin/mcprack-mcp-probe): the point is to
    test the *server's* own runtime, so the probe itself must not depend on
    the very libraries it is checking - a broken python3-fastmcp makes the
    spawned server crash on import, which surfaces here as EOF/timeout.
    """
    if not command:
        return False, "No command configured."
    if not check_stdio_command(command):
        return False, f"Command not found or not executable: '{command}'."

    full_env = dict(os.environ)
    if env:
        full_env.update(env)

    deadline = time.monotonic() + timeout
    buffer = b""

    # stderr goes to a temp file, not a PIPE: a chatty server must never
    # block on a full pipe while we are waiting on stdout.
    with tempfile.TemporaryFile(mode="w+b") as stderr_file:
        try:
            proc = subprocess.Popen(
                [command, *(args or [])],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                env=full_env,
                start_new_session=True,
            )
        except OSError as exc:
            return False, f"Could not start '{command}': {exc}"

        def _stderr_tail(max_lines=10):
            try:
                stderr_file.seek(0)
                text = stderr_file.read().decode("utf-8", "replace").strip()
            except OSError:
                return ""
            return "\n".join(text.splitlines()[-max_lines:])

        def _read_message():
            # One newline-delimited JSON-RPC message from the server's
            # stdout; non-JSON lines (log output) are skipped. Raw os.read
            # after select() so a buffered reader can never hide a complete
            # line inside its own buffer. Raises TimeoutError/EOFError.
            nonlocal buffer
            while True:
                newline = buffer.find(b"\n")
                if newline >= 0:
                    line, buffer = buffer[:newline], buffer[newline + 1:]
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        return json.loads(line)
                    except ValueError:
                        continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"timed out after {timeout:.0f}s waiting for the server to answer"
                    )
                ready, _, _ = select.select([proc.stdout.fileno()], [], [], remaining)
                if not ready:
                    raise TimeoutError(
                        f"timed out after {timeout:.0f}s waiting for the server to answer"
                    )
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    raise EOFError("server closed its stdout (it exited or crashed)")
                buffer += chunk

        def _request(method, params, request_id):
            payload = json.dumps(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            )
            try:
                proc.stdin.write((payload + "\n").encode("utf-8"))
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise EOFError(f"could not write to the server's stdin: {exc}")
            while True:
                message = _read_message()
                if message.get("id") != request_id:
                    continue  # a notification or an unrelated message
                return message

        def _notify(method):
            try:
                proc.stdin.write(
                    (json.dumps({"jsonrpc": "2.0", "method": method}) + "\n").encode("utf-8")
                )
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

        try:
            init = _request(
                "initialize",
                {
                    "protocolVersion": _PROBE_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": _PROBE_CLIENT_INFO,
                },
                request_id=1,
            )
            if "error" in init:
                return False, _list_call_error("initialize", init["error"]) or (
                    f"initialize returned a JSON-RPC error: {init['error']}"
                )
            result = _empty_capability_result(init.get("result") or {})

            # Required by the spec before any other request.
            _notify("notifications/initialized")

            for offset, (method, key) in enumerate(_LIST_METHODS, start=2):
                response = _request(method, {}, request_id=offset)
                if "error" in response:
                    error = _list_call_error(method, response["error"])
                    if error:
                        return False, error
                    continue
                payload = response.get("result") or {}
                result[key] = payload.get(key, [])
            return True, result
        except (TimeoutError, EOFError) as exc:
            detail = str(exc)
            tail = _stderr_tail()
            if tail:
                detail += f"\nlast stderr lines:\n{tail}"
            return False, detail
        finally:
            # A stdio server exits when stdin closes; give it a moment,
            # then SIGTERM/SIGKILL the whole process group (start_new_session
            # made the child a group leader) so no grandchildren linger.
            try:
                if proc.stdin:
                    proc.stdin.close()
            except OSError:
                pass
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        pass


def probe_http_capabilities(url, timeout=15.0, extra_headers=None):
    """Same probe as probe_stdio_capabilities, but against a streamable-HTTP
    MCP endpoint: initialize (keeping the returned session id, which every
    follow-up request must echo), notifications/initialized, then
    tools/list, resources/list, prompts/list. Returns (ok, result|error).
    """
    if not url:
        return False, "No URL configured."
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    if not host:
        return False, f"URL has no host: '{url}'."
    port = parts.port or (443 if parts.scheme == "https" else 80)
    https = parts.scheme == "https"
    path = parts.path or "/mcp"

    deadline = time.monotonic() + timeout

    def _remaining():
        return deadline - time.monotonic()

    # initialize first, capturing the session id the transport requires on
    # every subsequent request (same pattern as probe_tools above).
    try:
        conn = _connection(host, port, timeout, https)
        init_headers = {"Content-Type": "application/json", "Accept": _MCP_ACCEPT}
        if extra_headers:
            init_headers.update(extra_headers)
        conn.request(
            "POST",
            path,
            body=json.dumps({
                "jsonrpc": "2.0",
                "id": "mcprack-cli-init",
                "method": "initialize",
                "params": {
                    "protocolVersion": _PROBE_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": _PROBE_CLIENT_INFO,
                },
            }).encode("utf-8"),
            headers=init_headers,
        )
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        session_id = response.getheader(_MCP_SESSION_HEADER)
        conn.close()
        if response.status != 200:
            return False, f"initialize returned HTTP {response.status}: {raw[:300]}"
        init_response = _parse_mcp_body(raw)
    except (socket.timeout, OSError, http.client.HTTPException, ValueError) as exc:
        return False, f"initialize failed: {exc}"
    if "error" in init_response:
        return False, _list_call_error("initialize", init_response["error"]) or (
            f"initialize returned a JSON-RPC error: {init_response['error']}"
        )
    result = _empty_capability_result(init_response.get("result") or {})

    # notifications/initialized (no id -> no response expected); best effort,
    # some minimal servers reject everything until they see it, others
    # don't care.
    try:
        conn = _connection(host, port, max(_remaining(), 0.5), https)
        notify_headers = {"Content-Type": "application/json", "Accept": _MCP_ACCEPT}
        if session_id:
            notify_headers[_MCP_SESSION_HEADER] = session_id
        if extra_headers:
            notify_headers.update(extra_headers)
        conn.request(
            "POST",
            path,
            body=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode("utf-8"),
            headers=notify_headers,
        )
        conn.getresponse().read()
        conn.close()
    except (socket.timeout, OSError, http.client.HTTPException):
        pass

    for method, key in _LIST_METHODS:
        remaining = _remaining()
        if remaining <= 0.2:
            return False, f"timed out after {timeout:.0f}s before {method}"
        success, data = _send_jsonrpc_request(
            host, port, method, {}, timeout=remaining, session_id=session_id,
            path=path, https=https, extra_headers=extra_headers,
        )
        if not success:
            # _send_jsonrpc_request flattens JSON-RPC errors to
            # "MCP Error <code>: <message>"; -32601 (method not found) just
            # means the server does not implement that capability.
            text = str(data)
            if "-32601" in text:
                continue
            return False, f"{method} failed: {text[:300]}"
        payload = data if isinstance(data, dict) else {}
        result[key] = payload.get(key, [])
    return True, result

