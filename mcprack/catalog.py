import json
import http.client
import logging
import socket
import time
from urllib.parse import urlsplit

import hashlib
from datetime import datetime, timezone

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from . import appstream_icons
from . import audit
from . import env_detection
from . import health
from . import secret_store
from . import telemetry
from . import user_proxy
from . import vaultwarden
from .config_formats import render_claude_config, render_copilot_config
from .extensions import csrf, db
from .models import (
    ApiToken,
    McpServer,
    User,
    UserServerOverride,
    UserServerPermission,
    UserServerSelection,
)

bp = Blueprint("catalog", __name__)
logger = logging.getLogger(__name__)

RENDERERS = {
    "claude": (render_claude_config, "claude_desktop_config.json"),
    "copilot": (render_copilot_config, "mcp.json"),
    # Cursor uses the Claude-shaped mcpServers map; VS Code Copilot uses
    # the servers map. Aliases so /download/cursor and /api/.../config/vscode
    # exist for the dedicated sync utilities.
    "cursor": (render_claude_config, "mcp.json"),
    "vscode": (render_copilot_config, "mcp.json"),
}

PROXY_TOKEN_SALT = "mcprack-user-proxy"


def _proxy_serializer():
    from flask import current_app

    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=PROXY_TOKEN_SALT)


def _make_proxy_token(user_id, server_id):
    return _proxy_serializer().dumps({"u": user_id, "s": server_id})


def _parse_proxy_token(token):
    from flask import current_app

    # PROXY_TOKEN_MAX_AGE is None by default (see config.py) - itsdangerous
    # treats max_age=None as "no expiry check", so a config URL keeps
    # working until the user's config is regenerated or SECRET_KEY rotates.
    max_age = current_app.config["PROXY_TOKEN_MAX_AGE"]
    try:
        return _proxy_serializer().loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None


# Bounded well under gunicorn's worker timeout (30s), so a dead or
# crash-looping upstream produces a clean JSON-RPC error response instead
# of hanging the whole worker (and, transitively, every other request
# queued behind it) until the worker gets killed.
_PROXY_REQUEST_TIMEOUT = 10  # seconds
_PROXY_STREAM_IDLE_TIMEOUT = 60


def _jsonrpc_request_id(body):
    try:
        data = json.loads(body) if body else None
    except ValueError:
        return None
    return data.get("id") if isinstance(data, dict) else None


def _jsonrpc_error_response(request_id, message, status=502):
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": message}}
    ).encode()
    return Response(payload, status=status, mimetype="application/json")


def _is_empty_tools_list(request_body, payload):
    """True when a `tools/list` request was answered successfully but with
    no tools at all. A fastmcp stdio proxy does exactly this when the
    wrapped backend crashes (the failure is only logged upstream), so it is
    worth its own telemetry result and log line instead of a plain
    "success"."""
    if b"tools/list" not in request_body:
        return False
    try:
        data = health._parse_mcp_body(payload.decode("utf-8", errors="replace"))
    except ValueError:
        return False
    result = data.get("result") if isinstance(data, dict) else None
    return isinstance(result, dict) and result.get("tools") == []


def _relay_request(conn, path, extra_headers=None, server_name=None, transport="http"):
    """Forward the current Flask request onto an already-open http.client
    connection at `path`, and translate the upstream response (or a
    connection failure) back into a Flask Response. Shared by both proxy
    styles below - a per-user spawned stdio backend (always local to this
    mcprack host, 127.0.0.1:<ephemeral port>) and a fixed network backend
    (mcp_rack's shared fastmcp proxy - which may run on an entirely
    different host than mcprack itself - or a genuinely network-native MCP
    server) - so both get the same timeout, header-stripping, and telemetry
    handling."""
    body = request.get_data()
    headers = {}
    for key, value in request.headers.items():
        key_lower = key.lower()
        if key_lower in {
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "cookie",
        }:
            continue
        headers[key] = value
    if extra_headers:
        headers.update(extra_headers)

    start_time = time.monotonic()
    streaming = False
    with telemetry.span(
        "mcp.server.call", {"server_name": server_name, "transport": transport}
    ) as current_span:
        try:
            conn.request(request.method, path, body=body, headers=headers)
            upstream = conn.getresponse()
            content_type = upstream.getheader("Content-Type")
            is_sse = isinstance(content_type, str) and content_type.split(";", 1)[0].strip().lower() == "text/event-stream"
            if is_sse:
                if conn.sock is not None:
                    conn.sock.settimeout(_PROXY_STREAM_IDLE_TIMEOUT)

                def stream_response():
                    try:
                        while True:
                            chunk = upstream.read1(65536)
                            if not chunk:
                                break
                            yield chunk
                    except (OSError, http.client.HTTPException):
                        logger.warning("MCP stream for '%s' disconnected", server_name)
                    finally:
                        conn.close()

                payload = b""
                response = Response(stream_response(), status=upstream.status)
                response.call_on_close(conn.close)
                streaming = True
            else:
                payload = upstream.read()
                response = Response(payload, status=upstream.status)

            for key, value in upstream.getheaders():
                key_lower = key.lower()
                if key_lower in {"transfer-encoding", "connection", "keep-alive"}:
                    continue
                if is_sse and key_lower == "content-length":
                    continue
                response.headers[key] = value
            if is_sse:
                response.headers["X-Accel-Buffering"] = "no"

            result = "success" if upstream.status < 400 else "error"
            if result == "success" and _is_empty_tools_list(body, payload):
                result = "empty_tools"
                logger.warning(
                    "MCP server '%s' answered tools/list with no tools - its backend is "
                    "probably failing to start",
                    server_name,
                )
            telemetry.record_mcp_server_call(
                server_name, transport, result, time.monotonic() - start_time
            )
            if current_span is not None:
                current_span.set_attribute("mcp.result", result)
            return response
        except (socket.timeout, OSError, http.client.HTTPException) as exc:
            telemetry.record_mcp_server_call(
                server_name, transport, "error", time.monotonic() - start_time
            )
            if current_span is not None:
                current_span.set_attribute("mcp.result", "error")
            return _jsonrpc_error_response(
                _jsonrpc_request_id(body),
                f"Upstream MCP server did not respond within {_PROXY_REQUEST_TIMEOUT}s: {exc}",
            )
        finally:
            if not streaming:
                conn.close()


def _forward_to_user_proxy(port, server_name=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=_PROXY_REQUEST_TIMEOUT)
    return _relay_request(conn, "/mcp", server_name=server_name, transport="stdio")


def _forward_to_backend_url(url, env, server):
    """Relay to a server that already has a fixed network `url` of its own -
    either a genuinely network-native MCP server, or one of mcp_rack's
    shared fastmcp proxies (see spojeitisac/roles/mcp_rack), which is very
    often NOT on this same host - mcprack only needs network reachability
    to it, not colocation. Unlike the per-user spawn path above, there's no
    per-user process to manage: we just open a connection to `url`'s own
    host:port for each request. Any configured auth header is injected
    here, server-side, from `env` - never handed to the end user, same
    rationale as the per-user proxy path above (see
    _build_client_config_json's docstring)."""
    parts = urlsplit(url)
    scheme = parts.scheme or "http"
    host = parts.hostname
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    extra_headers = {}
    header_name = server.auth_header_name
    auth_key = server.auth_env_key
    if header_name and auth_key and env.get(auth_key):
        extra_headers[header_name] = env[auth_key]

    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=_PROXY_REQUEST_TIMEOUT)
    return _relay_request(
        conn, path, extra_headers=extra_headers, server_name=server.name, transport=server.transport
    )


def _allowed_enabled_server_ids(user_id):
    from flask import current_app

    enabled_ids = {s.id for s in McpServer.query.filter_by(enabled=True).all()}
    permission_rows = UserServerPermission.query.filter_by(user_id=user_id).all()
    if not permission_rows:
        if current_app.config["STRICT_SERVER_PERMISSIONS"]:
            return set()
        return enabled_ids

    allowed = {row.server_id for row in permission_rows if row.is_allowed}
    return enabled_ids & allowed


@bp.route("/")
@login_required
def index():
    allowed_ids = _allowed_enabled_server_ids(current_user.id)
    servers = (
        McpServer.query.filter(McpServer.id.in_(allowed_ids))
        .order_by(McpServer.category, McpServer.name)
        .all()
        if allowed_ids
        else []
    )
    selected_ids = {
        row.server_id
        for row in UserServerSelection.query.filter_by(user_id=current_user.id).all()
    }
    override_ids = {
        row.server_id
        for row in UserServerOverride.query.filter_by(user_id=current_user.id).all()
    }
    connectors = _selected_server_connectors(current_user)
    server_connectors = {
        server.id: _server_connector(current_user, server) for server in servers
    }
    return render_template(
        "catalog.html",
        servers=servers,
        selected_ids=selected_ids,
        override_ids=override_ids,
        connectors=connectors,
        server_connectors=server_connectors,
    )


@bp.route("/icon/server/<int:server_id>")
@login_required
def server_icon(server_id):
    server = db.get_or_404(McpServer, server_id)
    icon_path = appstream_icons.resolve_server_icon_path(server)
    if not appstream_icons.is_safe_icon_path(icon_path):
        return redirect(url_for("static", filename="mcprack-app-icon.svg"))
    return send_file(icon_path)


def _external_proxy_url(endpoint, **kwargs):
    """Absolute URL for a relay endpoint, preferring PUBLIC_BASE_URL over
    whatever the request happens to carry. Behind a reverse proxy the
    request's own host and scheme are the internal ones, so a config
    generated from them points clients at an address they cannot reach."""
    base_url = (current_app.config.get("PUBLIC_BASE_URL") or "").rstrip("/")
    if base_url:
        rel = url_for(endpoint, **kwargs)
        return f"{base_url}{rel}"
    return url_for(endpoint, _external=True, **kwargs)


def _proxy_relay_url(user, server):
    """Per-user MCP relay URL for `server`. When OAuth is enabled the
    path token is omitted — clients authenticate with Authorization:
    Bearer instead (OAuth access token or an ApiToken with proxy:access).
    Path-token URLs remain valid either way for clients that still embed
    them."""
    if current_app.config.get("OAUTH_ENABLED"):
        return _external_proxy_url(
            "catalog.user_proxy_mcp_oauth",
            server_id=server.id,
        )
    token = _make_proxy_token(user.id, server.id)
    return _external_proxy_url(
        "catalog.user_proxy_mcp",
        token=token,
        server_id=server.id,
    )


def _resolve_bearer_proxy_user():
    """Authenticate an MCP proxy request from Authorization: Bearer.

    Accepts either an OAuth access token minted by /oauth/token (scope
    ``mcp``) or a personal ApiToken that allows ``proxy:access`` (or is
    unrestricted). Returns the User, or None when the header is missing
    / invalid — callers decide between 401 (OAuth challenge) and 403."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    raw = auth_header[len("Bearer ") :].strip()
    if not raw:
        return None

    if current_app.config.get("OAUTH_ENABLED"):
        from . import oauth

        user = oauth.resolve_oauth_bearer_user(raw)
        if user is not None:
            return user

    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    token = ApiToken.query.filter_by(token_hash=token_hash).first()
    if token is None or token.is_revoked or token.is_expired:
        return None
    if not token.allows_any(("proxy:access",)):
        return None
    user = db.session.get(User, token.user_id)
    if user is None or not user.is_active:
        return None
    token.last_used_at = datetime.now(timezone.utc)
    db.session.commit()
    return user


_MAX_CLIENT_ERROR_CHARS = 500


def _redact_env_values(text, env):
    """Masks every configured value in `text`. A UserProxyError carries the
    tail of the spawned server's own log, and an MCP server that logs its
    connection string or an auth failure puts the credential we injected
    straight into it - the relay answer goes back to the end user's client,
    so it must not become a credential read-back channel."""
    for value in sorted((v for v in (env or {}).values() if v and len(str(v)) > 3), key=len, reverse=True):
        text = text.replace(str(value), "***")
    return text


def _serve_user_proxy_mcp(user, server_id):
    """Shared relay body after the caller has authenticated `user` for
    `server_id` (path token or Bearer)."""
    # Housekeeping only — a cleanup failure must never take the user's
    # actual proxy request down with it. (It used to: a lock-wait timeout
    # raised out of cleanup_idle_proxies() propagated as a 500 before the
    # token was even parsed.)
    try:
        user_proxy.cleanup_idle_proxies()
    except Exception:
        logger.exception("Idle proxy cleanup failed; continuing with the request")

    server = db.get_or_404(McpServer, server_id)
    if not server.enabled or not (server.command or server.url):
        abort(404)

    if server.id not in _allowed_enabled_server_ids(user.id):
        abort(403)

    selected = UserServerSelection.query.filter_by(user_id=user.id, server_id=server.id).first()
    if not selected:
        abort(403)

    if request.method == "GET" and (server.command or server.transport != "sse"):
        return Response(status=405, headers={"Allow": "POST, DELETE", "Cache-Control": "no-store"})

    request_id = _jsonrpc_request_id(request.get_data())

    try:
        env = secret_store.resolve_server_env(server, user=user)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        return _jsonrpc_error_response(request_id, f"Could not resolve credentials: {exc}")

    missing_required = [key for key in server.required_env_keys if not env.get(key)]
    if missing_required:
        return _jsonrpc_error_response(
            request_id,
            f"Server '{server.name}' is missing required configuration: "
            f"{', '.join(missing_required)}. Ask an admin to set it "
            "(Admin → Servers → edit), or set your own override if allowed.",
        )

    if server.command:
        for attempt in (1, 2):
            try:
                port = user_proxy.ensure_user_server_proxy(
                    user_id=user.id,
                    server_id=server.id,
                    server_name=server.name,
                    command=server.command,
                    args=server.args,
                    env=env,
                    server=server,
                )
            except user_proxy.UserProxyError as exc:
                # Redact before logging, not only before answering: the
                # exception carries the tail of the spawned server's own
                # log, so an unredacted logger call persists the credential
                # we injected. Truncation stays after it, so the log keeps
                # the whole message.
                message = _redact_env_values(str(exc), env)
                logger.error("Proxy start failed for server %s (user %s): %s", server.name, user.id, message)
                if len(message) > _MAX_CLIENT_ERROR_CHARS:
                    message = message[:_MAX_CLIENT_ERROR_CHARS] + "… (truncated; see the server log)"
                return _jsonrpc_error_response(request_id, message)

            if request.method == "GET":
                # A GET relay carries a long-lived SSE stream — holding
                # the pair lock for its whole lifetime would block reaping
                # for minutes, so GET relays stay unguarded.
                response = _forward_to_user_proxy(port, server_name=server.name)
            else:
                # Hold the pair's shared relay guard for the relay, so no
                # stop path (idle reaper, health re-probe, server
                # deletion) can SIGTERM the proxy mid-request. The guard
                # is released before a retry's re-ensure takes the
                # exclusive lock.
                with user_proxy.relay_guard(user.id, server.id):
                    response = _forward_to_user_proxy(port, server_name=server.name)
            if response.status_code != 502:
                return response
            if attempt == 1:
                # A 502 from _forward_to_user_proxy is mcprack's own
                # relay-failure response: the per-user proxy died between
                # ensure and relay (a cross-worker race with the health
                # re-probe or idle reaper, or a fastmcp crash), not an
                # upstream answer. Re-ensure — respawning the proxy if it
                # is gone — and retry the relay once. Clients retry failed
                # requests anyway; doing it here just hides the crash.
                logger.warning(
                    "Relay to user proxy for server '%s' (user %s) failed; "
                    "re-ensuring the proxy and retrying once",
                    server.name,
                    user.id,
                )
        return response

    # No command to spawn - this server already has a fixed network `url`
    # (a genuinely network-native MCP server, or one of mcp_rack's shared
    # fastmcp proxies, possibly on a different host entirely). Relay
    # straight to it instead of spawning anything.
    return _forward_to_backend_url(server.url, env, server)


@bp.route("/proxy/mcp/<token>/<int:server_id>", methods=["GET", "POST", "DELETE", "OPTIONS"])
def user_proxy_mcp(token, server_id):
    if request.method == "OPTIONS":
        return Response(status=204)

    data = _parse_proxy_token(token)
    if not data or data.get("s") != server_id:
        abort(403)

    user = db.get_or_404(User, data.get("u"))
    return _serve_user_proxy_mcp(user, server_id)


@bp.route("/proxy/mcp/<int:server_id>", methods=["GET", "POST", "DELETE", "OPTIONS"])
def user_proxy_mcp_oauth(server_id):
    """Tokenless MCP relay — requires OAUTH_ENABLED and a Bearer credential.

    MCP clients discover the Authorization Server via the 401
    WWW-Authenticate challenge / Protected Resource Metadata, complete
    the OAuth dance, then call this URL with Authorization: Bearer."""
    if request.method == "OPTIONS":
        return Response(status=204)

    if not current_app.config.get("OAUTH_ENABLED"):
        abort(404)

    user = _resolve_bearer_proxy_user()
    if user is None:
        from . import oauth

        return oauth.oauth_unauthorized_response(server_id)

    return _serve_user_proxy_mcp(user, server_id)


# Bearer-token authenticated (signed path token, or Authorization header
# when OAuth is on), not session-cookie authenticated — CSRF protection
# has nothing to add here since there's no ambient credential for a
# forged cross-site request to ride on, and remote MCP clients
# reconnecting to this URL never send one.
csrf.exempt(user_proxy_mcp)
csrf.exempt(user_proxy_mcp_oauth)


def set_user_selection(user_id, submitted_ids):
    """Replace user_id's selected servers with submitted_ids, restricted to
    servers they're actually allowed to see. Returns the final set of
    server ids selected. Caller is responsible for db.session.commit()."""
    allowed_ids = _allowed_enabled_server_ids(user_id)
    submitted_ids = set(submitted_ids) & allowed_ids

    existing = UserServerSelection.query.filter_by(user_id=user_id).all()
    existing_ids = {row.server_id for row in existing}

    for row in existing:
        if row.server_id not in submitted_ids:
            db.session.delete(row)

    for server_id in submitted_ids - existing_ids:
        db.session.add(UserServerSelection(user_id=user_id, server_id=server_id))

    return submitted_ids


@bp.route("/selection", methods=["POST"])
@login_required
def selection():
    """Save which servers go into this user's generated config.
    set_user_selection() filters the submitted ids against the ACL, so a
    posted id for a server the user may not use is dropped rather than
    rejected."""
    submitted_ids = {int(sid) for sid in request.form.getlist("server_id")}
    set_user_selection(current_user.id, submitted_ids)
    db.session.commit()
    flash("Selection saved.", "success")
    return redirect(url_for("catalog.index"))


def get_server_known_keys(server):
    """Collects all known/available configuration keys for `server` from
    manifests, package metadata, detected environment variables, and admin settings."""
    known = {}

    suggestions = env_detection.from_system_manifest(server) or server.detected_env_vars or []
    for s in suggestions:
        name = s.get("name")
        if name:
            desc = s.get("description") or ""
            if s.get("choices"):
                choices = "one of: " + ", ".join(s["choices"])
                desc = f"{desc} ({choices})" if desc else choices
            known[name] = {
                "key": name,
                "description": desc or None,
                "required": bool(s.get("required")),
                "sensitive": bool(s.get("secret")),
                "default": s.get("default") or "",
                "source": s.get("source"),
            }

    for k, v in (server.env_config or {}).items():
        entry = known.setdefault(
            k,
            {
                "key": k,
                "description": None,
                "required": False,
                "sensitive": False,
                "default": "",
                "source": "admin",
            },
        )
        entry["default"] = v
        entry["admin_defined"] = True

    for k in server.env_var_names:
        entry = known.setdefault(
            k,
            {
                "key": k,
                "description": None,
                "required": False,
                "sensitive": True,
                "default": "",
                "source": "admin",
            },
        )
        entry["sensitive"] = True
        entry["admin_defined"] = True
        entry["admin_secret"] = True

    for k in server.required_env_keys:
        entry = known.setdefault(
            k,
            {
                "key": k,
                "description": None,
                "required": True,
                "sensitive": False,
                "default": "",
                "source": "required",
            },
        )
        entry["required"] = True

    return sorted(known.values(), key=lambda x: (not x.get("required"), x["key"]))


def get_user_override_context(server, user):
    """Prepares structured rows and known keys for the user configuration editor."""
    try:
        user_non_secret, user_secret = secret_store.load_user_override(server, user)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        flash(f"Could not reach Vaultwarden to load your credentials: {exc}", "error")
        user_non_secret, user_secret = {}, {}

    admin_non_secret = dict(server.env_config or {})
    admin_secret_keys = set(server.env_var_names)
    required_keys = set(server.required_env_keys)

    known_keys = get_server_known_keys(server)
    known_map = {item["key"]: item for item in known_keys}

    all_keys = set(admin_non_secret) | admin_secret_keys | set(user_non_secret) | set(user_secret) | required_keys

    rows = []
    for k in sorted(all_keys, key=lambda key: (key not in required_keys, key)):
        is_admin_defined = (k in admin_non_secret) or (k in admin_secret_keys)
        is_secret = (k in user_secret) or (k in admin_secret_keys) or known_map.get(k, {}).get("sensitive", False)
        is_required = (k in required_keys) or known_map.get(k, {}).get("required", False)

        is_overridden = (k in user_non_secret) or (k in user_secret)

        admin_val = ""
        if k in admin_non_secret:
            admin_val = admin_non_secret[k]
        elif k in admin_secret_keys:
            admin_val = "●●●●●●"

        current_val = ""
        if k in user_non_secret:
            current_val = user_non_secret[k]
        elif k in user_secret:
            current_val = user_secret[k]

        rows.append({
            "key": k,
            "value": current_val,
            "admin_value": admin_val,
            "is_admin_defined": is_admin_defined,
            "is_overridden": is_overridden,
            "sensitive": is_secret,
            "required": is_required,
            "description": known_map.get(k, {}).get("description"),
            "source": known_map.get(k, {}).get("source"),
        })

    has_override = bool(user_non_secret or user_secret)
    return rows, known_keys, has_override


def _override_row_ids(form):
    """Submitted row ids in DOM order. Order matters: a set would make which
    of two rows with the same key wins arbitrary."""
    ids, seen = [], set()
    for name in form:
        if name.startswith("env_key__"):
            row_id = name[len("env_key__"):]
            if row_id not in seen:
                seen.add(row_id)
                ids.append(row_id)
    return ids


def parse_user_override_form(server, form):
    """The override editor's submitted rows -> (non_secret, secret, error).
    Shared by catalog.override and admin.user_override so the self-service
    and admin editors cannot drift apart.

    `error` is a message to show the submitter; when it is set, nothing was
    parsed and nothing should be saved. An empty value on an admin-defined
    key means "keep inheriting the default" - that is exactly what the
    editor's revert button does, it just clears the input."""
    admin_non_secret = dict(server.env_config or {})
    admin_secret_keys = set(server.env_var_names)

    if "env_editor" not in form:
        # override-editor.js injects that marker on load, so its absence
        # means the browser had no JS: fall back to the raw KEY=value
        # textarea the form still carries. Absence of env_key__* rows is
        # not the same signal - that is also what deleting every row looks
        # like, and falling back there re-saved the values just removed.
        return _parse_override_env_text(
            server, form.get("env_text", ""), _submitted_secret_keys(form)
        )

    non_secret, secret = {}, {}
    for row_id in _override_row_ids(form):
        key = form.get(f"env_key__{row_id}", "").strip()
        if not key:
            continue
        if key in non_secret or key in secret:
            return {}, {}, f"Duplicate key '{key}' — each variable name must appear only once."
        value = form.get(f"env_value__{row_id}", "")
        if not value and (key in admin_non_secret or key in admin_secret_keys):
            continue
        # The checkbox may opt a value *into* the secret store, never out of
        # it: an unchecked box is indistinguishable from a client that never
        # sent the field, so trusting it alone let an admin-declared secret
        # be written to plain env_config_json.
        if (
            form.get(f"env_sensitive__{row_id}") is not None
            or secret_store.override_key_is_secret(server, key)
        ):
            secret[key] = value
        else:
            non_secret[key] = value
    return non_secret, secret, None


def _submitted_secret_keys(form):
    """Which keys the form was rendered with in the secret store. The no-JS
    textarea carries both halves flattened into KEY=value lines, so without
    this the round-trip would re-classify by name alone and demote a key the
    user marked sensitive. Env var names never contain whitespace, so a
    space-separated list is enough.

    Client-controlled, but it can only add keys to the secret half or drop a
    key that is secret purely because a box was ticked - which is exactly
    what unticking that box already does. Admin-declared and
    credential-looking names stay forced by override_key_is_secret()."""
    return set(form.get("env_secret_keys", "").split())


def _parse_override_env_text(server, raw, secret_keys=()):
    """The no-JS fallback: raw KEY=value lines into (non_secret, secret,
    error). The error slot is always None - unlike the row editor this
    path cannot produce duplicates, since a repeated key simply wins."""
    values = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key:
            values[key] = value
    non_secret, secret = secret_store.split_override_values(server, values, secret_keys=secret_keys)
    return non_secret, secret, None


def override_rows_from_form(server, form):
    """Rebuild the editor's rows from a rejected submission, so the submitter
    gets their input back instead of a blank form (admin._env_rows_from_form
    does the same job for the server form)."""
    known_map = {item["key"]: item for item in get_server_known_keys(server)}
    admin_non_secret = dict(server.env_config or {})
    admin_secret_keys = set(server.env_var_names)
    required_keys = set(server.required_env_keys)

    rows = []
    for row_id in _override_row_ids(form):
        key = form.get(f"env_key__{row_id}", "").strip()
        if not key:
            continue
        meta = known_map.get(key, {})
        admin_value = admin_non_secret.get(key, "●●●●●●" if key in admin_secret_keys else "")
        value = form.get(f"env_value__{row_id}", "")
        rows.append({
            "key": key,
            "value": value,
            "admin_value": admin_value,
            "is_admin_defined": (key in admin_non_secret) or (key in admin_secret_keys),
            "is_overridden": bool(value),
            "sensitive": (
                form.get(f"env_sensitive__{row_id}") is not None
                or secret_store.override_key_is_secret(server, key)
            ),
            "required": (key in required_keys) or bool(meta.get("required")),
            "description": meta.get("description"),
            "source": meta.get("source"),
        })
    return rows


@bp.route("/override/<int:server_id>", methods=["GET", "POST"])
@login_required
def override(server_id):
    """The user's own configuration editor for one server. Needs both the
    server ACL and the server's allow_user_override flag - an admin can
    still set the same values through admin.user_override when
    self-service is off."""
    server = db.get_or_404(McpServer, server_id)
    if server.id not in _allowed_enabled_server_ids(current_user.id):
        abort(403)
    if not server.allow_user_override:
        abort(403)

    if request.method == "POST":
        if request.form.get("action") == "reset":
            try:
                secret_store.delete_user_override(server, current_user)
            except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
                flash(f"Could not reach Vaultwarden: {exc} (ask an admin to check the diagnostics wizard).", "error")
                return redirect(url_for("catalog.index"))
            db.session.commit()
            flash(f"Reverted '{server.label}' to the default credentials.", "success")
            return redirect(url_for("catalog.index"))

        user_non_secret, user_secret, error = parse_user_override_form(server, request.form)
        if error:
            flash(error, "error")
            return render_template(
                "override.html",
                server=server,
                env_rows=override_rows_from_form(server, request.form),
                known_keys=get_server_known_keys(server),
                has_override=True,
                env_text=request.form.get("env_text", ""),
            )

        try:
            secret_store.save_user_override(server, current_user, user_non_secret, user_secret)
        except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
            flash(f"Could not save your credentials: {exc} (ask an admin to check the diagnostics wizard).", "error")
            return redirect(url_for("catalog.index"))

        db.session.commit()
        flash(f"Saved your personal credentials for '{server.label}'.", "success")
        return redirect(url_for("catalog.index"))

    env_rows, known_keys, has_override = get_user_override_context(server, current_user)

    # env_text for backward compatibility
    env_text = "\n".join(f"{r['key']}={r['value']}" for r in env_rows if r["is_overridden"])

    return render_template(
        "override.html",
        server=server,
        env_rows=env_rows,
        known_keys=known_keys,
        has_override=has_override,
        env_text=env_text,
    )


def _selected_enabled_allowed_servers(user):
    """The McpServer rows `user` has both selected and is currently allowed
    to see - shared by _build_client_config_json and
    _selected_server_connectors so the "which servers is this user actually
    configured with" definition can't drift between the two."""
    allowed_ids = _allowed_enabled_server_ids(user.id)
    return (
        McpServer.query.join(UserServerSelection)
        .filter(
            UserServerSelection.user_id == user.id,
            McpServer.enabled.is_(True),
            McpServer.id.in_(allowed_ids),
        )
        .all()
    )


def _server_connector(user, server):
    """A single {id, name, label, url} dict for `server`, for the "copy
    name / copy URL" popup on the catalog page (see catalog.html). Some MCP
    clients - notably Claude Desktop's "Add custom connector" dialog - want
    a plain name+URL pair per server rather than a JSON config file; this
    is the friendlier route for those. The token only encodes user_id +
    server_id, so this works whether or not `server` is currently in the
    user's selection - actually calling the URL still requires the server
    to be selected (see user_proxy_mcp)."""
    return {
        "id": server.id,
        "name": server.name,
        "label": server.label,
        "url": _proxy_relay_url(user, server),
    }


def _selected_server_connectors(user):
    """Each of `user`'s selected+enabled+allowed servers as a connector
    dict (see _server_connector), for the "Add as Individual Connectors"
    section of the catalog page."""
    return [_server_connector(user, server) for server in _selected_enabled_allowed_servers(user)]


def _build_client_config_json(client, user=None):
    """Resolve `user`'s (default: the current user) selected+enabled servers
    into a rendered client config, as a pretty-printed JSON string. Returns
    (config_json, filename, error_message) — config_json is None and
    error_message is set if there's nothing selected, `client` is unknown,
    or credentials couldn't be resolved. Callers decide how to surface
    error_message (flash for HTML views, a JSON error envelope for the API)
    since this function itself must stay presentation-agnostic to be usable
    from both.

    Users always connect through mcprack itself, never straight to a
    backend: every selected server — whether it's a stdio tool spawned
    per-user, a genuinely network-native MCP server, or one of mcp_rack's
    shared fastmcp proxies (which may live on an entirely different host
    than mcprack, or behind a `127.0.0.1`/private address mcprack itself
    can reach but the end user's own machine cannot) — gets a per-user
    `/proxy/mcp/<token>/<id>` relay URL (or `/proxy/mcp/<id>` when
    OAUTH_ENABLED) instead of its raw backend address. Credentials are
    resolved lazily at the moment that URL is actually first connected
    to (see user_proxy_mcp), never embedded in the downloaded config.
    """
    if user is None:
        user = current_user
    if client not in RENDERERS:
        abort(404)
    render_fn, filename = RENDERERS[client]

    selected = _selected_enabled_allowed_servers(user)

    if not selected:
        return None, filename, "You haven't selected any MCP servers yet."

    entries = []
    for server in selected:
        # Never log this URL when it embeds a path token: that signed
        # string is a bearer credential for user_proxy_mcp — writing it
        # to a log file or stderr would leak a usable access credential
        # outside the config the user actually asked for.
        relay_url = _proxy_relay_url(user, server)
        entries.append(
            {
                "name": server.name,
                "transport": "http",
                "command": server.command,
                "args": server.args,
                "url": relay_url,
                "auth_header_name": server.auth_header_name,
                "auth_env_key": server.auth_env_key,
                "env": {},
            }
        )

    payload = render_fn(entries)
    return json.dumps(payload, indent=2), filename, None


@bp.route("/download/<client>")
@login_required
def download(client):
    with telemetry.span("catalog.generate_config", {"client_type": client}):
        config_json, filename, error_message = _build_client_config_json(client)
    if config_json is None:
        flash(error_message, "error")
        audit.log_audit_event(
            "config_download",
            "error",
            user=current_user,
            error_message=f"no config produced for client '{client}'",
        )
        return redirect(url_for("catalog.index"))

    audit.log_audit_event("config_download", "success", user=current_user)
    telemetry.record_config_download(client)
    return Response(
        config_json,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@bp.route("/view/<client>")
@login_required
def view(client):
    with telemetry.span("catalog.generate_config", {"client_type": client}):
        config_json, filename, error_message = _build_client_config_json(client)
    if config_json is None:
        flash(error_message, "error")
        return redirect(url_for("catalog.index"))

    return render_template(
        "view_config.html", client=client, filename=filename, config_json=config_json
    )
