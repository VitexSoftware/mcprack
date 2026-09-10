import json
import http.client
import socket
import time
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    abort,
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
from . import secret_store
from . import telemetry
from . import user_proxy
from . import vaultwarden
from .config_formats import render_claude_config, render_copilot_config
from .extensions import csrf, db
from .models import (
    McpServer,
    User,
    UserServerOverride,
    UserServerPermission,
    UserServerSelection,
)

bp = Blueprint("catalog", __name__)

RENDERERS = {
    "claude": (render_claude_config, "claude_desktop_config.json"),
    "copilot": (render_copilot_config, "mcp.json"),
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
    with telemetry.span(
        "mcp.server.call", {"server_name": server_name, "transport": transport}
    ) as current_span:
        try:
            conn.request(request.method, path, body=body, headers=headers)
            upstream = conn.getresponse()
            payload = upstream.read()
            response = Response(payload, status=upstream.status)

            for key, value in upstream.getheaders():
                key_lower = key.lower()
                if key_lower in {"transfer-encoding", "connection", "keep-alive"}:
                    continue
                response.headers[key] = value

            result = "success" if upstream.status < 400 else "error"
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
    return render_template(
        "catalog.html", servers=servers, selected_ids=selected_ids, override_ids=override_ids
    )


@bp.route("/icon/server/<int:server_id>")
@login_required
def server_icon(server_id):
    server = db.get_or_404(McpServer, server_id)
    icon_path = appstream_icons.resolve_server_icon_path(server)
    if not appstream_icons.is_safe_icon_path(icon_path):
        return redirect(url_for("static", filename="mcprack-app-icon.svg"))
    return send_file(icon_path)


@bp.route("/proxy/mcp/<token>/<int:server_id>", methods=["GET", "POST", "DELETE"])
def user_proxy_mcp(token, server_id):
    user_proxy.cleanup_idle_proxies()

    data = _parse_proxy_token(token)
    if not data or data.get("s") != server_id:
        abort(403)

    user = db.get_or_404(User, data.get("u"))
    server = db.get_or_404(McpServer, server_id)
    if not server.enabled or not (server.command or server.url):
        abort(404)

    if server.id not in _allowed_enabled_server_ids(user.id):
        abort(403)

    selected = UserServerSelection.query.filter_by(user_id=user.id, server_id=server.id).first()
    if not selected:
        abort(403)

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
            return _jsonrpc_error_response(request_id, str(exc))

        return _forward_to_user_proxy(port, server_name=server.name)

    # No command to spawn - this server already has a fixed network `url`
    # (a genuinely network-native MCP server, or one of mcp_rack's shared
    # fastmcp proxies, possibly on a different host entirely). Relay
    # straight to it instead of spawning anything.
    return _forward_to_backend_url(server.url, env, server)


# Bearer-token authenticated (the signed token in the URL path), not
# session-cookie authenticated - CSRF protection has nothing to add here
# since there's no ambient credential for a forged cross-site request to
# ride on, and remote MCP clients reconnecting to this URL never send one.
csrf.exempt(user_proxy_mcp)


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
    submitted_ids = {int(sid) for sid in request.form.getlist("server_id")}
    set_user_selection(current_user.id, submitted_ids)
    db.session.commit()
    flash("Selection saved.", "success")
    return redirect(url_for("catalog.index"))


@bp.route("/override/<int:server_id>", methods=["GET", "POST"])
@login_required
def override(server_id):
    server = db.get_or_404(McpServer, server_id)
    if server.id not in _allowed_enabled_server_ids(current_user.id):
        abort(403)
    if not server.allow_user_override:
        abort(403)

    override_row = UserServerOverride.query.filter_by(
        user_id=current_user.id, server_id=server.id
    ).first()

    if request.method == "POST":
        if request.form.get("action") == "reset":
            try:
                secret_store.delete_user_override_secrets(server, current_user)
            except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
                flash(f"Could not reach Vaultwarden: {exc} (ask an admin to check the diagnostics wizard).", "error")
                return redirect(url_for("catalog.index"))
            db.session.commit()
            flash(f"Reverted '{server.label}' to the default credentials.", "success")
            return redirect(url_for("catalog.index"))

        values = {}
        for line in request.form.get("env_text", "").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if key:
                values[key] = val.strip()

        try:
            secret_store.save_user_override_secrets(server, current_user, values)
        except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
            flash(f"Could not save your credentials: {exc} (ask an admin to check the diagnostics wizard).", "error")
            return redirect(url_for("catalog.index"))

        db.session.commit()
        flash(f"Saved your personal credentials for '{server.label}'.", "success")
        return redirect(url_for("catalog.index"))

    env_text = ""
    if override_row:
        try:
            values = secret_store.load_user_override_secrets(server, current_user)
        except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
            flash(f"Could not reach Vaultwarden to load your credentials: {exc}", "error")
            values = {}
        env_text = "\n".join(f"{k}={v}" for k, v in values.items())

    return render_template(
        "override.html", server=server, env_text=env_text, has_override=bool(override_row)
    )


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
    `/proxy/mcp/<token>/<id>` relay URL instead of its raw backend address.
    Credentials are resolved lazily at the moment that URL is actually
    first connected to (see user_proxy_mcp), never embedded in the
    downloaded config.
    """
    if user is None:
        user = current_user
    if client not in RENDERERS:
        abort(404)
    render_fn, filename = RENDERERS[client]

    allowed_ids = _allowed_enabled_server_ids(user.id)
    selected = (
        McpServer.query.join(UserServerSelection)
        .filter(
            UserServerSelection.user_id == user.id,
            McpServer.enabled.is_(True),
            McpServer.id.in_(allowed_ids),
        )
        .all()
    )

    if not selected:
        return None, filename, "You haven't selected any MCP servers yet."

    entries = []
    for server in selected:
        # Never log this URL: the signed token embedded in it is a bearer
        # credential for user_proxy_mcp (see _make_proxy_token /
        # _parse_proxy_token above) — writing it to a log file or stderr
        # would leak a usable access credential outside the config the
        # user actually asked for.
        token = _make_proxy_token(user.id, server.id)
        relay_url = url_for(
            "catalog.user_proxy_mcp",
            token=token,
            server_id=server.id,
            _external=True,
        )
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
