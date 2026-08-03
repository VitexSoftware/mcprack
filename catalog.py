import json
import http.client
import socket
import time

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

import appstream_icons
import audit
import secret_store
import telemetry
import user_proxy
import vaultwarden
from config_formats import render_claude_config, render_copilot_config
from extensions import csrf, db
from models import (
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
PROXY_TOKEN_MAX_AGE = 24 * 3600


def _proxy_serializer():
    from flask import current_app

    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=PROXY_TOKEN_SALT)


def _make_proxy_token(user_id, server_id):
    return _proxy_serializer().dumps({"u": user_id, "s": server_id})


def _parse_proxy_token(token):
    try:
        return _proxy_serializer().loads(token, max_age=PROXY_TOKEN_MAX_AGE)
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


def _forward_to_user_proxy(port, server_name=None):
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

    start_time = time.monotonic()
    with telemetry.span(
        "mcp.server.call", {"server_name": server_name, "transport": "stdio"}
    ) as current_span:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=_PROXY_REQUEST_TIMEOUT)
        try:
            conn.request(request.method, "/mcp", body=body, headers=headers)
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
                server_name, "stdio", result, time.monotonic() - start_time
            )
            if current_span is not None:
                current_span.set_attribute("mcp.result", result)
            return response
        except (socket.timeout, OSError, http.client.HTTPException) as exc:
            telemetry.record_mcp_server_call(
                server_name, "stdio", "error", time.monotonic() - start_time
            )
            if current_span is not None:
                current_span.set_attribute("mcp.result", "error")
            return _jsonrpc_error_response(
                _jsonrpc_request_id(body),
                f"Upstream MCP server did not respond within {_PROXY_REQUEST_TIMEOUT}s: {exc}",
            )
        finally:
            conn.close()


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
    if not server.enabled or not server.command or server.url:
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


# Bearer-token authenticated (the signed token in the URL path), not
# session-cookie authenticated - CSRF protection has nothing to add here
# since there's no ambient credential for a forged cross-site request to
# ride on, and remote MCP clients reconnecting to this URL never send one.
csrf.exempt(user_proxy_mcp)


@bp.route("/selection", methods=["POST"])
@login_required
def selection():
    submitted_ids = {int(sid) for sid in request.form.getlist("server_id")}
    allowed_ids = _allowed_enabled_server_ids(current_user.id)
    submitted_ids &= allowed_ids

    existing = UserServerSelection.query.filter_by(user_id=current_user.id).all()
    existing_ids = {row.server_id for row in existing}

    for row in existing:
        if row.server_id not in submitted_ids:
            db.session.delete(row)

    for server_id in submitted_ids - existing_ids:
        db.session.add(UserServerSelection(user_id=current_user.id, server_id=server_id))

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
    None (with a flash already set) if there's nothing selected, or `client`
    is unknown.

    Users always connect remotely: a stdio-implemented server (no network
    url of its own) is never spawned by the client directly — it always
    gets a per-user proxy URL instead (see user_proxy.py / user_proxy_mcp
    below), and its credentials are resolved lazily at the moment that URL
    is actually first connected to, not here. Only servers with a real
    network url (already-running, externally reachable services) need their
    auth header resolved eagerly, right here, to embed in the config.
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
        flash("You haven't selected any MCP servers yet.", "error")
        return None, filename

    entries = []
    try:
        for server in selected:
            raw_url = (server.url or "").strip() if server.url else ""
            clean_url = None if raw_url.lower() in {"", "none", "null"} else raw_url

            if clean_url:
                env = secret_store.resolve_server_env(server, user=user)
            else:
                env = {}

            entries.append(
                {
                    "name": server.name,
                    "transport": server.transport,
                    "command": server.command,
                    "args": server.args,
                    "url": clean_url,
                    "auth_header_name": server.auth_header_name,
                    "auth_env_key": server.auth_env_key,
                    "env": env,
                }
            )
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        flash(
            f"Could not reach Vaultwarden to resolve credentials: {exc} "
            "(ask an admin to check Admin → Vaultwarden diagnostics).",
            "error",
        )
        return None, filename

    for i, server in enumerate(selected):
        if not entries[i].get("url") and server.command:
            token = _make_proxy_token(user.id, server.id)
            relay_url = url_for(
                "catalog.user_proxy_mcp",
                token=token,
                server_id=server.id,
                _external=True,
            )
            entries[i]["url"] = relay_url
            entries[i]["transport"] = "http"

    payload = render_fn(entries)
    return json.dumps(payload, indent=2), filename


@bp.route("/download/<client>")
@login_required
def download(client):
    with telemetry.span("catalog.generate_config", {"client_type": client}):
        config_json, filename = _build_client_config_json(client)
    if config_json is None:
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
        config_json, filename = _build_client_config_json(client)
    if config_json is None:
        return redirect(url_for("catalog.index"))

    return render_template(
        "view_config.html", client=client, filename=filename, config_json=config_json
    )
