"""JSON REST API, mounted at /api/v1.

Authenticated the same way as the rest of the app (session cookie via
flask_login) plus a new bearer-token path (api_auth.py) for external
scripts/CI. Business logic is reused from admin.py/catalog.py wherever
possible rather than duplicated — this module is mostly serialization,
routing, and JSON request/response shaping.

CSRF is exempted for this whole blueprint at registration time in app.py:
bearer-token requests carry no ambient cookie for a forged cross-site
request to ride on, so CSRF protection has nothing to add for them, and no
browser JS calls into this API exist today either.
"""

import copy
import functools
import json
import os
from datetime import datetime, timezone
from functools import wraps

import yaml
from flask import Blueprint, abort, jsonify, request
from flask_login import current_user

import admin
import audit
import catalog
import secret_store
import vaultwarden
from extensions import db, limiter
from models import (
    ApiToken,
    AuditLogEntry,
    McpServer,
    User,
    UserServerOverride,
    UserServerPermission,
    UserServerSelection,
)

bp = Blueprint("api", __name__, url_prefix="/api/v1")

_OPENAPI_PATH = os.path.join(os.path.dirname(__file__), "openapi", "openapi.yaml")


# --- response envelope + auth decorators -----------------------------------

def api_ok(data=None, status=200, **extra):
    body = {} if data is None else {"data": data}
    body.update(extra)
    return jsonify(body), status


def api_error(status, code, message):
    return jsonify(error={"code": code, "message": message}), status


def api_login_required(view):
    """Like flask_login's @login_required, but returns a 401 JSON envelope
    instead of redirecting to the HTML login page — the right behavior for
    a JSON API hit by curl/scripts with no valid cookie or bearer token."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return api_error(401, "unauthorized", "Authentication required")
        return view(*args, **kwargs)
    return wrapped


def api_admin_required(view):
    @wraps(view)
    @api_login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            return api_error(403, "forbidden", "Admin privileges required")
        return view(*args, **kwargs)
    return wrapped


@bp.errorhandler(400)
@bp.errorhandler(403)
@bp.errorhandler(404)
def _json_http_error(e):
    """Catches abort()s raised inside reused helpers (e.g.
    _build_client_config_json's abort(404) for an unknown client, or
    db.get_or_404) so this blueprint never leaks Flask's default HTML error
    page to a JSON caller."""
    code = getattr(e, "code", 500) or 500
    name = getattr(e, "name", "Error") or "Error"
    description = getattr(e, "description", None) or name
    return api_error(code, name.lower().replace(" ", "_"), description)


def paginate(query, default_per_page=50, max_per_page=200):
    page = request.args.get("page", default=1, type=int) or 1
    per_page = request.args.get("per_page", default=default_per_page, type=int) or default_per_page
    per_page = max(1, min(per_page, max_per_page))
    result = query.paginate(page=page, per_page=per_page, error_out=False)
    return result.items, {
        "page": result.page,
        "per_page": result.per_page,
        "total": result.total,
        "pages": result.pages,
    }


# --- serializers -------------------------------------------------------

def _iso(value):
    return value.isoformat() if value else None


def _user_summary(user):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "display_name": user.display_name,
        "auth_type": user.auth_type,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "created_at": _iso(user.created_at),
    }


def _user_detail(user):
    data = _user_summary(user)
    permission_rows = UserServerPermission.query.filter_by(user_id=user.id).all()
    data["permissions"] = {row.server_id: bool(row.is_allowed) for row in permission_rows}
    return data


def _server_summary(server):
    return {
        "id": server.id,
        "name": server.name,
        "label": server.label,
        "description": server.description,
        "transport": server.transport,
        "category": server.category,
        "enabled": server.enabled,
        "allow_user_override": server.allow_user_override,
    }


def _server_detail(server, reveal_secrets=False):
    data = _server_summary(server)
    data.update(
        {
            "command": server.command,
            "args": server.args,
            "url": server.url,
            "auth_header_name": server.auth_header_name,
            "auth_env_key": server.auth_env_key,
            "env": server.env_config,
            "env_var_names": server.env_var_names,
            "has_secrets": secret_store.server_needs_secrets(server),
            "vaultwarden_item_name": server.vaultwarden_item_name,
            "install_method": server.install_method,
            "package_spec": server.package_spec,
            "expected_binary": server.expected_binary,
            "install_status": server.install_status,
            "installed_version": server.installed_version,
            "created_at": _iso(server.created_at),
            "updated_at": _iso(server.updated_at),
        }
    )
    if reveal_secrets:
        try:
            data["secrets"] = secret_store.load_server_secrets(server)
        except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
            data["secrets_error"] = str(exc)
    return data


def _token_summary(token):
    return {
        "id": token.id,
        "name": token.name,
        "prefix": token.prefix,
        "created_at": _iso(token.created_at),
        "last_used_at": _iso(token.last_used_at),
        "revoked_at": _iso(token.revoked_at),
    }


def _audit_entry_summary(entry):
    return {
        "id": entry.id,
        "timestamp": _iso(entry.timestamp),
        "user_id": entry.user_id,
        "server_id": entry.server_id,
        "server_name": entry.server_name,
        "action": entry.action,
        "result": entry.result,
        "error_code": entry.error_code,
        "error_message": entry.error_message,
        "source_ip": entry.source_ip,
        "hostname": entry.hostname,
        "duration_ms": entry.duration_ms,
        "request_id": entry.request_id,
    }


def _server_update_data(server, data):
    """Merge a partial JSON body over the server's current field values, so
    PUT behaves as a partial update rather than requiring every field."""
    return {
        "label": data.get("label", server.label),
        "description": data.get("description", server.description),
        "transport": data.get("transport", server.transport),
        "category": data.get("category", server.category),
        "enabled": data.get("enabled", server.enabled),
        "allow_user_override": data.get("allow_user_override", server.allow_user_override),
        "command": data.get("command", server.command),
        "args": data.get("args", server.args),
        "url": data.get("url", server.url),
        "auth_header_name": data.get("auth_header_name", server.auth_header_name),
        "auth_env_key": data.get("auth_env_key", server.auth_env_key),
    }


# --- profile -------------------------------------------------------------

@bp.route("/me", methods=["GET"])
@api_login_required
def me():
    return api_ok(_user_summary(current_user))


# --- self-service API tokens ----------------------------------------------

@bp.route("/tokens", methods=["GET"])
@api_login_required
def tokens_list():
    tokens = ApiToken.query.filter_by(user_id=current_user.id).order_by(ApiToken.created_at.desc()).all()
    return api_ok([_token_summary(t) for t in tokens])


@bp.route("/tokens", methods=["POST"])
@api_login_required
@limiter.limit("5 per minute")
def tokens_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return api_error(400, "invalid_request", "name is required")

    raw, token = ApiToken.generate(name, current_user.id)
    db.session.add(token)
    db.session.commit()
    audit.log_audit_event(
        "credential_access", "success", user=current_user, error_message=f"API token '{name}' created"
    )

    body = _token_summary(token)
    body["token"] = raw
    return api_ok(body, status=201)


@bp.route("/tokens/<int:token_id>", methods=["DELETE"])
@api_login_required
def tokens_delete(token_id):
    token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first()
    if token is None:
        return api_error(404, "not_found", "Token not found")

    token.revoked_at = datetime.now(timezone.utc)
    db.session.commit()
    audit.log_audit_event(
        "credential_access", "success", user=current_user, error_message=f"API token '{token.name}' revoked"
    )
    return "", 204


# --- servers (user-facing) -------------------------------------------------

@bp.route("/servers", methods=["GET"])
@api_login_required
def servers_list():
    allowed_ids = catalog._allowed_enabled_server_ids(current_user.id)
    servers = (
        McpServer.query.filter(McpServer.id.in_(allowed_ids))
        .order_by(McpServer.category, McpServer.name)
        .all()
        if allowed_ids
        else []
    )
    return api_ok([_server_summary(s) for s in servers])


# --- servers (admin CRUD) --------------------------------------------------

@bp.route("/admin/servers", methods=["GET", "POST"])
@api_admin_required
def admin_servers():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return api_error(400, "invalid_request", "name is required")
        if McpServer.query.filter_by(name=name).first():
            return api_error(409, "conflict", f"server '{name}' already exists")

        server = McpServer(name=name)
        try:
            admin._apply_server_fields(server, data)
        except KeyError as exc:
            return api_error(400, "invalid_request", f"missing required field: {exc}")

        db.session.add(server)
        db.session.commit()
        secrets_error = admin._apply_server_secrets(server, data.get("env", {}), data.get("secrets", {}))
        db.session.commit()
        admin._invalidate_health_cache()
        audit.log_audit_event(
            "admin_change", "success", user=current_user, server=server, error_message="server created via API"
        )

        response = _server_detail(server)
        if secrets_error:
            response["secrets_error"] = secrets_error
        return api_ok(response, status=201)

    include_health = request.args.get("include_health") == "1"
    items, pagination = paginate(McpServer.query.order_by(McpServer.name))
    health_by_id = admin._compute_server_health(items) if include_health else {}
    servers = []
    for server in items:
        entry = _server_detail(server)
        if include_health:
            entry["health"] = health_by_id.get(server.id)
        servers.append(entry)
    return api_ok(servers, pagination=pagination)


@bp.route("/admin/servers/<int:server_id>", methods=["GET"])
@api_admin_required
def admin_server_detail(server_id):
    server = db.get_or_404(McpServer, server_id)
    reveal = request.args.get("reveal_secrets") == "1"
    return api_ok(_server_detail(server, reveal_secrets=reveal))


@bp.route("/admin/servers/<int:server_id>", methods=["PUT"])
@api_admin_required
def admin_server_update(server_id):
    server = db.get_or_404(McpServer, server_id)
    data = request.get_json(silent=True) or {}

    admin._apply_server_fields(server, _server_update_data(server, data))
    secrets_error = None
    if "env" in data or "secrets" in data:
        secrets_error = admin._apply_server_secrets(
            server, data.get("env", server.env_config), data.get("secrets", {})
        )

    db.session.commit()
    admin._invalidate_health_cache()
    audit.log_audit_event(
        "admin_change", "success", user=current_user, server=server, error_message="server updated via API"
    )

    response = _server_detail(server)
    if secrets_error:
        response["secrets_error"] = secrets_error
    return api_ok(response)


@bp.route("/admin/servers/<int:server_id>", methods=["DELETE"])
@api_admin_required
def admin_server_delete(server_id):
    server = db.get_or_404(McpServer, server_id)
    name = server.name
    db.session.delete(server)
    db.session.commit()
    admin._invalidate_health_cache()
    audit.log_audit_event(
        "admin_change", "success", user=current_user, server_name=name, error_message="server deleted via API"
    )
    return "", 204


# --- current user's selections ---------------------------------------------

@bp.route("/me/selections", methods=["GET"])
@api_login_required
def me_selections_list():
    rows = UserServerSelection.query.filter_by(user_id=current_user.id).all()
    server_ids = [row.server_id for row in rows]
    names = {s.id: s.name for s in McpServer.query.filter(McpServer.id.in_(server_ids)).all()} if server_ids else {}
    return api_ok(
        [
            {"server_id": row.server_id, "server_name": names.get(row.server_id), "selected_at": _iso(row.selected_at)}
            for row in rows
        ]
    )


@bp.route("/me/selections", methods=["PUT"])
@api_login_required
def me_selections_set():
    data = request.get_json(silent=True) or {}
    try:
        submitted_ids = {int(sid) for sid in data.get("server_ids", [])}
    except (TypeError, ValueError):
        return api_error(400, "invalid_request", "server_ids must be a list of integers")

    final_ids = catalog.set_user_selection(current_user.id, submitted_ids)
    db.session.commit()
    return api_ok({"server_ids": sorted(final_ids)})


# --- current user's per-server overrides ------------------------------------

def _override_target_server(server_id):
    server = db.get_or_404(McpServer, server_id)
    if server.id not in catalog._allowed_enabled_server_ids(current_user.id):
        abort(403)
    if not server.allow_user_override:
        abort(403)
    return server


@bp.route("/me/overrides/<int:server_id>", methods=["GET"])
@api_login_required
def me_override_get(server_id):
    server = _override_target_server(server_id)
    override_row = UserServerOverride.query.filter_by(user_id=current_user.id, server_id=server.id).first()
    data = {"server_id": server.id, "has_override": bool(override_row)}
    if override_row:
        try:
            values = secret_store.load_user_override_secrets(server, current_user)
        except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
            return api_error(502, "vaultwarden_unreachable", str(exc))
        if request.args.get("reveal") == "1":
            data["env"] = values
        else:
            data["env_keys"] = list(values.keys())
    return api_ok(data)


@bp.route("/me/overrides/<int:server_id>", methods=["PUT"])
@api_login_required
def me_override_set(server_id):
    server = _override_target_server(server_id)
    data = request.get_json(silent=True) or {}
    values = data.get("env")
    if not isinstance(values, dict):
        return api_error(400, "invalid_request", "env must be an object of key/value pairs")

    try:
        secret_store.save_user_override_secrets(server, current_user, values)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        return api_error(502, "vaultwarden_unreachable", str(exc))

    db.session.commit()
    return api_ok({"server_id": server.id, "env_keys": list(values.keys())})


@bp.route("/me/overrides/<int:server_id>", methods=["DELETE"])
@api_login_required
def me_override_delete(server_id):
    server = _override_target_server(server_id)
    try:
        secret_store.delete_user_override_secrets(server, current_user)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        return api_error(502, "vaultwarden_unreachable", str(exc))

    db.session.commit()
    return "", 204


# --- current user's client config -------------------------------------------

@bp.route("/me/config/<client>", methods=["GET"])
@api_login_required
def me_config(client):
    config_json, filename, error_message = catalog._build_client_config_json(client, user=current_user)
    if config_json is None:
        audit.log_audit_event(
            "config_download",
            "error",
            user=current_user,
            error_message=f"no config produced for client '{client}' (API)",
        )
        return api_error(404, "no_config", error_message)

    audit.log_audit_event("config_download", "success", user=current_user)
    return api_ok({"filename": filename, "config": json.loads(config_json)})


# --- admin: users ------------------------------------------------------------

@bp.route("/admin/users", methods=["GET", "POST"])
@api_admin_required
def admin_users():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username or not password:
            return api_error(400, "invalid_request", "username and password are required")
        if User.query.filter_by(username=username).first():
            return api_error(409, "conflict", f"user '{username}' already exists")

        user = User(
            username=username,
            email=data.get("email", ""),
            auth_type="local",
            is_admin=bool(data.get("is_admin")),
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        audit.log_audit_event(
            "admin_change", "success", user=current_user, error_message=f"user '{user.username}' created via API"
        )
        return api_ok(_user_detail(user), status=201)

    items, pagination = paginate(User.query.order_by(User.username))
    return api_ok([_user_summary(u) for u in items], pagination=pagination)


@bp.route("/admin/users/<int:user_id>", methods=["GET"])
@api_admin_required
def admin_user_detail(user_id):
    user = db.get_or_404(User, user_id)
    return api_ok(_user_detail(user))


@bp.route("/admin/users/<int:user_id>", methods=["PUT"])
@api_admin_required
def admin_user_update(user_id):
    user = db.get_or_404(User, user_id)
    data = request.get_json(silent=True) or {}

    if "is_admin" in data:
        user.is_admin = bool(data["is_admin"])
    if "is_active" in data:
        user.is_active_flag = bool(data["is_active"])
    if data.get("password") and user.auth_type == "local":
        user.set_password(data["password"])
    if "permissions" in data:
        available_servers = McpServer.query.filter_by(enabled=True).order_by(McpServer.name).all()
        try:
            overrides = {int(k): bool(v) for k, v in (data.get("permissions") or {}).items()}
        except (TypeError, ValueError):
            return api_error(400, "invalid_request", "permissions must map server id to a boolean")
        admin.set_user_server_permissions(user, available_servers, overrides)

    db.session.commit()
    audit.log_audit_event(
        "admin_change", "success", user=current_user, error_message=f"user '{user.username}' updated via API"
    )
    return api_ok(_user_detail(user))


@bp.route("/admin/users/<int:user_id>", methods=["DELETE"])
@api_admin_required
def admin_user_delete(user_id):
    if user_id == current_user.id:
        return api_error(400, "cannot_delete_self", "You cannot delete your own account.")

    user = db.get_or_404(User, user_id)
    username = user.username
    db.session.delete(user)
    db.session.commit()
    audit.log_audit_event(
        "admin_change", "success", user_id=current_user.id, error_message=f"user '{username}' deleted via API"
    )
    return "", 204


# --- admin: audit log --------------------------------------------------------

@bp.route("/audit-log", methods=["GET"])
@api_admin_required
def audit_log_list():
    query, filters = admin.build_audit_log_query(request.args)
    items, pagination = paginate(query.order_by(AuditLogEntry.timestamp.desc()))
    return api_ok([_audit_entry_summary(e) for e in items], pagination=pagination, filters=filters)


# --- OpenAPI spec -------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _load_openapi_spec():
    with open(_OPENAPI_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


@bp.route("/openapi.json", methods=["GET"])
def openapi_spec():
    from version import get_version

    spec = copy.deepcopy(_load_openapi_spec())
    spec.setdefault("info", {})["version"] = get_version()
    return jsonify(spec)
