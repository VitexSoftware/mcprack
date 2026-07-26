from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from datetime import datetime

import detection
import health
import appstream_icons
import secret_store
import user_proxy
import vaultwarden
from auth import admin_required
from extensions import db
from models import McpServer, User, UserServerPermission

bp = Blueprint("admin", __name__, url_prefix="/admin")

# Cache for server health checks (expires after 5 minutes)
_health_cache = {}
_health_cache_time = None
_health_cache_key = None
HEALTH_CACHE_TTL = 300  # seconds
# Vaultwarden lookups are expensive; for bigger inventories prioritize fast
# page render and skip per-row credential checks on the listing page.
FULL_HEALTH_MAX_SERVERS = 8


def _invalidate_health_cache():
    global _health_cache, _health_cache_time, _health_cache_key
    _health_cache = {}
    _health_cache_time = None
    _health_cache_key = None


def _vaultwarden_ready_for_listing():
    """Cheap pre-check before running expensive `bw` subprocesses.

    If required BW config is missing or the BW endpoint cannot be reached
    quickly, the servers listing should still render immediately (without
    per-row missing-credentials checks).
    """
    cfg = current_app.config
    if cfg.get("TESTING"):
        return True
    required = ("BW_SERVER", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD")
    if not all(cfg.get(key) for key in required):
        return False
    return health.check_http_reachable(cfg.get("BW_SERVER"), timeout=0.25)


def _compute_server_health(servers):
    """One Vaultwarden session for the whole list, instead of one per row —
    and servers that declare no secret keys at all never touch Vaultwarden
    (or the local encrypted store) here, see secret_store.server_needs_secrets.
    Falls back to 'credentials unknown' (never flagged as missing) if
    Vaultwarden itself can't be reached, so a vault outage doesn't turn the
    entire servers list red.

    Caches results for 5 minutes to avoid repeated Vaultwarden/bw calls."""
    global _health_cache, _health_cache_time, _health_cache_key

    now = datetime.now()
    current_key = tuple(server.id for server in servers)
    if (
        _health_cache_time
        and _health_cache_key == current_key
        and (now - _health_cache_time).total_seconds() < HEALTH_CACHE_TTL
    ):
        return _health_cache

    health_by_id = {
        server.id: {"missing_credentials": [], "reachable": health.check_reachable(server)}
        for server in servers
    }
    needing_secrets = [s for s in servers if secret_store.server_needs_secrets(s)]

    if needing_secrets and not secret_store.is_vaultwarden_configured():
        for server in needing_secrets:
            try:
                values = secret_store.load_server_secrets(server)
            except secret_store.SecretStoreError:
                values = {}
            health_by_id[server.id]["missing_credentials"] = vaultwarden.missing_credential_keys(
                server, values
            )
    elif (
        needing_secrets
        and len(needing_secrets) <= FULL_HEALTH_MAX_SERVERS
        and _vaultwarden_ready_for_listing()
    ):
        # Vaultwarden configured and the list is small enough to afford one
        # batched session; otherwise skip credential checks and just show
        # reachability, so a large inventory or a slow vault doesn't stall
        # the page.
        try:
            with vaultwarden.session() as sess:
                for server in needing_secrets:
                    try:
                        vault_values = vaultwarden.get_notes(sess, server.vaultwarden_item_name)
                    except vaultwarden.VaultwardenError:
                        vault_values = {}
                    health_by_id[server.id]["missing_credentials"] = vaultwarden.missing_credential_keys(
                        server, vault_values
                    )
        except vaultwarden.VaultwardenError:
            pass

    _health_cache = health_by_id
    _health_cache_time = now
    _health_cache_key = current_key
    return health_by_id


@bp.route("/servers")
@admin_required
def servers_list():
    servers = McpServer.query.order_by(McpServer.name).all()
    server_health = _compute_server_health(servers)
    return render_template("admin/servers_list.html", servers=servers, server_health=server_health)


@bp.route("/servers/new", methods=["GET", "POST"])
@admin_required
def server_new():
    if request.method == "POST":
        server = McpServer(name=request.form["name"])
        _apply_server_form(server, request.form)
        db.session.add(server)
        db.session.commit()
        _invalidate_health_cache()
        flash(f"Server '{server.name}' created.", "success")
        return redirect(url_for("admin.servers_list"))
    return render_template("admin/server_form.html", server=None, env_rows=[])


@bp.route("/servers/<int:server_id>/edit", methods=["GET", "POST"])
@admin_required
def server_edit(server_id):
    server = db.get_or_404(McpServer, server_id)

    if request.method == "POST":
        _apply_server_form(server, request.form)
        db.session.commit()
        _invalidate_health_cache()
        flash(f"Server '{server.name}' updated.", "success")
        return redirect(url_for("admin.servers_list"))

    env_rows = [{"key": k, "value": v, "sensitive": False} for k, v in (server.env_config or {}).items()]
    try:
        secret_values = secret_store.load_server_secrets(server)
        env_rows += [{"key": k, "value": v, "sensitive": True} for k, v in secret_values.items()]
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        flash(f"Could not load current secret values: {exc}", "error")

    icon_path = appstream_icons.resolve_server_icon_path(server)
    icon_url = None
    if appstream_icons.is_safe_icon_path(icon_path):
        icon_url = url_for("catalog.server_icon", server_id=server.id)

    return render_template(
        "admin/server_form.html",
        server=server,
        env_rows=env_rows,
        icon_url=icon_url,
    )


def _parse_env_rows(form):
    """Parse the Key/Value/Sensitive row editor, submitted as
    env_key__<id>, env_value__<id>, env_sensitive__<id> — <id> is an
    opaque client-assigned token, not necessarily contiguous, so rows can
    be added/removed freely in the browser without renumbering."""
    row_ids = {name[len("env_key__"):] for name in form if name.startswith("env_key__")}

    non_secret, secret = {}, {}
    for row_id in row_ids:
        key = form.get(f"env_key__{row_id}", "").strip()
        if not key:
            continue
        value = form.get(f"env_value__{row_id}", "")
        is_sensitive = form.get(f"env_sensitive__{row_id}") is not None
        if is_sensitive:
            secret[key] = value
        else:
            non_secret[key] = value
    return non_secret, secret


def _apply_server_form(server, form):
    def _nullable_text(value):
        value = (value or "").strip()
        if not value or value.lower() == "none":
            return None
        return value

    server.label = form.get("label", server.name)
    server.description = form.get("description", "")
    server.transport = form["transport"]
    server.category = form.get("category", "")
    server.enabled = form.get("enabled") == "on"
    server.allow_user_override = form.get("allow_user_override") == "on"

    # Command/args (how the server is actually run) and url/auth (how remote
    # users reach it over the network) are independent of each other: a
    # stdio-implemented server can still have a network endpoint if it's
    # proxied — in that case remote users should always get the network
    # address, never a "run this locally" command. Only a server with no
    # url at all falls back to local stdio spawn. See config_formats.py.
    server.command = _nullable_text(form.get("command", ""))
    server.args = [a for a in form.get("args", "").split() if a]
    server.url = _nullable_text(form.get("url", ""))
    server.auth_header_name = _nullable_text(form.get("auth_header_name", ""))
    server.auth_env_key = _nullable_text(form.get("auth_env_key", ""))

    had_secrets_before = secret_store.server_needs_secrets(server)
    non_secret, secret_values = _parse_env_rows(form)

    # The auth token key always carries a credential — force it into the
    # secret set even if the admin left its row unchecked.
    if server.auth_env_key and server.auth_env_key in non_secret:
        secret_values[server.auth_env_key] = non_secret.pop(server.auth_env_key)

    server.env_config = non_secret
    server.env_var_names = list(secret_values.keys())
    if not server.vaultwarden_item_name:
        server.vaultwarden_item_name = f"MCP-{server.name}"

    # Nothing to save and nothing to clear — skip Vaultwarden/local storage
    # entirely rather than touching either backend for an empty write.
    if not secret_values and not had_secrets_before:
        return

    try:
        secret_store.save_server_secrets(server, secret_values)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        flash(
            f"Could not save credentials: {exc} "
            "(see Vaultwarden diagnostics in the nav bar to find out why).",
            "error",
        )


@bp.route("/servers/autodetect", methods=["POST"])
@admin_required
def servers_autodetect():
    detected = detection.detect_local_mcp_servers()
    existing_names = {s.name for s in McpServer.query.all()}

    created = []
    for entry in detected:
        if entry["name"] in existing_names:
            continue

        server = McpServer(name=entry["name"])
        server.label = entry["label"]
        server.transport = entry["transport"]
        server.category = entry.get("category", "auto-detected")
        server.enabled = True
        server.allow_user_override = True
        server.vaultwarden_item_name = f"MCP-{server.name}"

        # command/args and url/auth are independent (see config_formats.py) —
        # a detected entry may carry either or both, depending on its source.
        server.command = entry.get("command")
        server.args = entry.get("args", [])
        server.url = entry.get("url")
        server.auth_header_name = entry.get("auth_header_name")
        server.auth_env_key = entry.get("auth_env_key")
        # Structure only — never actual credential values, see detection.py.
        # These are just hints shown on the admin credentials form; nothing
        # is written to Vaultwarden here.
        server.env_var_names = entry.get("env_var_names", [])

        db.session.add(server)
        created.append(server.name)
        existing_names.add(server.name)

    db.session.commit()
    _invalidate_health_cache()

    if created:
        flash(
            f"Autodetected and registered {len(created)} server(s): {', '.join(created)}. "
            "Set default credentials for each before enabling for wider use.",
            "success",
        )
    else:
        flash("No new MCP servers detected on this machine (or they're already registered).", "success")

    return redirect(url_for("admin.servers_list"))


@bp.route("/servers/<int:server_id>/delete", methods=["POST"])
@admin_required
def server_delete(server_id):
    server = db.get_or_404(McpServer, server_id)
    db.session.delete(server)
    db.session.commit()
    _invalidate_health_cache()
    flash(f"Server '{server.name}' deleted.", "success")
    return redirect(url_for("admin.servers_list"))


@bp.route("/vaultwarden/wizard")
@admin_required
def vaultwarden_wizard():
    steps = vaultwarden.diagnose()
    return render_template(
        "admin/vaultwarden_wizard.html",
        steps=steps,
        vaultwarden_configured=secret_store.is_vaultwarden_configured(),
    )


def _flash_migration_summary(summary, moved_key, verb):
    moved = summary.get(moved_key, [])
    failed = summary.get("failed", [])
    if moved:
        flash(f"{verb} {len(moved)} item(s): {', '.join(moved)}.", "success")
    if failed:
        detail = "; ".join(f"{label}: {err}" for label, err in failed)
        flash(f"{len(failed)} item(s) could not be {verb.lower()}: {detail}", "error")
    if not moved and not failed:
        flash("Nothing to do — no locally stored secrets found.", "success")


@bp.route("/vaultwarden/migrate-to-vaultwarden", methods=["POST"])
@admin_required
def vaultwarden_migrate_to_vaultwarden():
    """Move secrets accumulated locally (while Vaultwarden was unconfigured)
    into Vaultwarden, now that it's configured and reachable. Verifies each
    write before clearing the local copy."""
    try:
        summary = secret_store.migrate_local_to_vaultwarden()
    except secret_store.SecretStoreError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.vaultwarden_wizard"))

    _flash_migration_summary(summary, "moved", "Moved to Vaultwarden")
    _invalidate_health_cache()
    return redirect(url_for("admin.vaultwarden_wizard"))


@bp.route("/vaultwarden/snapshot-to-local", methods=["POST"])
@admin_required
def vaultwarden_snapshot_to_local():
    """Copy everything currently in Vaultwarden into the local encrypted
    store, without touching Vaultwarden's copy — run this before a planned
    Vaultwarden outage so mcprack can be switched to local-only mode
    (unset BW_SERVER) for the duration without losing access to secrets."""
    try:
        summary = secret_store.snapshot_vaultwarden_to_local()
    except secret_store.SecretStoreError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.vaultwarden_wizard"))

    _flash_migration_summary(summary, "copied", "Copied to local storage")
    return redirect(url_for("admin.vaultwarden_wizard"))


@bp.route("/proxy-instances")
@admin_required
def proxy_instances():
    user_proxy.cleanup_idle_proxies()
    rows = user_proxy.list_proxy_instances()

    user_ids = {row["user_id"] for row in rows}
    server_ids = {row["server_id"] for row in rows}
    users = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}
    servers = {s.id: s for s in McpServer.query.filter(McpServer.id.in_(server_ids)).all()} if server_ids else {}

    for row in rows:
        user = users.get(row["user_id"])
        server = servers.get(row["server_id"])
        row["username"] = user.username if user else f"user#{row['user_id']}"
        row["server_name"] = server.name if server else f"server#{row['server_id']}"

    return render_template("admin/proxy_instances.html", rows=rows)


@bp.route("/proxy-instances/stop/<int:user_id>/<int:server_id>", methods=["POST"])
@admin_required
def proxy_instance_stop(user_id, server_id):
    user_proxy.stop_user_server_proxy(user_id, server_id)
    flash(f"Stopped per-user proxy for user #{user_id}, server #{server_id}.", "success")
    return redirect(url_for("admin.proxy_instances"))


@bp.route("/users")
@admin_required
def users_list():
    users = User.query.order_by(User.username).all()
    return render_template("admin/users_list.html", users=users)


@bp.route("/users/new", methods=["GET", "POST"])
@admin_required
def user_new():
    if request.method == "POST":
        user = User(
            username=request.form["username"],
            email=request.form.get("email", ""),
            auth_type="local",
            is_admin=request.form.get("is_admin") == "on",
        )
        user.set_password(request.form["password"])
        db.session.add(user)
        db.session.commit()
        flash(f"Local user '{user.username}' created.", "success")
        return redirect(url_for("admin.users_list"))
    return render_template("admin/user_form.html", user=None)


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def user_edit(user_id):
    user = db.get_or_404(User, user_id)
    available_servers = McpServer.query.filter_by(enabled=True).order_by(McpServer.name).all()
    permission_rows = UserServerPermission.query.filter_by(user_id=user.id).all()
    permission_map = {row.server_id: bool(row.is_allowed) for row in permission_rows}

    if request.method == "POST":
        user.is_admin = request.form.get("is_admin") == "on"
        user.is_active_flag = request.form.get("is_active") == "on"
        new_password = request.form.get("password", "")
        if user.auth_type == "local" and new_password:
            user.set_password(new_password)

        # Persist explicit per-server ACL for currently available servers.
        UserServerPermission.query.filter_by(user_id=user.id).delete()
        for server in available_servers:
            value = request.form.get(f"server_access_{server.id}", "allow")
            is_allowed = value != "deny"
            db.session.add(
                UserServerPermission(
                    user_id=user.id,
                    server_id=server.id,
                    is_allowed=is_allowed,
                )
            )

        db.session.commit()
        flash(f"User '{user.username}' updated.", "success")
        return redirect(url_for("admin.users_list"))

    return render_template(
        "admin/user_form.html",
        user=user,
        available_servers=available_servers,
        permission_map=permission_map,
    )
