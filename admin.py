from flask import Blueprint, flash, redirect, render_template, request, url_for

import detection
import health
import vaultwarden
from auth import admin_required
from extensions import db
from models import McpServer, User

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _parse_kv_textarea(text):
    values = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key:
            values[key] = val.strip()
    return values


def _render_kv_textarea(values):
    return "\n".join(f"{k}={v}" for k, v in values.items())


def _compute_server_health(servers):
    """One Vaultwarden session for the whole list, instead of one per row.
    Falls back to 'credentials unknown' (never flagged as missing) if
    Vaultwarden itself can't be reached, so a vault outage doesn't turn the
    entire servers list red."""
    session = None
    try:
        session = vaultwarden.unlock()
    except vaultwarden.VaultwardenError:
        session = None

    health_by_id = {}
    for server in servers:
        vault_values = {}
        if session is not None:
            try:
                vault_values = vaultwarden.get_notes(session, server.vault_item)
            except vaultwarden.VaultwardenError:
                vault_values = {}

        health_by_id[server.id] = {
            "missing_credentials": vaultwarden.missing_credential_keys(server, vault_values),
            "reachable": health.check_reachable(server),
        }

    if session is not None:
        vaultwarden.lock(session)

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
        flash(f"Server '{server.name}' created.", "success")
        return redirect(url_for("admin.servers_list"))
    return render_template("admin/server_form.html", server=None, env_text="")


@bp.route("/servers/<int:server_id>/edit", methods=["GET", "POST"])
@admin_required
def server_edit(server_id):
    server = db.get_or_404(McpServer, server_id)

    if request.method == "POST":
        _apply_server_form(server, request.form)
        db.session.commit()
        flash(f"Server '{server.name}' updated.", "success")
        return redirect(url_for("admin.servers_list"))

    session = vaultwarden.unlock()
    try:
        env_values = vaultwarden.get_notes(session, server.vault_item)
    finally:
        vaultwarden.lock(session)

    return render_template(
        "admin/server_form.html", server=server, env_text=_render_kv_textarea(env_values)
    )


def _apply_server_form(server, form):
    server.label = form.get("label", server.name)
    server.description = form.get("description", "")
    server.transport = form["transport"]
    server.category = form.get("category", "")
    server.enabled = form.get("enabled") == "on"
    server.allow_user_override = form.get("allow_user_override") == "on"

    # Command/args (how the server is actually run) and url/auth (how remote
    # users reach it over the network) are independent of each other: a
    # stdio-implemented server can still have a network endpoint if it's
    # proxied (e.g. via mcp_rack's fastmcp proxy) — in that case remote users
    # should always get the network address, never a "run this locally"
    # command. Only a server with no url at all falls back to local stdio
    # spawn. See config_formats.py for how download-time rendering picks
    # between the two.
    server.command = form.get("command", "") or None
    server.args = [a for a in form.get("args", "").split() if a]
    server.url = form.get("url", "") or None
    server.auth_header_name = form.get("auth_header_name", "") or None
    server.auth_env_key = form.get("auth_env_key", "") or None

    env_values = _parse_kv_textarea(form.get("env_text", ""))
    server.env_var_names = list(env_values.keys())
    if not server.vaultwarden_item_name:
        server.vaultwarden_item_name = f"MCP-{server.name}"

    try:
        session = vaultwarden.unlock()
    except vaultwarden.VaultwardenError as exc:
        flash(
            f"Could not reach Vaultwarden — credentials were NOT saved: {exc} "
            "(see Vaultwarden diagnostics in the nav bar to find out why).",
            "error",
        )
        return

    try:
        vaultwarden.set_notes(session, server.vault_item, env_values)
    except vaultwarden.VaultwardenError as exc:
        flash(f"Could not save credentials to Vaultwarden: {exc}", "error")
    finally:
        vaultwarden.lock(session)


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
    flash(f"Server '{server.name}' deleted.", "success")
    return redirect(url_for("admin.servers_list"))


@bp.route("/vaultwarden/wizard")
@admin_required
def vaultwarden_wizard():
    steps = vaultwarden.diagnose()
    return render_template("admin/vaultwarden_wizard.html", steps=steps)


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

    if request.method == "POST":
        user.is_admin = request.form.get("is_admin") == "on"
        user.is_active_flag = request.form.get("is_active") == "on"
        new_password = request.form.get("password", "")
        if user.auth_type == "local" and new_password:
            user.set_password(new_password)
        db.session.commit()
        flash(f"User '{user.username}' updated.", "success")
        return redirect(url_for("admin.users_list"))

    return render_template("admin/user_form.html", user=user)
