from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for, Response
from datetime import datetime, timezone

from . import audit
from . import catalog
from . import detection
from . import env_detection
from . import health
from . import installer
from . import appstream_icons
from . import secret_store
from . import user_proxy
from . import vaultwarden
from .auth import admin_required
from .extensions import db
from flask_login import current_user
from .models import AuditLogEntry, McpServer, User, UserServerPermission, UserServerSelection

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


def _demo_mode_blocked():
    """Call at the top of any route that adds/edits/deletes an MCP server
    registration. Returns a redirect response if DEMO_MODE is on (nothing
    else is restricted), or None to let the route proceed."""
    if not current_app.config.get("DEMO_MODE"):
        return None
    flash("This is a public demo instance — registering, editing, and deleting MCP servers is disabled.", "error")
    return redirect(url_for("admin.servers_list"))


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

    def _missing_required(server, secret_values):
        """Admin-default view only (no per-user overrides) — an admin
        default gap doesn't necessarily mean the server is unusable if
        allow_user_override lets each user supply their own value, but it's
        still worth flagging as incomplete."""
        if not server.required_env_keys:
            return []
        effective = dict(server.env_config or {})
        effective.update(secret_values or {})
        return sorted(key for key in server.required_env_keys if not effective.get(key))

    health_by_id = {
        server.id: {
            "missing_credentials": [],
            "missing_required": _missing_required(server, {}),
            "reachable": health.check_reachable(server),
        }
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
            health_by_id[server.id]["missing_required"] = _missing_required(server, values)
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
                    health_by_id[server.id]["missing_required"] = _missing_required(server, vault_values)
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
    blocked = _demo_mode_blocked()
    if blocked:
        return blocked
    if request.method == "POST":
        server = McpServer(name=request.form["name"])
        _apply_server_form(server, request.form)
        db.session.add(server)
        db.session.commit()
        _invalidate_health_cache()
        audit.log_audit_event(
            "admin_change", "success", user=current_user, server=server, error_message="server created"
        )
        flash(f"Server '{server.name}' created.", "success")
        return redirect(url_for("admin.servers_list"))
    return render_template("admin/server_form.html", server=None, env_rows=[])


@bp.route("/servers/<int:server_id>/edit", methods=["GET", "POST"])
@admin_required
def server_edit(server_id):
    server = db.get_or_404(McpServer, server_id)

    if request.method == "POST":
        blocked = _demo_mode_blocked()
        if blocked:
            return blocked
        _apply_server_form(server, request.form)
        db.session.commit()
        _invalidate_health_cache()
        audit.log_audit_event(
            "admin_change", "success", user=current_user, server=server, error_message="server updated"
        )
        flash(f"Server '{server.name}' updated.", "success")
        return redirect(url_for("admin.servers_list"))

    required_keys = set(server.required_env_keys)
    env_rows = [
        {"key": k, "value": v, "sensitive": False, "required": k in required_keys}
        for k, v in (server.env_config or {}).items()
    ]
    try:
        secret_values = secret_store.load_server_secrets(server)
        env_rows += [
            {"key": k, "value": v, "sensitive": True, "required": k in required_keys}
            for k, v in secret_values.items()
        ]
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        flash(f"Could not load current secret values: {exc}", "error")

    # Detected-but-not-yet-configured suggestions get folded in as
    # additional, pre-filled-but-empty rows so the admin sees them directly
    # in the editable list — never applied/saved unless the admin actually
    # submits the form. Only registry/manifest sources ever carry
    # required=True (see env_detection.py); a heuristic source-scan/
    # docker-inspect guess is still shown, just not pre-checked required.
    configured_keys = set(server.env_config or {}) | set(server.env_var_names)
    for suggestion in server.detected_env_vars:
        if suggestion.get("name") not in configured_keys:
            env_rows.append(
                {
                    "key": suggestion["name"],
                    "value": "",
                    "sensitive": bool(suggestion.get("secret")),
                    "required": bool(suggestion.get("required")),
                }
            )

    icon_path = appstream_icons.resolve_server_icon_path(server)
    icon_url = None
    if appstream_icons.is_safe_icon_path(icon_path):
        icon_url = url_for("catalog.server_icon", server_id=server.id)

    return render_template(
        "admin/server_form.html",
        server=server,
        env_rows=env_rows,
        icon_url=icon_url,
        demo_mode=current_app.config.get("DEMO_MODE", False),
    )


def _parse_env_rows(form):
    """Parse the Key/Value/Sensitive/Required row editor, submitted as
    env_key__<id>, env_value__<id>, env_sensitive__<id>, env_required__<id>
    — <id> is an opaque client-assigned token, not necessarily contiguous,
    so rows can be added/removed freely in the browser without renumbering.
    Returns (non_secret, secret, required_keys)."""
    row_ids = {name[len("env_key__"):] for name in form if name.startswith("env_key__")}

    non_secret, secret, required_keys = {}, {}, set()
    for row_id in row_ids:
        key = form.get(f"env_key__{row_id}", "").strip()
        if not key:
            continue
        value = form.get(f"env_value__{row_id}", "")
        is_sensitive = form.get(f"env_sensitive__{row_id}") is not None
        is_required = form.get(f"env_required__{row_id}") is not None
        if is_sensitive:
            secret[key] = value
        else:
            non_secret[key] = value
        if is_required:
            required_keys.add(key)
    return non_secret, secret, required_keys


def _apply_server_fields(server, data):
    """Plain-dict field assignment shared by the HTML form and the JSON API
    — no Werkzeug form dependency, so it works the same from either caller."""
    def _nullable_text(value):
        value = (value or "").strip()
        if not value or value.lower() == "none":
            return None
        return value

    server.label = data.get("label") or server.name
    server.description = data.get("description", "") or ""
    server.transport = data["transport"]
    server.category = data.get("category", "") or ""
    server.enabled = bool(data.get("enabled"))
    server.allow_user_override = bool(data.get("allow_user_override"))

    # Command/args (how the server is actually run) and url/auth (how remote
    # users reach it over the network) are independent of each other: a
    # stdio-implemented server can still have a network endpoint if it's
    # proxied — in that case remote users should always get the network
    # address, never a "run this locally" command. Only a server with no
    # url at all falls back to local stdio spawn. See config_formats.py.
    server.command = _nullable_text(data.get("command", ""))
    args = data.get("args", [])
    if isinstance(args, str):
        args = [a for a in args.split() if a]
    server.args = list(args or [])
    server.url = _nullable_text(data.get("url", ""))
    server.auth_header_name = _nullable_text(data.get("auth_header_name", ""))
    server.auth_env_key = _nullable_text(data.get("auth_env_key", ""))


def _apply_server_secrets(server, non_secret, secret, required_keys=None):
    """Persists non-secret env config directly and secret values via
    secret_store, shared by the HTML form and the JSON API. Returns an error
    message string on failure (caller decides how to surface it), or None
    on success."""
    had_secrets_before = secret_store.server_needs_secrets(server)
    non_secret = dict(non_secret or {})
    secret_values = dict(secret or {})

    # The auth token key always carries a credential — force it into the
    # secret set even if the caller left it in the non-secret map.
    if server.auth_env_key and server.auth_env_key in non_secret:
        secret_values[server.auth_env_key] = non_secret.pop(server.auth_env_key)

    server.env_config = non_secret
    server.env_var_names = list(secret_values.keys())
    server.required_env_keys = list(required_keys or [])
    if not server.vaultwarden_item_name:
        server.vaultwarden_item_name = f"MCP-{server.name}"

    # Nothing to save and nothing to clear — skip Vaultwarden/local storage
    # entirely rather than touching either backend for an empty write.
    if not secret_values and not had_secrets_before:
        return None

    try:
        secret_store.save_server_secrets(server, secret_values)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        return f"Could not save credentials: {exc} (see Vaultwarden diagnostics in the nav bar to find out why)."
    return None


def _apply_server_form(server, form):
    """HTML form entry point: builds plain dicts from the Werkzeug form and
    delegates to the JSON-friendly helpers above, so the two views share all
    business logic and HTML behavior is unchanged."""
    _apply_server_fields(
        server,
        {
            "label": form.get("label", server.name),
            "description": form.get("description", ""),
            "transport": form["transport"],
            "category": form.get("category", ""),
            "enabled": form.get("enabled") == "on",
            "allow_user_override": form.get("allow_user_override") == "on",
            "command": form.get("command", ""),
            "args": form.get("args", ""),
            "url": form.get("url", ""),
            "auth_header_name": form.get("auth_header_name", ""),
            "auth_env_key": form.get("auth_env_key", ""),
        },
    )

    non_secret, secret_values, required_keys = _parse_env_rows(form)
    error_message = _apply_server_secrets(server, non_secret, secret_values, required_keys)
    if error_message:
        flash(error_message, "error")


@bp.route("/servers/autodetect", methods=["POST"])
@admin_required
def servers_autodetect():
    blocked = _demo_mode_blocked()
    if blocked:
        return blocked
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
    blocked = _demo_mode_blocked()
    if blocked:
        return blocked
    server = db.get_or_404(McpServer, server_id)
    server_name = server.name
    db.session.delete(server)
    db.session.commit()
    _invalidate_health_cache()
    audit.log_audit_event(
        "admin_change",
        "success",
        user=current_user,
        server_name=server_name,
        error_message="server deleted",
    )
    flash(f"Server '{server_name}' deleted.", "success")
    return redirect(url_for("admin.servers_list"))


@bp.route("/servers/<int:server_id>/test", methods=["POST"])
@admin_required
def server_test_stdio(server_id):
    """On-demand only (never automatic on page load — it really spawns the
    registered command). Catches registrations that look fine by
    `check_stdio_command` (file exists, executable) but are actually broken
    at runtime — e.g. a missing dependency that crashes on import."""
    server = db.get_or_404(McpServer, server_id)
    if server.url:
        flash(f"'{server.name}' is a network endpoint, not a local stdio command — nothing to test here.", "error")
        return redirect(url_for("admin.servers_list"))

    try:
        env = secret_store.resolve_server_env(server)
    except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
        flash(f"Could not resolve credentials to test '{server.name}': {exc}", "error")
        return redirect(url_for("admin.servers_list"))

    ok, detail = health.check_stdio_startup(server.command, server.args, env)
    if ok:
        flash(f"✓ '{server.name}' started successfully. {detail}", "success")
    else:
        flash(f"✗ '{server.name}' failed to start: {detail}", "error")
    return redirect(url_for("admin.servers_list"))


def _installable_name_taken(name):
    return McpServer.query.filter_by(name=name).first() is not None


@bp.route("/install")
@admin_required
def install_wizard():
    """Status/diagnose page for the pip/npm/docker installer subsystem —
    same shape as the Vaultwarden/OTel wizards: a GET status page, with
    separate POST action routes below that each perform one step and
    redirect back here with a flash message."""
    import shutil as _shutil

    servers = (
        McpServer.query.filter(McpServer.install_method.isnot(None))
        .order_by(McpServer.name)
        .all()
    )
    capabilities = {
        "pip": _shutil.which("python3") is not None,
        "npm": _shutil.which("npm") is not None,
        "docker": installer.docker_available(),
    }
    return render_template(
        "admin/install_wizard.html",
        servers=servers,
        capabilities=capabilities,
        demo_mode=current_app.config.get("DEMO_MODE", False),
    )


def _create_install_server(form, install_method):
    name = (form.get("name") or "").strip()
    if not name:
        raise ValueError("Server name is required.")
    if _installable_name_taken(name):
        raise ValueError(f"A server named '{name}' is already registered.")

    server = McpServer(name=name)
    server.label = form.get("label") or name
    server.description = form.get("description", "")
    server.category = form.get("category") or f"{install_method}-installed"
    server.transport = "stdio"
    server.enabled = True
    server.allow_user_override = True
    server.vaultwarden_item_name = f"MCP-{server.name}"
    server.install_method = install_method
    server.install_status = "queued"

    non_secret, secret_values, required_keys = _parse_env_rows(form)
    server.env_config = non_secret
    server.env_var_names = list(secret_values.keys())
    server.required_env_keys = list(required_keys)

    db.session.add(server)
    db.session.commit()

    if secret_values:
        try:
            secret_store.save_server_secrets(server, secret_values)
        except (vaultwarden.VaultwardenError, secret_store.SecretStoreError) as exc:
            flash(f"Server registered, but credentials could not be saved: {exc}", "error")

    return server


@bp.route("/install/pip", methods=["POST"])
@admin_required
def install_pip():
    blocked = _demo_mode_blocked()
    if blocked:
        return blocked

    package_spec = (request.form.get("package_spec") or "").strip()
    expected_binary = (request.form.get("expected_binary") or "").strip()
    if not package_spec or not expected_binary:
        flash("Package spec and expected binary name are both required.", "error")
        return redirect(url_for("admin.install_wizard"))

    try:
        server = _create_install_server(request.form, "pip")
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.install_wizard"))

    server.package_spec = package_spec
    server.expected_binary = expected_binary
    db.session.commit()

    try:
        install_path = installer.start_pip_install(server.name, package_spec, expected_binary)
        server.install_path = install_path
        db.session.commit()
    except installer.InstallError as exc:
        server.install_status = "failed"
        server.install_error = str(exc)[:500]
        db.session.commit()
        flash(f"Could not start pip install: {exc}", "error")
        return redirect(url_for("admin.install_wizard"))

    audit.log_audit_event(
        "admin_change", "success", user=current_user, server=server,
        error_message=f"pip install started for '{server.name}' ({package_spec})",
    )
    flash(f"Installing '{server.name}' via pip — refresh this page to check progress.", "success")
    return redirect(url_for("admin.install_wizard"))


@bp.route("/install/npm", methods=["POST"])
@admin_required
def install_npm():
    blocked = _demo_mode_blocked()
    if blocked:
        return blocked

    package_spec = (request.form.get("package_spec") or "").strip()
    expected_binary = (request.form.get("expected_binary") or "").strip()
    if not package_spec or not expected_binary:
        flash("Package spec and expected binary name are both required.", "error")
        return redirect(url_for("admin.install_wizard"))

    try:
        server = _create_install_server(request.form, "npm")
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.install_wizard"))

    server.package_spec = package_spec
    server.expected_binary = expected_binary
    db.session.commit()

    try:
        install_path = installer.start_npm_install(server.name, package_spec, expected_binary)
        server.install_path = install_path
        db.session.commit()
    except installer.InstallError as exc:
        server.install_status = "failed"
        server.install_error = str(exc)[:500]
        db.session.commit()
        flash(f"Could not start npm install: {exc}", "error")
        return redirect(url_for("admin.install_wizard"))

    audit.log_audit_event(
        "admin_change", "success", user=current_user, server=server,
        error_message=f"npm install started for '{server.name}' ({package_spec})",
    )
    flash(f"Installing '{server.name}' via npm — refresh this page to check progress.", "success")
    return redirect(url_for("admin.install_wizard"))


@bp.route("/install/docker", methods=["POST"])
@admin_required
def install_docker():
    blocked = _demo_mode_blocked()
    if blocked:
        return blocked

    image_ref = (request.form.get("image_ref") or "").strip()
    if not image_ref:
        flash("Docker image reference is required.", "error")
        return redirect(url_for("admin.install_wizard"))

    if not installer.docker_available():
        flash(
            "Docker CLI is not usable by the mcprack service account — this requires adding "
            "it to the 'docker' group (equivalent to root access), a deliberate manual step: "
            "sudo usermod -aG docker mcprack && systemctl restart mcprack. "
            "See README § Installing new MCP servers for the security tradeoff.",
            "error",
        )
        return redirect(url_for("admin.install_wizard"))

    try:
        server = _create_install_server(request.form, "docker")
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.install_wizard"))

    server.package_spec = image_ref
    server.command = "docker"
    server.args = ["run", "--rm", "-i", image_ref]
    db.session.commit()

    installer.start_docker_pull(server.name, image_ref)

    audit.log_audit_event(
        "admin_change", "success", user=current_user, server=server,
        error_message=f"docker pull started for '{server.name}' ({image_ref})",
    )
    flash(f"Pulling image for '{server.name}' — refresh this page to check progress.", "success")
    return redirect(url_for("admin.install_wizard"))


@bp.route("/install/<int:server_id>/status")
@admin_required
def install_status(server_id):
    """JSON polling endpoint. Finalizes install_status/install_error/
    installed_version/installed_at on the McpServer row the first time a
    terminal state (success/failed) is observed — safe to call repeatedly,
    since re-finalizing an already-terminal row is a harmless no-op."""
    server = db.get_or_404(McpServer, server_id)
    if not server.install_method:
        return jsonify({"error": "not an installer-managed server"}), 400

    result = installer.get_install_status(server.name)

    if server.install_status not in ("success", "failed") and result["status"] in ("success", "failed"):
        if result["status"] == "success":
            binary_path = None
            if server.install_method == "pip":
                binary_path = installer.verify_pip_binary(server.install_path, server.expected_binary)
            elif server.install_method == "npm":
                binary_path = installer.verify_npm_binary(server.install_path, server.expected_binary)
            elif server.install_method == "docker":
                binary_path = "docker" if installer.verify_docker_image(server.package_spec) else None

            if binary_path:
                if server.install_method != "docker":
                    server.command = binary_path
                server.install_status = "success"
                server.install_error = None
                server.installed_version = installer.resolve_installed_version(
                    server.install_method, server.install_path, server.package_spec
                )
                server.installed_at = datetime.now(timezone.utc)
                server.detected_env_vars = env_detection.detect_env_vars(server)
            else:
                server.install_status = "failed"
                server.install_error = (
                    f"Install succeeded but expected binary '{server.expected_binary}' was not "
                    "found — check the log for the actual installed script name."
                )[:500]
        else:
            server.install_status = "failed"
            server.install_error = (result["error"] or "")[:500]
        db.session.commit()
        _invalidate_health_cache()

    return jsonify(
        {
            "status": server.install_status,
            "error": server.install_error,
            "log_tail": result["log_tail"],
            "installed_version": server.installed_version,
        }
    )


@bp.route("/install/<int:server_id>/uninstall", methods=["POST"])
@admin_required
def install_uninstall(server_id):
    blocked = _demo_mode_blocked()
    if blocked:
        return blocked

    server = db.get_or_404(McpServer, server_id)
    server_name = server.name

    for selection in UserServerSelection.query.filter_by(server_id=server.id).all():
        user_proxy.stop_user_server_proxy(selection.user_id, server.id)

    installer.uninstall(server)

    db.session.delete(server)
    db.session.commit()
    _invalidate_health_cache()
    audit.log_audit_event(
        "admin_change", "success", user=current_user, server_name=server_name,
        error_message="installer-managed server uninstalled",
    )
    flash(f"Uninstalled '{server_name}'.", "success")
    return redirect(url_for("admin.install_wizard"))


@bp.route("/vaultwarden/wizard")
@admin_required
def vaultwarden_wizard():
    steps = vaultwarden.diagnose()
    return render_template(
        "admin/vaultwarden_wizard.html",
        steps=steps,
        vaultwarden_configured=secret_store.is_vaultwarden_configured(),
    )


@bp.route("/otel/wizard")
@admin_required
def otel_wizard():
    """Read-only status page + on-demand connectivity test — same pattern
    as the Vaultwarden wizard above, but for OpenTelemetry export."""
    from . import telemetry

    state = telemetry.status()
    return render_template("admin/otel_wizard.html", state=state)


@bp.route("/otel/wizard/test", methods=["POST"])
@admin_required
def otel_wizard_test():
    from . import telemetry

    ok, detail = telemetry.send_test_signal()
    flash(detail, "success" if ok else "error")
    return redirect(url_for("admin.otel_wizard"))


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

    selections = (
        UserServerSelection.query.join(User)
        .join(McpServer)
        .order_by(User.username, McpServer.name)
        .all()
    )

    user_ids = {row["user_id"] for row in rows} | {s.user_id for s in selections}
    server_ids = {row["server_id"] for row in rows} | {s.server_id for s in selections}
    users = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}
    servers = {s.id: s for s in McpServer.query.filter(McpServer.id.in_(server_ids)).all()} if server_ids else {}

    running_pairs = {(row["user_id"], row["server_id"]) for row in rows if row["running"]}

    for row in rows:
        user = users.get(row["user_id"])
        server = servers.get(row["server_id"])
        row["username"] = user.username if user else f"user#{row['user_id']}"
        row["server_name"] = server.name if server else f"server#{row['server_id']}"

    subscription_rows = [
        {
            "user_id": sel.user_id,
            "server_id": sel.server_id,
            "username": (users.get(sel.user_id).username if users.get(sel.user_id) else f"user#{sel.user_id}"),
            "server_name": (servers.get(sel.server_id).name if servers.get(sel.server_id) else f"server#{sel.server_id}"),
            "selected_at": sel.selected_at,
            "proxy_running": (sel.user_id, sel.server_id) in running_pairs,
            "is_stdio_proxy_candidate": bool(servers.get(sel.server_id) and servers[sel.server_id].command and not servers[sel.server_id].url),
        }
        for sel in selections
    ]

    return render_template(
        "admin/proxy_instances.html", rows=rows, subscription_rows=subscription_rows
    )


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
        audit.log_audit_event(
            "admin_change",
            "success",
            user=current_user,
            error_message=f"user '{user.username}' created",
        )
        flash(f"Local user '{user.username}' created.", "success")
        return redirect(url_for("admin.users_list"))
    return render_template("admin/user_form.html", user=None)


def set_user_server_permissions(user, available_servers, permission_overrides):
    """Replace user's explicit per-server ACL for available_servers.
    permission_overrides maps server_id -> is_allowed (bool); servers not
    present in the map default to allowed. Caller commits."""
    UserServerPermission.query.filter_by(user_id=user.id).delete()
    for server in available_servers:
        is_allowed = permission_overrides.get(server.id, True)
        db.session.add(
            UserServerPermission(
                user_id=user.id,
                server_id=server.id,
                is_allowed=bool(is_allowed),
            )
        )


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
        permission_overrides = {
            server.id: request.form.get(f"server_access_{server.id}", "allow") != "deny"
            for server in available_servers
        }
        set_user_server_permissions(user, available_servers, permission_overrides)

        db.session.commit()
        audit.log_audit_event(
            "admin_change",
            "success",
            user=current_user,
            error_message=f"user '{user.username}' updated",
        )
        flash(f"User '{user.username}' updated.", "success")
        return redirect(url_for("admin.users_list"))

    return render_template(
        "admin/user_form.html",
        user=user,
        available_servers=available_servers,
        permission_map=permission_map,
        clients=list(catalog.RENDERERS.keys()),
    )


@bp.route("/users/<int:user_id>/config/<client>")
@admin_required
def user_config_view(user_id, client):
    target_user = db.get_or_404(User, user_id)
    config_json, filename, error_message = catalog._build_client_config_json(client, user=target_user)
    if config_json is None:
        flash(error_message, "error")
        return redirect(url_for("admin.user_edit", user_id=user_id))

    return render_template(
        "admin/user_config_view.html",
        target_user=target_user,
        client=client,
        filename=filename,
        config_json=config_json,
    )


@bp.route("/users/<int:user_id>/config/<client>/download")
@admin_required
def user_config_download(user_id, client):
    target_user = db.get_or_404(User, user_id)
    config_json, filename, error_message = catalog._build_client_config_json(client, user=target_user)
    if config_json is None:
        flash(error_message, "error")
        audit.log_audit_event(
            "config_download",
            "error",
            user=target_user,
            error_message=(
                f"no config produced for client '{client}' "
                f"(requested by admin '{current_user.username}')"
            ),
        )
        return redirect(url_for("admin.user_edit", user_id=user_id))

    audit.log_audit_event(
        "config_download",
        "success",
        user=target_user,
        error_message=f"downloaded by admin '{current_user.username}'",
    )
    return Response(
        config_json,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def build_audit_log_query(args):
    """Filtered (unordered) AuditLogEntry query from a request.args-like
    mapping, shared by the HTML view and the JSON API. Returns
    (query, filters_dict) — filters_dict echoes back the parsed filter
    values for display/serialization."""
    query = AuditLogEntry.query

    server_id = args.get("server_id", type=int)
    if server_id:
        query = query.filter(AuditLogEntry.server_id == server_id)

    user_id = args.get("user_id", type=int)
    if user_id:
        query = query.filter(AuditLogEntry.user_id == user_id)

    since = args.get("since", "").strip()
    if since:
        parsed = _parse_datetime_local(since)
        if parsed:
            query = query.filter(AuditLogEntry.timestamp >= parsed)

    until = args.get("until", "").strip()
    if until:
        parsed = _parse_datetime_local(until)
        if parsed:
            query = query.filter(AuditLogEntry.timestamp <= parsed)

    errors_only = args.get("errors_only") == "on"
    if errors_only:
        query = query.filter(AuditLogEntry.result == "error")

    filters = {
        "server_id": server_id,
        "user_id": user_id,
        "since": since,
        "until": until,
        "errors_only": errors_only,
    }
    return query, filters


@bp.route("/audit-log")
@admin_required
def audit_log():
    """Read-only, filterable view of the append-only audit trail. No route
    exists to edit or delete individual entries — see AuditLogEntry."""
    query, filters = build_audit_log_query(request.args)
    entries = query.order_by(AuditLogEntry.timestamp.desc()).limit(500).all()

    servers = McpServer.query.order_by(McpServer.name).all()
    users = User.query.order_by(User.username).all()

    return render_template(
        "admin/audit_log.html",
        entries=entries,
        servers=servers,
        users=users,
        filters=filters,
        retention_days=current_app.config.get("AUDIT_RETENTION_DAYS"),
    )


@bp.route("/audit-log/request/<request_id>")
@admin_required
def audit_log_request(request_id):
    """All entries sharing one request_id — the full proxy -> server ->
    response chain for a single incoming request, for troubleshooting."""
    entries = (
        AuditLogEntry.query.filter_by(request_id=request_id)
        .order_by(AuditLogEntry.timestamp.asc())
        .all()
    )
    trace_url_template = current_app.config.get("OTEL_TRACE_UI_URL_TEMPLATE")
    trace_url = None
    if trace_url_template:
        try:
            trace_url = trace_url_template.format(request_id=request_id, trace_id=request_id)
        except (KeyError, IndexError):
            trace_url = None
    return render_template(
        "admin/audit_log_detail.html",
        entries=entries,
        request_id=request_id,
        trace_url=trace_url,
    )


def _parse_datetime_local(value):
    """Parse an HTML <input type="datetime-local"> value ('YYYY-MM-DDTHH:MM')."""
    from datetime import datetime

    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None
