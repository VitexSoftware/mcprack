import json

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    Response,
    url_for,
)
from flask_login import current_user, login_required

import vaultwarden
from config_formats import render_claude_config, render_copilot_config
from extensions import db
from models import McpServer, UserServerOverride, UserServerSelection

bp = Blueprint("catalog", __name__)

RENDERERS = {
    "claude": (render_claude_config, "claude_desktop_config.json"),
    "copilot": (render_copilot_config, "mcp.json"),
}


@bp.route("/")
@login_required
def index():
    servers = McpServer.query.filter_by(enabled=True).order_by(McpServer.category, McpServer.name).all()
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


@bp.route("/selection", methods=["POST"])
@login_required
def selection():
    submitted_ids = {int(sid) for sid in request.form.getlist("server_id")}
    enabled_ids = {s.id for s in McpServer.query.filter_by(enabled=True).all()}
    submitted_ids &= enabled_ids

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
    if not server.allow_user_override:
        abort(403)

    override_item = f"{server.vault_item}-user-{current_user.username}"
    override_row = UserServerOverride.query.filter_by(
        user_id=current_user.id, server_id=server.id
    ).first()

    if request.method == "POST":
        if request.form.get("action") == "reset":
            try:
                with vaultwarden.session() as sess:
                    vaultwarden.delete_item(sess, override_item)
            except vaultwarden.VaultwardenError as exc:
                flash(f"Could not reach Vaultwarden: {exc} (ask an admin to check the diagnostics wizard).", "error")
                return redirect(url_for("catalog.index"))
            if override_row:
                db.session.delete(override_row)
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
            with vaultwarden.session() as sess:
                vaultwarden.set_notes(sess, override_item, values)
        except vaultwarden.VaultwardenError as exc:
            flash(f"Could not save your credentials to Vaultwarden: {exc} (ask an admin to check the diagnostics wizard).", "error")
            return redirect(url_for("catalog.index"))

        if not override_row:
            db.session.add(UserServerOverride(user_id=current_user.id, server_id=server.id))
        db.session.commit()
        flash(f"Saved your personal credentials for '{server.label}'.", "success")
        return redirect(url_for("catalog.index"))

    env_text = ""
    if override_row:
        try:
            with vaultwarden.session() as sess:
                values = vaultwarden.get_notes(sess, override_item)
        except vaultwarden.VaultwardenError as exc:
            flash(f"Could not reach Vaultwarden to load your credentials: {exc}", "error")
            values = {}
        env_text = "\n".join(f"{k}={v}" for k, v in values.items())

    return render_template(
        "override.html", server=server, env_text=env_text, has_override=bool(override_row)
    )


def _build_client_config_json(client):
    """Resolve the current user's selected+enabled servers into a rendered
    client config, as a pretty-printed JSON string. Returns None (with a
    flash already set) if there's nothing selected, or `client` is unknown."""
    if client not in RENDERERS:
        abort(404)
    render_fn, filename = RENDERERS[client]

    selected = (
        McpServer.query.join(UserServerSelection)
        .filter(UserServerSelection.user_id == current_user.id, McpServer.enabled.is_(True))
        .all()
    )

    if not selected:
        flash("You haven't selected any MCP servers yet.", "error")
        return None, filename

    try:
        with vaultwarden.session() as sess:
            entries = []
            for server in selected:
                env = vaultwarden.resolve_env(sess, server, user=current_user)
                entries.append(
                    {
                        "name": server.name,
                        "transport": server.transport,
                        "command": server.command,
                        "args": server.args,
                        "url": server.url,
                        "auth_header_name": server.auth_header_name,
                        "auth_env_key": server.auth_env_key,
                        "env": env,
                    }
                )
    except vaultwarden.VaultwardenError as exc:
        flash(
            f"Could not reach Vaultwarden to resolve credentials: {exc} "
            "(ask an admin to check Admin → Vaultwarden diagnostics).",
            "error",
        )
        return None, filename

    payload = render_fn(entries)
    return json.dumps(payload, indent=2), filename


@bp.route("/download/<client>")
@login_required
def download(client):
    config_json, filename = _build_client_config_json(client)
    if config_json is None:
        return redirect(url_for("catalog.index"))

    return Response(
        config_json,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@bp.route("/view/<client>")
@login_required
def view(client):
    config_json, filename = _build_client_config_json(client)
    if config_json is None:
        return redirect(url_for("catalog.index"))

    return render_template(
        "view_config.html", client=client, filename=filename, config_json=config_json
    )
