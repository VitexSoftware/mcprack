"""DEMO_MODE write guard.

A public demo instance lets anyone log in (the credentials are even
prefilled on the login page), possibly as an admin. Registering or editing an
MCP server there would let that visitor run an arbitrary `command` as the
service user, so server registration/editing/deletion and package
installation are refused - and so are account and password changes, which
would let one visitor take the shared demo login over from everybody else.

The guard lives in ONE place - a `before_request` hook keyed on endpoint
names - instead of being sprinkled over individual routes. It used to be
called only from the HTML admin routes, which left the REST API
(`/api/v1/admin/servers`) completely unguarded (docs/AUDIT-2026-11.md A-01).
tests/test_admin_demo_mode.py walks the URL map and fails if a new
server-mutating route is added without being listed here.
"""

from flask import current_app, flash, jsonify, redirect, request, url_for

# Endpoints that register, edit, delete or install an MCP server (i.e. define
# what gets executed). Only their mutating methods are blocked: GET stays
# available so the demo can still show the pages read-only.
BLOCKED_ENDPOINTS = frozenset(
    {
        "admin.server_new",
        "admin.server_edit",
        "admin.servers_autodetect",
        "admin.server_delete",
        "admin.install_pip",
        "admin.install_npm",
        "admin.install_docker",
        "admin.install_uninstall",
        "api.admin_servers",
        "api.admin_server_update",
        "api.admin_server_delete",
        # The demo login is shared and public. Whoever changes its password,
        # creates or demotes accounts, or moves the secret store around would
        # take the demo over for everybody else.
        "auth.account_password",
        "auth.account_mfa",
        "admin.user_mfa_reset",
        "api.admin_user_mfa_reset",
        "admin.user_new",
        "admin.user_edit",
        "admin.vaultwarden_migrate_to_vaultwarden",
        "admin.vaultwarden_snapshot_to_local",
        "admin.user_revoke_tokens",
        "api.admin_users",
        "api.admin_user_update",
        "api.admin_user_delete",
        "api.admin_user_revoke_tokens",
    }
)

# Every OTHER mutating route has to be listed here, with the reason it is
# harmless on a public demo. tests/test_admin_demo_mode.py walks the URL map
# and fails for any mutating route that is in neither set, so a new route
# cannot silently skip the review (default-deny, not a name-substring match).
REVIEWED_SAFE = {
    # authentication / own account
    "auth.login": "authentication",
    "auth.logout": "ends the caller's own sessions",
    "auth.login_mfa": "second step of a login; nobody has a second factor on the demo",
    "auth.forgot_password": "reset request, rate limited",
    "auth.reset_password": "reset completion with a signed token",
    # per-user catalog state - overrides are constrained by env_policy
    # (DEMO_MODE additionally limits them to keys the server declares)
    "catalog.selection": "chooses among already registered servers",
    "catalog.override": "per-user env values, validated by env_policy",
    "catalog.user_proxy_mcp": "MCP relay (path token)",
    "catalog.user_proxy_mcp_oauth": "MCP relay (bearer)",
    "api.me_selections_set": "chooses among already registered servers",
    "api.me_override_set": "per-user env values, validated by env_policy",
    "api.me_override_delete": "removes the caller's own override",
    "api.tokens_create": "caller's own API token",
    "api.tokens_delete": "caller's own API token",
    # OAuth endpoints (only mounted with OAUTH_ENABLED)
    "oauth.authorize": "consent for the logged-in user",
    "oauth.issue_token": "token endpoint",
    "oauth.register_client": "dynamic client registration",
    "oauth.revoke_token": "token revocation",
    # admin plane that does not define what gets executed
    "admin.server_test_stdio": "starts an already registered command, registers nothing",
    "admin.proxy_instance_stop": "stops a running proxy",
    "admin.otel_wizard_test": "sends a test telemetry signal",
    "admin.template_new": "ACL/selection preset",
    "admin.template_edit": "ACL/selection preset",
    "admin.template_delete": "ACL/selection preset",
    "admin.user_apply_template": "ACL/selection preset",
    "admin.user_override": "per-user env values, validated by env_policy",
    "api.admin_templates": "ACL/selection preset",
    "api.admin_template_update": "ACL/selection preset",
    "api.admin_template_delete": "ACL/selection preset",
    "api.admin_user_apply_template": "ACL/selection preset",
    "api.admin_user_selections_set": "chooses among already registered servers",
    "api.admin_user_override_set": "per-user env values, validated by env_policy",
    "api.admin_user_override_delete": "removes a user's override",
}

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

MESSAGE = "This is a public demo instance — registering MCP servers, changing accounts and passwords, and similar actions are disabled."


def guard():
    """`before_request` hook. Returns a response to short-circuit the
    request, or None to let it through."""
    if not current_app.config.get("DEMO_MODE"):
        return None
    endpoint = request.endpoint
    if endpoint not in BLOCKED_ENDPOINTS or request.method in _SAFE_METHODS:
        return None
    if endpoint.startswith("api."):
        return jsonify(error={"code": "demo_mode", "message": MESSAGE}), 403
    flash(MESSAGE, "error")
    if endpoint.startswith("admin."):
        return redirect(url_for("admin.servers_list"))
    return redirect(url_for("catalog.index"))
