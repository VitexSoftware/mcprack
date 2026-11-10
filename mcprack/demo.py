"""DEMO_MODE write guard.

A public demo instance lets anyone log in (the credentials are even
prefilled on the login page), possibly as an admin. Registering or editing an
MCP server there would let that visitor run an arbitrary `command` as the
service user, so server registration/editing/deletion and package
installation are refused.

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
    }
)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

MESSAGE = "This is a public demo instance — registering, editing, and deleting MCP servers is disabled."


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
    return redirect(url_for("admin.servers_list"))
