"""Fresh authentication ("sudo mode") before the dangerous administrator actions
(docs/AUDIT-2026-11.md B-08).

An administrator's browser session can be stolen - an XSS, a copied cookie, a
shared machine - and a stolen session has already passed the password and the
second factor. The actions below are the ones that let an attacker keep control or
run code: registering what the service executes, installing packages, creating or
changing accounts, resetting somebody's second factor, moving the secret store.
They therefore need the password (and the code, if the account has MFA) AGAIN,
unless the session was authenticated in the last ADMIN_REAUTH_SECONDS (10 minutes
by default; signing in counts). Everything else an administrator does stays one
click.

One `before_request` hook keyed on endpoint names - the way demo.py works - rather
than a decorator on each route. tests/test_reauth.py walks the URL map and fails
for any mutating admin endpoint that is in neither SENSITIVE_ENDPOINTS nor
REVIEWED_NOT_SENSITIVE, so a new admin route cannot skip the decision.

Bearer-token requests are not affected: a token is a credential of its own, with
scopes and an expiry. Only browser (cookie) sessions are.
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

from flask import current_app, flash, g, redirect, request, session, url_for
from flask_babel import _
from flask_login import current_user

SENSITIVE_ENDPOINTS = frozenset(
    {
        # what the service user runs, and what gets installed for it
        "admin.server_new",
        "admin.server_edit",
        "admin.server_delete",
        "admin.servers_autodetect",
        "admin.install_pip",
        "admin.install_npm",
        "admin.install_docker",
        "admin.install_uninstall",
        # accounts, privileges and second factors
        "admin.user_new",
        "admin.user_edit",
        "admin.user_mfa_reset",
        # the secret store
        "admin.vaultwarden_migrate_to_vaultwarden",
        "admin.vaultwarden_snapshot_to_local",
        # the same, over the REST API (cookie sessions only)
        "api.admin_servers",
        "api.admin_server_update",
        "api.admin_server_delete",
        "api.admin_users",
        "api.admin_user_update",
        "api.admin_user_delete",
        "api.admin_user_mfa_reset",
    }
)

# Every other mutating admin endpoint, with the reason it needs no fresh login.
REVIEWED_NOT_SENSITIVE = {
    "admin.otel_wizard_test": "sends a test telemetry signal",
    "admin.proxy_instance_stop": "stops a running proxy; harmless",
    "admin.server_test_stdio": "starts an already registered command, registers nothing",
    "admin.template_new": "ACL/selection preset",
    "admin.template_edit": "ACL/selection preset",
    "admin.template_delete": "ACL/selection preset",
    "admin.user_apply_template": "ACL/selection preset",
    "admin.user_override": "per-user env values, validated by env_policy",
    "admin.user_revoke_tokens": "a defensive action: takes access away",
    "api.admin_templates": "ACL/selection preset",
    "api.admin_template_update": "ACL/selection preset",
    "api.admin_template_delete": "ACL/selection preset",
    "api.admin_user_apply_template": "ACL/selection preset",
    "api.admin_user_selections_set": "chooses among already registered servers",
    "api.admin_user_override_set": "per-user env values, validated by env_policy",
    "api.admin_user_override_delete": "removes a user's override",
    "api.admin_user_revoke_tokens": "a defensive action: takes access away",
}

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def window():
    """Seconds a sign-in or re-authentication stays fresh; 0 switches the check off."""
    return int(current_app.config.get("ADMIN_REAUTH_SECONDS", 600))


def mark_fresh():
    session["reauth_at"] = int(time.time())


def is_fresh():
    stamp = session.get("reauth_at")
    if not isinstance(stamp, int) or isinstance(stamp, bool):
        return False  # a session from before this existed, or a mangled value
    age = time.time() - stamp
    return 0 <= age <= window()  # a timestamp in the future is not "fresh"


def _return_target():
    """Where to come back to after re-authenticating: the page, or for a POST the
    page it was submitted from (the form data is lost - the user submits again)."""
    if request.method in _SAFE_METHODS:
        return request.full_path.rstrip("?")
    referrer = urlsplit(request.referrer or "")
    if referrer.netloc == request.host and referrer.path.startswith("/") and not referrer.path.startswith("//"):
        return referrer.path + (f"?{referrer.query}" if referrer.query else "")
    return url_for("admin.servers_list")


def guard():
    """`before_request` hook."""
    endpoint = request.endpoint
    if endpoint not in SENSITIVE_ENDPOINTS or request.method in _SAFE_METHODS:
        return None
    cfg = current_app.config
    if window() <= 0 or cfg.get("DEMO_MODE"):
        return None
    # Resolving current_user loads the session user and then - only if there is
    # none - the bearer token, which sets g.api_token. A token request is not ours
    # to judge; a request with a session cookie is, whatever else it carries.
    if not current_user.is_authenticated or getattr(g, "api_token", None) is not None:
        return None
    if not current_user.is_admin:
        return None  # the route's own decorator answers 403
    if is_fresh():
        return None

    if request.blueprint == "api":
        from .api import api_error

        return api_error(
            403,
            "reauth_required",
            "Confirm your password (and code) first: POST /api/v1/auth/reauth. "
            f"The confirmation is valid for {window()} seconds.",
        )
    flash(_("Please confirm your password to continue. Your changes were not saved - submit them again afterwards."), "error")
    return redirect(url_for("auth.reauth_view", next=_return_target()))

