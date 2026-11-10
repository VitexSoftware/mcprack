"""Absolute URLs that leave the application.

Behind a reverse proxy the request's own host and scheme are whatever the
client sent (Host / X-Forwarded-* headers), so a URL built from them can be
steered by an attacker. Anything that is e-mailed or handed to another
system must be built from the configured PUBLIC_BASE_URL instead
(docs/AUDIT-2026-11.md A-05).
"""

import re

from flask import current_app, url_for

# What a legitimate mount point (X-Forwarded-Prefix -> SCRIPT_NAME) looks like:
# "/mcprack", "/tools/mcprack". Anything else - "//evil.example", "/a/../b",
# "javascript:", backslashes, control characters - is not a path prefix and
# would turn every url_for() and redirect into a link to somewhere else.
_SAFE_PREFIX = re.compile(r"^(?:/[A-Za-z0-9._~-]+)*$")


def sanitize_script_name(wsgi_app):
    """WSGI middleware: drop a SCRIPT_NAME that is not a plain path prefix
    (docs/AUDIT-2026-11.md C-04). It must run AFTER ProxyFix has turned
    X-Forwarded-Prefix into SCRIPT_NAME, i.e. sit *inside* it - see
    `trust_one_proxy_hop`, which is the only place the two are composed."""

    def middleware(environ, start_response):
        prefix = environ.get("SCRIPT_NAME", "")
        if prefix and (not _SAFE_PREFIX.match(prefix) or ".." in prefix.split("/")):
            environ["SCRIPT_NAME"] = ""
        return wsgi_app(environ, start_response)

    return middleware


def external_url(endpoint, **values):
    """Absolute URL for `endpoint`: PUBLIC_BASE_URL + path when configured,
    otherwise (development, no reverse proxy) derived from the request."""
    base_url = (current_app.config.get("PUBLIC_BASE_URL") or "").rstrip("/")
    if base_url:
        return f"{base_url}{url_for(endpoint, **values)}"
    return url_for(endpoint, _external=True, **values)


def trust_one_proxy_hop(flask_app):
    """Put the reverse-proxy handling in front of `flask_app` (wsgi.py calls
    this; tests call it too, so the order is exercised, not just described).

    ProxyFix trusts exactly one hop of X-Forwarded-For/-Proto/-Host/-Prefix.
    The sanitizer is wrapped *inside* it: WSGI middleware run outermost-first,
    so only a sanitizer that is called by ProxyFix sees the SCRIPT_NAME
    ProxyFix has just derived from the client-controllable header. (Wrapped
    outside, it ran first, saw an empty SCRIPT_NAME and did nothing.)"""
    from werkzeug.middleware.proxy_fix import ProxyFix

    flask_app.wsgi_app = ProxyFix(
        sanitize_script_name(flask_app.wsgi_app), x_for=1, x_proto=1, x_host=1, x_prefix=1
    )
    return flask_app
