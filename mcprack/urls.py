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
    """WSGI middleware, applied after ProxyFix: drop a SCRIPT_NAME that is not a
    plain path prefix (docs/AUDIT-2026-11.md C-04)."""

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
