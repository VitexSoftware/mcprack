"""Absolute URLs that leave the application.

Behind a reverse proxy the request's own host and scheme are whatever the
client sent (Host / X-Forwarded-* headers), so a URL built from them can be
steered by an attacker. Anything that is e-mailed or handed to another
system must be built from the configured PUBLIC_BASE_URL instead
(docs/AUDIT-2026-11.md A-05).
"""

from flask import current_app, url_for


def external_url(endpoint, **values):
    """Absolute URL for `endpoint`: PUBLIC_BASE_URL + path when configured,
    otherwise (development, no reverse proxy) derived from the request."""
    base_url = (current_app.config.get("PUBLIC_BASE_URL") or "").rstrip("/")
    if base_url:
        return f"{base_url}{url_for(endpoint, **values)}"
    return url_for(endpoint, _external=True, **values)
