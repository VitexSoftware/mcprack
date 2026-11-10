"""Which backend URLs an administrator may register (docs/AUDIT-2026-11.md B-09).

A server's `url` is where mcprack's relay connects, from the mcprack host, with
the server's credentials attached. Nobody but an administrator can set it - but
an administrator account is exactly what an attacker is after, and a relay that
will talk to *anything* is a ready-made request forger for the network behind
it. So the obviously wrong destinations are refused at the door, and the rest is
left to the network (an egress policy for the service user - see README.Debian).

Not checked on purpose: host names are not resolved here. A name resolves to
whatever DNS says at connection time, so a check now proves nothing later, and a
lookup in a request handler is its own problem. Literal addresses are checked;
names are checked against the cloud-metadata aliases.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from flask import current_app

# Cloud instance-metadata aliases that are *names*, not addresses.
_METADATA_NAMES = frozenset(
    {"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}
)


def url_errors(url: str | None) -> list[str]:
    """Reasons `url` must not be registered as a backend (empty = acceptable)."""
    if not url:
        return []
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        parts.port  # noqa: B018 - raises ValueError for a malformed port
    except ValueError:
        return ["The URL is not valid."]

    errors: list[str] = []
    if parts.scheme not in ("http", "https"):
        errors.append("The URL must start with http:// or https:// (other schemes are not relayed).")
    if not hostname:
        errors.append("The URL has no host.")
        return errors
    if parts.username is not None or parts.password is not None:
        errors.append(
            "Do not put credentials into the URL: it is stored and logged in clear text. "
            "Use the server's auth header / environment settings instead."
        )

    if current_app.config.get("BACKEND_ALLOW_LINK_LOCAL", False):
        return errors

    name = hostname.rstrip(".").lower()
    if name in _METADATA_NAMES:
        errors.append("That host name is a cloud metadata service - it is never a legitimate MCP backend.")
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return errors
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped  # ::ffff:169.254.169.254 is the same address
    if address.is_link_local:
        errors.append(
            "Link-local addresses (169.254.0.0/16, fe80::/10 - cloud metadata services live here) are refused. "
            "Set BACKEND_ALLOW_LINK_LOCAL=true if you really run a backend there."
        )
    if address.is_unspecified:
        errors.append("0.0.0.0 / :: is not a destination.")
    if address.is_multicast:
        errors.append("Multicast addresses are not destinations.")
    return errors
