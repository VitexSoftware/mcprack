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
import re
import socket
from urllib.parse import urlsplit

from flask import current_app

# Cloud instance-metadata aliases that are *names*, not addresses.
_METADATA_NAMES = frozenset(
    {"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}
)


# The legacy numeric spellings of an IPv4 address that every C resolver still
# accepts: "2852039166", "0xa9fea9fe", "0251.0376.0251.0376", "169.254.43518",
# "127.1". `ipaddress` rejects them all, so a check that only asked `ipaddress`
# would call them "a host name" while the connection goes to 169.254.169.254.
_LEGACY_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}", re.IGNORECASE)


def _literal_address(name: str):
    """The address `name` stands for when it is a literal one - read the way
    the resolver reads it - else None. Raises ValueError for something that is
    numeric in form but not an address (999.1.1.1)."""
    try:
        return ipaddress.ip_address(name)
    except ValueError:
        pass
    if _LEGACY_NUMERIC_HOST.fullmatch(name):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(name))
        except OSError as exc:
            raise ValueError(name) from exc
    return None


def destination_errors(url: str | None) -> list[str]:
    """Why the *destination* of `url` is unacceptable (empty = acceptable).
    This is the part that is also enforced when the relay connects, so a server
    registered before the policy existed cannot be used to reach it either."""
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

    if current_app.config.get("BACKEND_ALLOW_LINK_LOCAL", False):
        return errors

    name = hostname.rstrip(".").lower()
    if name in _METADATA_NAMES:
        errors.append("That host name is a cloud metadata service - it is never a legitimate MCP backend.")
    try:
        address = _literal_address(name)
    except ValueError:
        errors.append("The host looks like a numeric address but is not a valid one.")
        return errors
    if address is None:
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


def url_errors(url: str | None) -> list[str]:
    """Reasons `url` must not be *registered* as a backend: its destination, plus
    credentials in the URL (stored and logged in clear text)."""
    if not url:
        return []
    errors = destination_errors(url)
    try:
        parts = urlsplit(url)
        if parts.username is not None or parts.password is not None:
            errors.append(
                "Do not put credentials into the URL: it is stored and logged in clear text. "
                "Use the server's auth header / environment settings instead."
            )
    except ValueError:
        pass
    return errors
