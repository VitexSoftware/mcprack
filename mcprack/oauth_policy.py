"""Which redirect URIs a dynamically registered OAuth client may use.

Dynamic client registration is open (MCP clients have no prior relationship
with the server), so without a policy anyone could register a client named
"Claude" that sends the authorization code to a host of their choosing and
then phish a logged-in user into approving it (docs/AUDIT-2026-11.md A-07).
The MCP security guidance asks for exact, validated redirect URIs and a
consent page that shows them.

Allowed:
* http://localhost | 127.0.0.1 | [::1], any port, any path (RFC 8252 loopback
  redirect for native and CLI clients - Claude Code uses
  http://localhost:<port>/callback);
* https:// to a host listed in OAUTH_ALLOWED_REDIRECT_HOSTS (exact name or
  "*.suffix"); the default covers the hosted Claude clients;
* anything starting with an entry of OAUTH_ALLOWED_REDIRECT_PREFIXES
  (custom schemes, e.g. "vscode://", explicitly opted into).
Never: fragments, embedded credentials, plain http to a non-loopback host,
javascript:/data:/file: and other schemes.
"""

import re
from urllib.parse import urlsplit

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# A strict DNS name (or IPv4 literal), checked BEFORE any allowlist comparison:
# URL parsers disagree about backslashes, non-ASCII look-alikes, userinfo and
# odd authorities, and an allowlist test is only as good as the parser that
# feeds it.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
MAX_URIS_PER_CLIENT = 10
MAX_URI_LENGTH = 512


def _csv(value):
    return [item.strip().lower() for item in (value or "").split(",") if item.strip()]


def is_loopback(uri):
    parts = urlsplit(uri)
    return parts.scheme == "http" and (parts.hostname or "").lower() in LOOPBACK_HOSTS


def _host_allowed(host, allowed):
    host = host.lower()
    for entry in allowed:
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and host != entry[2:]:
                return True
        elif host == entry:
            return True
    return False


def check_redirect_uri(uri, config):
    """None when `uri` is acceptable, else a message."""
    if not isinstance(uri, str) or not uri or len(uri) > MAX_URI_LENGTH:
        return "redirect_uri must be a non-empty string of reasonable length"
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in uri):
        return "redirect_uri must be plain ASCII without whitespace or control characters"
    if "\\" in uri:
        return "redirect_uri must not contain a backslash"
    parts = urlsplit(uri)
    if parts.fragment or "#" in uri:
        return "redirect_uri must not contain a fragment"
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return "redirect_uri must not contain credentials"

    for prefix in (config.get("OAUTH_ALLOWED_REDIRECT_PREFIXES") or "").split(","):
        prefix = prefix.strip()
        if prefix and uri.startswith(prefix):
            return None

    host = (parts.hostname or "")
    try:
        port = parts.port
    except ValueError:
        return "redirect_uri has an invalid port"
    # the authority must be exactly host[:port] - nothing the parser might have
    # skipped over
    expected = f"[{host}]" if ":" in host else host
    if port is not None:
        expected += f":{port}"
    if parts.netloc.lower() != expected.lower():
        return "redirect_uri has an unusual authority"
    if parts.scheme == "http" and host.lower() in LOOPBACK_HOSTS:
        return None
    if (
        parts.scheme == "https"
        and host
        and _HOSTNAME.match(host.lower())
        and _host_allowed(host, _csv(config.get("OAUTH_ALLOWED_REDIRECT_HOSTS")))
    ):
        return None
    return (
        "redirect_uri is not allowed: use a loopback address (http://localhost:<port>/...) or an https URL on a "
        "host this server trusts (OAUTH_ALLOWED_REDIRECT_HOSTS)"
    )


def check_redirect_uris(uris, config):
    """None when every URI passes, else the first message."""
    if not isinstance(uris, (list, tuple)) or not uris:
        return "redirect_uris must be a non-empty list"
    if len(uris) > MAX_URIS_PER_CLIENT:
        return f"at most {MAX_URIS_PER_CLIENT} redirect_uris are accepted"
    for uri in uris:
        problem = check_redirect_uri(uri, config)
        if problem:
            return problem
    return None
