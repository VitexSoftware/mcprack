"""Probe an MCP endpoint the way a client does: initialize, then tools/list.

Used by `mcprack user config verify`. It talks plain HTTP to the URL a
generated client configuration contains - through the reverse proxy, TLS and the
relay, to the MCP server behind it - so a green result means the whole chain a
client depends on works, not just that the application is up. (The stand-alone
`bin/mcprack-mcp-probe` does the same for an operator who has only a URL.)

Whatever carries the credential - the Authorization header, or the signed path
token inside the URL of the older client formats - is sent only over https or to
loopback, and redirects are never followed: a redirect would carry it to whatever
host the answer names. The check applies to EVERY probe, not only to ones with a
bearer token, because a URL may be the credential.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

# The newest protocol revision this relay's clients speak. A server answers with
# the highest revision it supports that is not newer than this, and the answer is
# reported - so "which version did we actually get" is visible, not assumed.
PROTOCOL_VERSION = "2025-06-18"
CLIENT_NAME = "mcprack-verify"
MAX_BODY_BYTES = 8 * 1024 * 1024
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


@dataclass
class ProbeResult:
    ok: bool
    step: str  # the step that failed, or "tools/list" when ok
    detail: str = ""
    tools: int = 0
    protocol: str = ""
    seconds: float = 0.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _transport_ok(url, *, allow_insecure):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" or parts.hostname in _LOOPBACK or allow_insecure


def _post(url, payload, headers, timeout):
    """(status, response headers, body) - the default transport."""
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(MAX_BODY_BYTES + 1)


def _json_rpc_message(body, request_id):
    """The JSON-RPC response with `request_id` from a plain JSON or SSE body."""
    text = body.decode("utf-8", "replace")
    candidates = [text] if text.lstrip().startswith("{") else [
        line[5:].strip() for line in text.splitlines() if line.startswith("data:")
    ]
    for candidate in candidates:
        try:
            message = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(message, dict) and message.get("id") == request_id and ("result" in message or "error" in message):
            return message
    return None


def _short(text, limit=200):
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))[:limit]


def probe(url, *, bearer=None, timeout=60.0, allow_insecure=False, transport=_post) -> ProbeResult:
    """initialize + tools/list against `url`. Never raises for a failing server:
    the failure is in the result."""
    started = time.monotonic()

    def failed(step, detail):
        return ProbeResult(False, step, _short(detail), seconds=time.monotonic() - started)

    if not _transport_ok(url, allow_insecure=allow_insecure):
        return failed(
            "initialize",
            "refusing to send the credential over plain http to a non-loopback host - the token is in the "
            "Authorization header or in the URL itself (use https, or --insecure on a trusted network)",
        )

    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    def call(payload, extra=None):
        merged = {**headers, **(extra or {})}
        try:
            return transport(url, payload, merged, timeout)
        except (OSError, ValueError) as exc:  # URLError, timeouts, refused connections
            return exc

    first = call(
        {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": CLIENT_NAME, "version": "1.0"}},
        }
    )
    if isinstance(first, Exception):
        reason = getattr(first, "reason", first)
        return failed("initialize", f"could not connect: {reason}")
    status, response_headers, body = first
    if 300 <= status < 400:
        return failed("initialize", f"HTTP {status} redirect - not followed while a token is sent")
    if status == 401:
        return failed("initialize", "HTTP 401 - the credential was not accepted")
    if status == 405:
        return failed("initialize", "HTTP 405 - this URL does not accept POST (is it the right endpoint?)")
    message = _json_rpc_message(body, 1)
    if status >= 400 and message is None:
        return failed("initialize", f"HTTP {status}")
    if message is None:
        return failed("initialize", f"HTTP {status} but no JSON-RPC answer")
    if "error" in message:
        error = message["error"]
        return failed("initialize", error.get("message") if isinstance(error, dict) else error)
    result = message.get("result") or {}
    protocol = str(result.get("protocolVersion", ""))

    session = {k: v for k, v in response_headers.items() if k.lower() == "mcp-session-id"}
    call({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    listing = call({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, session)
    if isinstance(listing, Exception):
        return failed("tools/list", f"could not connect: {getattr(listing, 'reason', listing)}")
    status, _headers, body = listing
    message = _json_rpc_message(body, 2)
    if message is None:
        return failed("tools/list", f"HTTP {status}, no JSON-RPC answer")
    if "error" in message:
        error = message["error"]
        return failed("tools/list", error.get("message") if isinstance(error, dict) else error)
    tools = (message.get("result") or {}).get("tools") or []
    if not tools:
        return ProbeResult(
            False, "tools/list", "the server answered but offers no tools (it probably crashed while loading)",
            protocol=protocol, seconds=time.monotonic() - started,
        )
    return ProbeResult(True, "tools/list", tools=len(tools), protocol=protocol, seconds=time.monotonic() - started)
