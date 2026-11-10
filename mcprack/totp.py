"""TOTP (RFC 6238) on top of HOTP (RFC 4226), standard library only.

Every authenticator app implements exactly this - HMAC-SHA1, 6 digits, 30 second
steps - and the algorithm is short enough to read in full. Writing it here
instead of depending on `pyotp` keeps `debian/control` unchanged and leaves
nothing new to patch or pin; tests/test_totp.py runs it against the test vectors
published in the two RFCs.

Nothing here touches the database or the request: it is arithmetic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6
SECRET_BYTES = 20  # 160 bits, the length RFC 4226 recommends


def generate_secret() -> str:
    """A fresh shared secret, base32 without padding (what authenticator apps take)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    cleaned = "".join(secret.split()).upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def hotp(secret: str, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 section 5.3: HMAC-SHA1 over the 8-byte counter, dynamic truncation."""
    mac = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def normalise_code(code: str | None) -> str | None:
    """What the user typed, reduced to the digits - or None when it cannot be a
    TOTP code (authenticator apps show them as '123 456')."""
    if not code:
        return None
    cleaned = "".join(code.split()).replace("-", "")
    return cleaned if len(cleaned) == DIGITS and cleaned.isascii() and cleaned.isdigit() else None


def match(secret: str, code: str | None, *, now: float | None = None, window: int = 1, after_step: int = 0):
    """The time step `code` is valid for, or None.

    `window` steps either side of the current one are accepted (clock drift, the
    time it takes to type). Only a step *after* `after_step` is accepted: the
    caller stores the step it last accepted, so a code that has been used once -
    typed over a shoulder, captured by a phishing proxy - cannot be used again
    within its validity. All candidate steps are compared, in constant time,
    whatever matches."""
    candidate = normalise_code(code)
    if candidate is None:
        return None
    step = current_step(now)
    found = None
    for candidate_step in range(step - window, step + window + 1):
        equal = hmac.compare_digest(hotp(secret, candidate_step), candidate)
        if equal and candidate_step > after_step and found is None:
            found = candidate_step
    return found


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """The otpauth:// URI the authenticator apps import (usually as a QR code)."""
    label = quote(f"{issuer}:{account}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )


def group(secret: str, size: int = 4) -> str:
    """The secret in groups, for typing it into an app by hand."""
    return " ".join(secret[i : i + size] for i in range(0, len(secret), size))


# --- recovery codes ---------------------------------------------------------------------------

# No I, O, 0 or 1: they get misread off a printout.
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
RECOVERY_CODE_LENGTH = 12  # 12 x 5 bits = 60 bits


def generate_recovery_code() -> str:
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(RECOVERY_CODE_LENGTH))
    return "-".join(raw[i : i + 4] for i in range(0, RECOVERY_CODE_LENGTH, 4))


def normalise_recovery_code(code: str | None) -> str | None:
    if not code:
        return None
    cleaned = "".join(code.split()).replace("-", "").upper()
    if len(cleaned) != RECOVERY_CODE_LENGTH or any(ch not in _RECOVERY_ALPHABET for ch in cleaned):
        return None
    return cleaned
