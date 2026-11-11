"""QR code of the TOTP provisioning address, as an inline SVG.

Rendered on the server so the shared secret never leaves mcprack (no QR web
service), and as SVG so the page's Content-Security-Policy needs no exception.
`segno` is optional: without it `svg()` returns None and the setup page shows
only the key and the otpauth:// address, as before.
"""

from __future__ import annotations

from markupsafe import Markup

try:  # pragma: no cover - exercised by whether python3-segno is installed
    import segno
except ImportError:  # pragma: no cover
    segno = None


def available() -> bool:
    return segno is not None


def svg(data: str, *, title: str = "", description: str = "") -> Markup | None:
    """`data` as a QR code, or None when segno is missing.

    The title and description are fixed, translated texts for screen readers;
    `data` (it holds the secret) is never put into them. Error level M, four
    modules of quiet zone: what phone scanners expect."""
    if segno is None:
        return None
    code = segno.make(data, error="m", micro=False)
    return Markup(
        code.svg_inline(
            scale=6,
            border=4,
            omitsize=True,
            dark="#000000",
            light="#ffffff",
            svgclass="qr-code",
            title=title or None,
            desc=description or None,
        )
    )
