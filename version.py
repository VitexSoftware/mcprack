import os
import re
import subprocess

_CHANGELOG_PATH = os.path.join(os.path.dirname(__file__), "debian", "changelog")
_CHANGELOG_VERSION_RE = re.compile(r"^\S+ \(([^)]+)\)")


def _from_dpkg():
    """Installed-package version, authoritative when running from the
    Debian package (debian/changelog itself isn't shipped, only baked into
    the installed package's metadata)."""
    try:
        result = subprocess.run(
            ["dpkg-query", "--showformat=${Version}", "-W", "mcprack"],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None if result.returncode == 0 else None


def _from_changelog():
    """Fallback for running straight from a git checkout (no .deb installed)."""
    try:
        with open(_CHANGELOG_PATH, encoding="utf-8") as f:
            first_line = f.readline()
    except OSError:
        return None
    match = _CHANGELOG_VERSION_RE.match(first_line)
    return match.group(1) if match else None


def get_version():
    """Current mcprack version, for display (e.g. the page footer). Prefers
    debian/changelog (accurate for a git checkout) and falls back to the
    installed package's version (changelog isn't shipped in the .deb)."""
    return _from_changelog() or _from_dpkg() or "dev"
