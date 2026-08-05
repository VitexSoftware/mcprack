import importlib.metadata
import os
import re
import subprocess

# mcprack/version.py -> repo root is one directory up from the mcprack/
# package; debian/changelog lives there in a git checkout, but is never
# shipped inside the installed package itself (Debian .deb or PyPI wheel).
_CHANGELOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "debian", "changelog"
)
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


def _from_pip_metadata():
    """Authoritative when running from a pip/venv install: scoped to
    *this* Python environment's installed distributions, unlike dpkg-query
    which reflects unrelated system-wide package state. Checked before
    _from_dpkg() so a pip-installed mcprack never reports the version of
    a completely separate .deb install that happens to exist on the same
    machine (e.g. a developer machine with both a system install and a
    venv checkout)."""
    try:
        return importlib.metadata.version("mcprack")
    except importlib.metadata.PackageNotFoundError:
        return None


def get_version():
    """Current mcprack version, for display (e.g. the page footer). Prefers
    debian/changelog (accurate for a git checkout), then this environment's
    own pip-installed distribution metadata, then dpkg's system-wide record
    as a last resort (relevant only for the actual Debian-installed copy,
    where there's no separate venv to shadow it)."""
    return _from_changelog() or _from_pip_metadata() or _from_dpkg() or "dev"
