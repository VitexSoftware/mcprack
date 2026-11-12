import os
import subprocess
import time
import xml.etree.ElementTree as ET
from glob import glob
from urllib.parse import urlsplit


INDEX_TTL = 300
_index_cache = None
_index_time = 0.0

_ICON_DIRS = (
    "/usr/share/icons/hicolor/scalable/apps",
    "/usr/share/icons/hicolor/512x512/apps",
    "/usr/share/icons/hicolor/256x256/apps",
    "/usr/share/icons/hicolor/128x128/apps",
    "/usr/share/icons/hicolor/64x64/apps",
    "/usr/share/icons/hicolor/48x48/apps",
    "/usr/share/icons/hicolor/32x32/apps",
    "/usr/share/icons/hicolor/24x24/apps",
    "/usr/share/icons/hicolor/16x16/apps",
    "/usr/share/pixmaps",
    "/var/lib/app-info/icons",
    "/var/cache/app-info/icons",
)

_SAFE_PREFIXES = (
    "/usr/share/icons",
    "/usr/share/pixmaps",
    "/var/lib/app-info/icons",
    "/var/cache/app-info/icons",
)


def _tag_name(elem):
    if "}" in elem.tag:
        return elem.tag.rsplit("}", 1)[1]
    return elem.tag


def _first_text(parent, tag):
    for child in parent:
        if _tag_name(child) == tag and child.text:
            return child.text.strip()
    return None


def _candidate_icon_names(component):
    names = []
    for child in component:
        if _tag_name(child) != "icon":
            continue
        if not child.text:
            continue
        icon_name = child.text.strip()
        if icon_name:
            names.append(icon_name)
    return names


def _component_binaries(component):
    binaries = set()
    for child in component:
        if _tag_name(child) != "provides":
            continue
        for provided in child:
            if _tag_name(provided) == "binary" and provided.text:
                name = provided.text.strip()
                if name:
                    binaries.add(name)
    return binaries


def _component_pkgname(component):
    return _first_text(component, "pkgname")


def _iter_metainfo_files():
    """Every AppStream metainfo file on the system that is actually a file.
    The isfile() guard is not paranoia - see the ardour case below."""
    patterns = (
        "/usr/share/metainfo/*.xml",
        "/usr/share/appdata/*.xml",
    )
    for pattern in patterns:
        for path in glob(pattern):
            # Debian's ardour ships /usr/share/metainfo/ardour.appdata.xml as a
            # *directory* of per-version files, so the glob can match something
            # ET.parse() cannot open.
            if os.path.isfile(path):
                yield path


def _resolve_icon_file(icon_name):
    if os.path.isabs(icon_name) and os.path.isfile(icon_name):
        return icon_name

    # Icon names are often dotted reverse-DNS ids (cz.vitexsoftware.foo), so
    # splitext() would wrongly treat the last label as a file extension.
    # Only skip suffix probing when the name already ends in an image extension.
    names = [icon_name]
    if not icon_name.lower().endswith((".svg", ".png", ".xpm", ".svgz")):
        names.extend([f"{icon_name}.svg", f"{icon_name}.png", f"{icon_name}.xpm"])

    for icon_dir in _ICON_DIRS:
        if not os.path.isdir(icon_dir):
            continue
        for name in names:
            candidate = os.path.join(icon_dir, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _children(component, tag):
    return [c for c in component if _tag_name(c) == tag]


def _paragraphs(description):
    """Plain-text paragraphs and list items of an AppStream <description>."""
    out = []
    if description is None:
        return out
    for child in description:
        name = _tag_name(child)
        if name == "p":
            text = " ".join("".join(child.itertext()).split())
            if text:
                out.append(text)
        elif name in ("ul", "ol"):
            items = [" ".join("".join(li.itertext()).split()) for li in child if _tag_name(li) == "li"]
            items = [i for i in items if i]
            if items:
                out.append(items)
    return out


def _component_meta(component):
    """What the server's own AppStream metainfo says about it - shown on the
    server page. All values are plain text (never markup) and urls are kept
    only when they are http(s)."""
    urls = {}
    for u in _children(component, "url"):
        kind = u.get("type")
        text = (u.text or "").strip()
        try:
            parsed = urlsplit(text)
        except ValueError:
            continue
        if kind and parsed.scheme in ("http", "https") and parsed.hostname:
            urls.setdefault(kind, text)

    developer = None
    for dev in _children(component, "developer"):
        developer = _first_text(dev, "name")
    if developer is None:
        developer = _first_text(component, "developer_name")

    descriptions = _children(component, "description")
    releases = []
    for rels in _children(component, "releases"):
        for rel in _children(rels, "release"):
            if rel.get("version"):
                releases.append({"version": rel.get("version"), "date": rel.get("date")})

    return {
        "id": _first_text(component, "id"),
        "name": _first_text(component, "name"),
        "summary": _first_text(component, "summary"),
        "description": _paragraphs(descriptions[0]) if descriptions else [],
        "license": _first_text(component, "project_license"),
        "developer": developer,
        "urls": urls,
        "categories": [
            (c.text or "").strip()
            for cats in _children(component, "categories")
            for c in _children(cats, "category")
            if (c.text or "").strip()
        ],
        "latest_release": releases[0] if releases else None,
    }


def _build_index():
    by_binary = {}
    by_package = {}
    meta_by_binary = {}
    meta_by_package = {}
    for path in _iter_metainfo_files():
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            continue

        components = [root]
        if _tag_name(root) == "components":
            components = [c for c in root if _tag_name(c) == "component"]

        for component in components:
            if _tag_name(component) != "component":
                continue

            meta = _component_meta(component)
            pkgname = _component_pkgname(component)
            if pkgname:
                meta_by_package.setdefault(pkgname, meta)
            for binary in _component_binaries(component):
                meta_by_binary.setdefault(binary, meta)

            icon_path = None
            for icon_name in _candidate_icon_names(component):
                icon_path = _resolve_icon_file(icon_name)
                if icon_path:
                    break

            if not icon_path:
                continue

            if pkgname and pkgname not in by_package:
                by_package[pkgname] = icon_path

            for binary in _component_binaries(component):
                by_binary.setdefault(binary, icon_path)

    return {
        "by_binary": by_binary,
        "by_package": by_package,
        "meta_by_binary": meta_by_binary,
        "meta_by_package": meta_by_package,
    }


def _get_index():
    global _index_cache, _index_time
    now = time.time()
    if _index_cache is None or (now - _index_time) > INDEX_TTL:
        _index_cache = _build_index()
        _index_time = now
    return _index_cache


def _binary_candidates(server):
    candidates = set()
    if server.command:
        candidates.add(os.path.basename(server.command))
    candidates.add(server.name)
    if server.name.endswith("-mcp"):
        candidates.add(server.name[:-4])
    # Servers are often registered under a short name ("netbox", "zabbix")
    # while the packaged binary follows a naming convention.
    for pattern in ("{}-mcp", "{}-mcp-server", "mcp-server-{}", "mcp-{}-python"):
        candidates.add(pattern.format(server.name))
    return {c for c in candidates if c}


# `dpkg-query -S` walks the whole package database. It used to run, unbounded,
# on every icon lookup - i.e. while rendering a page - so a slow or wedged dpkg
# held a request thread for as long as it liked (docs/AUDIT-2026-11.md B-14).
_DPKG_TIMEOUT = 5  # seconds
_DPKG_CACHE_TTL = 600  # seconds; which package owns a file changes only on (un)install
_dpkg_cache = {}


def _owning_package(command):
    """The Debian package that owns `command`, or None. Bounded in time and
    remembered for a while - including "unknown", so a failing lookup is not
    retried on every request."""
    now = time.monotonic()
    cached = _dpkg_cache.get(command)
    if cached is not None and now - cached[0] < _DPKG_CACHE_TTL:
        return cached[1]
    package = None
    try:
        result = subprocess.run(
            ["dpkg-query", "-S", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=_DPKG_TIMEOUT,
        )
        if result.returncode == 0 and result.stdout:
            package = result.stdout.split(":", 1)[0].strip()
    except (OSError, subprocess.TimeoutExpired):
        package = None
    if len(_dpkg_cache) > 512:
        _dpkg_cache.clear()
    _dpkg_cache[command] = (now, package)
    return package


def resolve_server_icon_path(server):
    index = _get_index()

    for binary in _binary_candidates(server):
        icon_path = index["by_binary"].get(binary)
        if icon_path and os.path.isfile(icon_path):
            return icon_path

    if server.command and os.path.isabs(server.command) and os.path.exists(server.command):
        pkg = _owning_package(server.command)
        if pkg:
            icon_path = index["by_package"].get(pkg)
            if icon_path and os.path.isfile(icon_path):
                return icon_path

    return None


def resolve_server_metadata(server):
    """AppStream metadata (summary, description, developer, urls, license...)
    of the component that provides this server's binary, or None."""
    index = _get_index()

    for binary in _binary_candidates(server):
        meta = index["meta_by_binary"].get(binary)
        if meta:
            return meta

    if server.command and os.path.isabs(server.command) and os.path.exists(server.command):
        pkg = _owning_package(server.command)
        if pkg:
            return index["meta_by_package"].get(pkg)

    return None


def is_safe_icon_path(path):
    if not path:
        return False
    real_path = os.path.realpath(path)
    if not os.path.isfile(real_path):
        return False
    return any(real_path.startswith(prefix + os.sep) or real_path == prefix for prefix in _SAFE_PREFIXES)