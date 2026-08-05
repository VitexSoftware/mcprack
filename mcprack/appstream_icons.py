import os
import time
import xml.etree.ElementTree as ET
from glob import glob


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
    patterns = (
        "/usr/share/metainfo/*.xml",
        "/usr/share/appdata/*.xml",
    )
    for pattern in patterns:
        for path in glob(pattern):
            yield path


def _resolve_icon_file(icon_name):
    if os.path.isabs(icon_name) and os.path.isfile(icon_name):
        return icon_name

    base, ext = os.path.splitext(icon_name)
    names = [icon_name]
    if not ext:
        names.extend([f"{icon_name}.svg", f"{icon_name}.png", f"{icon_name}.xpm"])
        if base and base != icon_name:
            names.extend([f"{base}.svg", f"{base}.png", f"{base}.xpm"])

    for icon_dir in _ICON_DIRS:
        if not os.path.isdir(icon_dir):
            continue
        for name in names:
            candidate = os.path.join(icon_dir, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _build_index():
    by_binary = {}
    by_package = {}
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

            icon_path = None
            for icon_name in _candidate_icon_names(component):
                icon_path = _resolve_icon_file(icon_name)
                if icon_path:
                    break

            if not icon_path:
                continue

            pkgname = _component_pkgname(component)
            if pkgname and pkgname not in by_package:
                by_package[pkgname] = icon_path

            for binary in _component_binaries(component):
                by_binary.setdefault(binary, icon_path)

    return {"by_binary": by_binary, "by_package": by_package}


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
    return {c for c in candidates if c}


def resolve_server_icon_path(server):
    index = _get_index()

    for binary in _binary_candidates(server):
        icon_path = index["by_binary"].get(binary)
        if icon_path and os.path.isfile(icon_path):
            return icon_path

    if server.command and os.path.isabs(server.command) and os.path.exists(server.command):
        try:
            import subprocess

            result = subprocess.run(
                ["dpkg-query", "-S", server.command],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0 and result.stdout:
                pkg = result.stdout.split(":", 1)[0].strip()
                icon_path = index["by_package"].get(pkg)
                if icon_path and os.path.isfile(icon_path):
                    return icon_path
        except OSError:
            return None

    return None


def is_safe_icon_path(path):
    if not path:
        return False
    real_path = os.path.realpath(path)
    if not os.path.isfile(real_path):
        return False
    return any(real_path.startswith(prefix + os.sep) or real_path == prefix for prefix in _SAFE_PREFIXES)