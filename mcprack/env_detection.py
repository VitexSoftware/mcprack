"""Best-effort detection of the environment variables an installed MCP
server package accepts, so an admin reviewing a newly-installed server sees
likely env vars pre-listed instead of having to read the package's source
or docs.

Detection only ever produces *suggestions* — a name, a guess at
required/secret status, and an optional description. It never touches
McpServer.env_config/env_var_names/required_env_keys directly and never
fabricates a value. Only the "registry" and "manifest" tiers may ever mark
a suggestion required=True — the heuristic source-scan and docker-inspect
tiers can find variable *names* but have no reliable way to know whether
one is actually required, and a wrong "required" guess would silently block
a perfectly working server (see installer.py's verify_pip_binary docstring
for the exact same lesson learned about wrong guesses previously).

Every tier is wrapped so it can never raise — a detection failure (network
down, malformed package, docker not running) must never break the
install-finalize path that calls detect_env_vars().
"""

import glob
import json
import logging
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .installer import PREFLIGHT_TIMEOUT

logger = logging.getLogger(__name__)

REGISTRY_BASE_URL = "https://registry.modelcontextprotocol.io"
HTTP_TIMEOUT = 5  # seconds — one shot, no retries; offline is a normal outcome

SENSITIVE_NAME_HINTS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "APIKEY")
DOCKER_ENV_DENYLIST = {"PATH", "HOME", "LANG", "TZ", "HOSTNAME"}

# Bounds for the heuristic source scan, so a huge/unusual package can't make
# install-finalize slow — this is a best-effort convenience feature, not
# something worth spending real time on.
SCAN_MAX_FILES = 500
SCAN_MAX_BYTES = 2 * 1024 * 1024

PY_ENV_PATTERN = re.compile(r'os\.(?:environ\.get|getenv)\(\s*["\']([A-Z][A-Z0-9_]*)["\']')
JS_ENV_PATTERN = re.compile(
    r'process\.env\.([A-Z][A-Z0-9_]*)\b|process\.env\[\s*["\']([A-Z][A-Z0-9_]*)["\']'
)


def _looks_sensitive(name):
    upper = name.upper()
    return any(hint in upper for hint in SENSITIVE_NAME_HINTS)


def _bare_package_name(package_spec):
    """Strips version pins the same way installer.resolve_installed_version
    does, e.g. 'foo-mcp==1.2.0' / 'foo-mcp>=1.0' / '@org/foo@1.2.0' -> bare name."""
    spec = package_spec.strip()
    for sep in ("==", ">=", "<=", "!=", "~=", ">", "<"):
        spec = spec.split(sep)[0]
    # npm scoped packages: @org/name@version -> strip a trailing @version only
    if spec.startswith("@"):
        at_positions = [i for i, c in enumerate(spec) if c == "@"]
        if len(at_positions) > 1:
            spec = spec[: at_positions[-1]]
        return spec.strip()
    return spec.split("@")[0].strip()


def _env_vars_from_manifest_dict(data):
    """Maps the MCP Registry / bundled server.json shape:
    environmentVariables: [{name, description, isRequired, isSecret, default, choices}]
    -> our suggestion dicts (source filled in by the caller)."""
    results = []
    for entry in data.get("environmentVariables") or []:
        name = entry.get("name")
        if not name:
            continue
        results.append(
            {
                "name": name,
                "required": bool(entry.get("isRequired")),
                "secret": bool(entry.get("isSecret")) or _looks_sensitive(name),
                "description": entry.get("description"),
            }
        )
    return results


def _from_registry(package_spec, install_method):
    """Queries the official MCP Registry (registry.modelcontextprotocol.io)
    for a package matching package_spec. Best-effort: any network/parse
    failure silently yields no results — this is enrichment, not a
    dependency the feature relies on being reachable."""
    bare_name = _bare_package_name(package_spec)
    if not bare_name:
        return []

    try:
        search_url = f"{REGISTRY_BASE_URL}/v0.1/servers?search={urllib.parse.quote(bare_name)}"
        with urllib.request.urlopen(search_url, timeout=HTTP_TIMEOUT) as resp:
            search_data = json.loads(resp.read().decode("utf-8"))

        candidates = search_data.get("servers") or []
        matched_name = None
        for candidate in candidates:
            server_info = candidate.get("server") or candidate
            for pkg in server_info.get("packages") or []:
                if pkg.get("identifier") == bare_name:
                    matched_name = server_info.get("name")
                    break
            if matched_name:
                break
        if not matched_name:
            return []

        version_url = (
            f"{REGISTRY_BASE_URL}/v0.1/servers/"
            f"{urllib.parse.quote(matched_name, safe='')}/versions/latest"
        )
        with urllib.request.urlopen(version_url, timeout=HTTP_TIMEOUT) as resp:
            version_data = json.loads(resp.read().decode("utf-8"))

        server_info = version_data.get("server") or version_data
        results = []
        for pkg in server_info.get("packages") or []:
            if pkg.get("identifier") == bare_name:
                results.extend(_env_vars_from_manifest_dict(pkg))
        for entry in results:
            entry["source"] = "registry"
        return results
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        ValueError,
        KeyError,
    ):
        return []


def _candidate_package_dirs(install_path, install_method, package_spec):
    """Locates the installed package's own directory on disk, best-effort."""
    bare_name = _bare_package_name(package_spec)
    if not bare_name:
        return []

    if install_method == "pip":
        # Python distribution names normalize '-'/'_' interchangeably.
        pattern_names = {bare_name, bare_name.replace("-", "_"), bare_name.replace("_", "-")}
        dirs = []
        for name in pattern_names:
            dirs.extend(glob.glob(f"{install_path}/lib/python3.*/site-packages/{name}"))
        return dirs

    if install_method == "npm":
        return [str(Path(install_path) / "node_modules" / bare_name)]

    return []


def _from_bundled_manifest(install_path, install_method, package_spec):
    """Looks for a server.json (MCP Registry manifest shape) or a minimal
    smithery.yaml inside the installed package's own directory."""
    results = []
    for pkg_dir in _candidate_package_dirs(install_path, install_method, package_spec):
        pkg_dir_path = Path(pkg_dir)
        if not pkg_dir_path.is_dir():
            continue

        server_json = pkg_dir_path / "server.json"
        if server_json.is_file():
            try:
                data = json.loads(server_json.read_text(encoding="utf-8"))
                for entry in _env_vars_from_manifest_dict(data):
                    entry["source"] = "manifest"
                    results.append(entry)
            except (OSError, ValueError):
                pass

        smithery_yaml = pkg_dir_path / "smithery.yaml"
        if smithery_yaml.is_file():
            try:
                for entry in _parse_smithery_yaml(smithery_yaml.read_text(encoding="utf-8")):
                    entry["source"] = "manifest"
                    results.append(entry)
            except (OSError, ValueError):
                pass

        if results:
            break
    return results


def _parse_smithery_yaml(text):
    """Deliberately not a real YAML parser (no PyYAML dependency) — just
    enough to pull configSchema.required and configSchema.properties keys
    out of the conventional two-space-indented shape smithery.yaml uses.
    Anything more exotic (anchors, flow style, etc.) is simply not found,
    which is fine since this is a best-effort secondary signal."""
    required_names = set()
    property_names = []

    lines = text.splitlines()
    in_required = False
    in_properties = False
    properties_indent = None

    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if stripped.startswith("required:"):
            in_required = True
            in_properties = False
            continue
        if stripped.startswith("properties:"):
            in_properties = True
            in_required = False
            properties_indent = indent
            continue

        if in_required:
            m = re.match(r"-\s*([A-Za-z_][A-Za-z0-9_]*)", stripped)
            if m:
                required_names.add(m.group(1))
                continue
            in_required = False

        if in_properties:
            if properties_indent is not None and indent <= properties_indent and stripped:
                in_properties = False
                continue
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*):\s*$", stripped)
            if m and indent == (properties_indent or 0) + 2:
                property_names.append(m.group(1))

    results = []
    for name in property_names:
        results.append(
            {
                "name": name,
                "required": name in required_names,
                "secret": _looks_sensitive(name),
                "description": None,
            }
        )
    return results


def _iter_scan_files(pkg_dir, extensions):
    total_bytes = 0
    file_count = 0
    root = Path(pkg_dir)
    for path in root.rglob("*"):
        if file_count >= SCAN_MAX_FILES or total_bytes >= SCAN_MAX_BYTES:
            return
        if not path.is_file() or path.suffix not in extensions:
            continue
        # Never descend into a nested dependency tree bundled inside the
        # package itself (npm packages sometimes vendor their own deps) —
        # pkg_dir itself legitimately lives under a node_modules/ directory
        # (that's npm's own layout), so only paths *relative to pkg_dir*
        # count here, not the absolute path.
        if "node_modules" in path.relative_to(root).parts:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        file_count += 1
        total_bytes += size
        yield path


def _from_source_scan(install_path, install_method, package_spec):
    """Heuristic fallback: greps the package's own source for direct env
    var access. Names only — required is always False here since a grep
    can't know whether a code path is actually reached at required-startup
    time."""
    extensions = {".py"} if install_method == "pip" else {".js", ".ts", ".mjs", ".cjs"}
    pattern = PY_ENV_PATTERN if install_method == "pip" else JS_ENV_PATTERN

    found = {}
    for pkg_dir in _candidate_package_dirs(install_path, install_method, package_spec):
        if not Path(pkg_dir).is_dir():
            continue
        for path in _iter_scan_files(pkg_dir, extensions):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for match in pattern.finditer(text):
                name = match.group(1) or (match.group(2) if match.lastindex and match.lastindex > 1 else None)
                if name and name not in found:
                    found[name] = {
                        "name": name,
                        "required": False,
                        "secret": _looks_sensitive(name),
                        "description": None,
                        "source": "source-scan",
                    }
        if found:
            break
    return list(found.values())


def _from_docker_inspect(image_ref):
    """Reads the image's baked-in Config.Env — low-signal (mostly base-image
    defaults, not user-supplied credentials) but free, since verify_docker_image
    already confirms the image exists. required is always False."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image_ref, "--format", "{{json .Config.Env}}"],
            capture_output=True,
            timeout=PREFLIGHT_TIMEOUT,
            check=False,
            text=True,
        )
        if result.returncode != 0:
            return []
        env_list = json.loads(result.stdout or "[]")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []

    results = []
    for item in env_list or []:
        if "=" not in item:
            continue
        name = item.split("=", 1)[0]
        if name in DOCKER_ENV_DENYLIST:
            continue
        results.append(
            {
                "name": name,
                "required": False,
                "secret": _looks_sensitive(name),
                "description": "declared in Docker image",
                "source": "docker-inspect",
            }
        )
    return results


def _dedupe(suggestions):
    seen = {}
    for entry in suggestions:
        name = entry.get("name")
        if not name:
            continue
        if name not in seen:
            seen[name] = entry
    return list(seen.values())


def detect_env_vars(server):
    """Entry point. `server` is an McpServer with install_method set.
    Returns a deduped list of suggestion dicts:
    {"name", "required", "secret", "description", "source"}. Never raises."""
    try:
        install_method = server.install_method
        package_spec = server.package_spec
        install_path = server.install_path

        if not install_method or not package_spec:
            return []

        if install_method in ("pip", "npm"):
            suggestions = _from_registry(package_spec, install_method)
            if not suggestions and install_path:
                suggestions = _from_bundled_manifest(install_path, install_method, package_spec)
            if not suggestions and install_path:
                suggestions = _from_source_scan(install_path, install_method, package_spec)
        elif install_method == "docker":
            suggestions = _from_registry(package_spec, install_method)
            suggestions = suggestions + _from_docker_inspect(package_spec)
        else:
            suggestions = []

        return _dedupe(suggestions)
    except Exception:
        logger.debug("env_detection.detect_env_vars failed", exc_info=True)
        return []
