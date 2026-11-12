"""What mcprack knows about a KIND of MCP server, for its public page.

Sources, strongest first (each fills only what the stronger one left empty):

1. The server's ``server.json`` - ONE file, a valid MCP Registry document plus
   the VitexSoftware extension (``uuid``, author, tools, prompts, ...), see
   manifest.py and schemas/mcp-server.schema.json - installed at
   ``/usr/share/<binary>/server.json`` (or ``/usr/share/mcprack/manifests/
   <binary>.json`` for a server whose package we do not control). The
   parameters (environment variables) come from it as well.
2. The legacy ``lhm.plugin.json`` (``/usr/share/<binary>/lhm.plugin.json``),
   read only until every server project has been converted.
3. The AppStream metainfo of the package that provides the binary
   (appstream_icons.resolve_server_metadata).
4. What is stored in the mcprack database (label, description, category ...).

Everything here is read from local files; nothing is fetched from the
network and nothing secret is returned (parameter *names* and descriptions
only, never values).
"""

import json
import logging
import uuid as uuid_module
from pathlib import Path
from urllib.parse import urlsplit

from . import appstream_icons, env_detection, manifest as manifest_mod
from .extensions import db
from .models import McpServer

logger = logging.getLogger(__name__)

PLUGIN_FILE = "lhm.plugin.json"  # legacy, superseded by server.json
PLUGIN_MAX_BYTES = 1024 * 1024  # a plugin file lists every tool with its schema


def _http_url(value):
    """`value` if it is an absolute http(s) URL with a host, else None. The
    only thing ever put into an href on the server page."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    return value if parsed.scheme in ("http", "https") and parsed.hostname else None


def _valid_uuid(value):
    try:
        return str(uuid_module.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


def _read_json(path, limit):
    try:
        if path.is_file() and path.stat().st_size <= limit:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except (OSError, ValueError):
        logger.debug("server_info: cannot read %s", path, exc_info=True)
    return {}


def load_manifest(server):
    """The server.json installed on this host for `server`, or {}."""
    for path in env_detection._manifest_candidates(getattr(server, "command", None)):
        data = _read_json(path, env_detection.MANIFEST_MAX_BYTES)
        if data:
            return data
    return {}


def _plugin_candidates(command):
    name = Path(command).name if command else ""
    if not env_detection._SAFE_BASENAME.match(name):
        return []
    return [
        Path(env_detection.MANIFEST_DIRS[0]) / name / PLUGIN_FILE,
        Path(env_detection.MANIFEST_DIRS[1]) / f"{name}.{PLUGIN_FILE}",
    ]


def load_plugin(server):
    """The lhm.plugin.json installed on this host for `server`, or {}."""
    for path in _plugin_candidates(getattr(server, "command", None)):
        data = _read_json(path, PLUGIN_MAX_BYTES)
        if data:
            return data
    return {}


def _meta(server):
    """The normalised project metadata of `server` (manifest.normalise)."""
    return manifest_mod.normalise(load_manifest(server), load_plugin(server))


def _text(value, limit=2000):
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else None


def _named_items(items, limit=200):
    """[{name, description}] from a plugin list, text only (the page never
    renders anything the plugin file could use as markup)."""
    out = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and _text(item.get("name")):
            out.append({"name": _text(item["name"], 200), "description": _text(item.get("description"))})
        if len(out) >= limit:
            break
    return out


def sync_uuid(server):
    """Adopt the UUID declared by the server project, when there is one.

    The database default is a random UUID, so a server registered by hand has
    its own until its project's server.json is found; from then on the declared
    one wins, making it identical on every mcprack instance. Returns True if
    the UUID changed. Never raises; skips a UUID another row already owns."""
    try:
        declared = _valid_uuid(_meta(server)["uuid"])
        if not declared or declared == server.uuid:
            return False
        if McpServer.query.filter(McpServer.uuid == declared, McpServer.id != server.id).first():
            logger.warning("server_info: UUID %s of %s is already used by another server", declared, server.name)
            return False
        server.uuid = declared
        db.session.commit()
        return True
    except Exception:  # best-effort identity sync must not break a page view
        db.session.rollback()
        logger.debug("server_info.sync_uuid failed", exc_info=True)
        return False


def _parameters(server, manifest):
    params = env_detection._env_vars_from_manifest_dict(manifest) if manifest else []  # handles packages[].environmentVariables
    source = "manifest"
    if not params:
        params = [dict(p) for p in server.detected_env_vars if isinstance(p, dict) and p.get("name")]
        source = "detected"
    if not params:
        required = set(server.required_env_keys)
        params = [{"name": n, "required": n in required, "secret": env_detection.looks_sensitive_name(n), "description": None} for n in server.env_var_names]
        source = "registered"
    required = set(server.required_env_keys)
    for p in params:
        if p["name"] in required:
            p["required"] = True
    return params, source


def describe(server):
    """Everything the server page shows, as plain data."""
    manifest = load_manifest(server)
    meta = manifest_mod.normalise(manifest, load_plugin(server))
    appstream = appstream_icons.resolve_server_metadata(server) or {}
    urls = appstream.get("urls") or {}

    homepage = _http_url(meta.get("homepage")) or urls.get("homepage")
    repository = _http_url(meta.get("repository")) or urls.get("vcs-browser")
    if not repository and homepage and "github.com" in homepage:
        repository = homepage

    summary = _text(meta.get("description"))
    author_name = _text(meta.get("author"), 200) or appstream.get("developer")
    parameters, parameters_source = _parameters(server, manifest)
    category = _text(meta.get("category"), 100)
    long_description = [
        b if isinstance(b, str) else [i for i in b if isinstance(i, str)]
        for b in meta.get("long_description") or []
        if isinstance(b, (str, list))
    ]
    uuid_declared = bool(_valid_uuid(meta.get("uuid")))

    return {
        "uuid": server.uuid,
        "name": server.name,
        "label": server.label,
        "title": _text(meta.get("title"), 200) or appstream.get("name") or server.label,
        "summary": server.description or summary or appstream.get("summary"),
        "description": long_description or appstream.get("description") or [],
        "author": {"name": author_name, "url": _http_url(meta.get("author_url"))},
        "homepage": homepage,
        "repository": repository,
        "bugtracker": urls.get("bugtracker"),
        "license": appstream.get("license"),
        "version": _text(meta.get("version"), 50) or (appstream.get("latest_release") or {}).get("version") or server.installed_version,
        "categories": [category] if category else appstream.get("categories") or ([server.category] if server.category else []),
        "tags": [t for t in (meta.get("tags") or []) if isinstance(t, str)][:20],
        "transport": server.transport,
        "parameters": parameters,
        "parameters_source": parameters_source,
        "tools": _named_items(meta.get("tools")),
        "prompts": _named_items(meta.get("prompts")),
        "resources": _named_items(meta.get("resources")),
        "manifest_format": meta.get("format"),
        "has_manifest": bool(meta),
        "has_appstream": bool(appstream),
        "uuid_declared": uuid_declared,
        "missing": [
            label
            for label, present in (
                ("server.json", meta.get("format") == "server.json"),
                ("uuid", uuid_declared),
                ("description", bool(summary or appstream.get("summary") or server.description)),
                ("author", bool(author_name)),
                ("repository", bool(repository)),
                ("parameters", bool(parameters)),
            )
            if not present
        ],
    }
