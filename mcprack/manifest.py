"""The unified MCP server manifest: schema, validation, normalisation.

One file per server, ``server.json``: a valid MCP Registry document plus the
VitexSoftware extension block (see schemas/mcp-server.schema.json and
MCP-SERVER-STANDARDS.md section 6). ``lhm.plugin.json`` is the legacy format
it replaces; mcprack still reads it, via :func:`from_legacy_plugin`, until all
server projects are converted (``mcprack server manifest-convert``).
"""

import json
from pathlib import Path

PUBLISHER_KEY = "io.modelcontextprotocol.registry/publisher-provided"
EXTENSION_KEY = "cz.vitexsoftware.mcp"
SCHEMA_PATH = Path(__file__).with_name("schemas") / "mcp-server.schema.json"

_schema_cache = None


def schema():
    global _schema_cache
    if _schema_cache is None:
        _schema_cache = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return _schema_cache


def extension(data):
    """The cz.vitexsoftware.mcp block of a server.json dict, or {}."""
    meta = data.get("_meta") if isinstance(data, dict) else None
    publisher = meta.get(PUBLISHER_KEY) if isinstance(meta, dict) else None
    block = publisher.get(EXTENSION_KEY) if isinstance(publisher, dict) else None
    return block if isinstance(block, dict) else {}


def validate(data):
    """Human-readable problems of a manifest dict; [] when it conforms."""
    import jsonschema

    validator = jsonschema.Draft7Validator(schema())
    problems = []
    for error in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in error.absolute_path) or "(root)"
        problems.append(f"{where}: {error.message}")
    return problems


def environment_variables(data):
    """All declared environment variables (top level for old files, else
    packages[].environmentVariables)."""
    entries = list(data.get("environmentVariables") or [])
    for pkg in data.get("packages") or []:
        if isinstance(pkg, dict):
            entries.extend(pkg.get("environmentVariables") or [])
    return [e for e in entries if isinstance(e, dict) and e.get("name")]


def from_legacy_plugin(plugin, package_name=None):
    """Build a unified server.json dict from a legacy lhm.plugin.json dict.

    Gaps the old format cannot fill (repository source, registry type,
    uuid) are left out or defaulted; run the validator on the result and
    fill in what it reports. The ``description`` is cut to the Registry's 100
    characters, the full text moves to ``longDescription``."""
    description = (plugin.get("description") or "").strip()
    short = description if len(description) <= 100 else description[:97].rstrip() + "..."
    identifier = package_name or plugin.get("identifier") or ""
    homepage = plugin.get("homepage") or ""
    ext = {"author": {"name": plugin.get("author") or ""}}
    if plugin.get("authorUrl"):
        ext["author"]["url"] = plugin["authorUrl"]
    if plugin.get("uuid"):
        ext["uuid"] = plugin["uuid"]
    if len(description) > 100:
        ext["longDescription"] = [description]
    for key in ("category", "tags", "prompts", "resources"):
        if plugin.get(key):
            ext[key] = plugin[key]
    ext["tools"] = plugin.get("tools") or []
    out = {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": f"io.github.vitexsoftware/{identifier}" if identifier else "",
        "title": plugin.get("name") or identifier,
        "description": short,
        "version": plugin.get("version") or "0.0.0",
        "websiteUrl": homepage,
        "repository": {"url": plugin.get("repository") or homepage, "source": "github"},
        "packages": [{"registryType": "pypi", "identifier": identifier, "version": plugin.get("version") or "0.0.0", "transport": {"type": "stdio"}, "environmentVariables": []}],
        "_meta": {PUBLISHER_KEY: {EXTENSION_KEY: ext}},
    }
    return out


def normalise(manifest=None, legacy_plugin=None):
    """The fields the server page needs, from a unified manifest or, failing
    that, a legacy lhm.plugin.json. Plain values only."""
    manifest = manifest or {}
    if manifest:
        ext = extension(manifest)
        repo = manifest.get("repository") if isinstance(manifest.get("repository"), dict) else {}
        author = ext.get("author") if isinstance(ext.get("author"), dict) else {}
        return {
            "uuid": ext.get("uuid"),
            "title": manifest.get("title"),
            "description": manifest.get("description"),
            "long_description": ext.get("longDescription") or [],
            "version": manifest.get("version"),
            "author": author.get("name"),
            "author_url": author.get("url"),
            "homepage": manifest.get("websiteUrl"),
            "repository": repo.get("url"),
            "category": ext.get("category"),
            "tags": ext.get("tags") or [],
            "tools": ext.get("tools") or [],
            "prompts": ext.get("prompts") or [],
            "resources": ext.get("resources") or [],
            "format": "server.json",
        }
    plugin = legacy_plugin or {}
    if plugin:
        return {
            "uuid": plugin.get("uuid"),
            "title": plugin.get("name"),
            "description": plugin.get("description"),
            "long_description": [],
            "version": plugin.get("version"),
            "author": plugin.get("author"),
            "author_url": plugin.get("authorUrl"),
            "homepage": plugin.get("homepage"),
            "repository": plugin.get("repository"),
            "category": plugin.get("category"),
            "tags": plugin.get("tags") or [],
            "tools": plugin.get("tools") or [],
            "prompts": plugin.get("prompts") or [],
            "resources": plugin.get("resources") or [],
            "format": "lhm.plugin.json",
        }
    return {}


def validate_file(path):
    """Problems of the manifest file at `path` (unreadable counts as one)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        return [f"cannot read as JSON: {exc}"]
    return validate(data)


def convert_file(plugin_file, package_name=None, new_uuid=False):
    """(manifest dict, remaining problems) for a legacy lhm.plugin.json,
    merging environmentVariables from a server.json lying next to it."""
    import os
    import uuid as uuid_module

    with open(plugin_file, encoding="utf-8") as fh:
        plugin = json.load(fh)
    data = from_legacy_plugin(plugin, package_name)
    ext = extension(data)
    if new_uuid and not ext.get("uuid"):
        ext["uuid"] = str(uuid_module.uuid4())
    old_registry = os.path.join(os.path.dirname(plugin_file) or ".", "server.json")
    if os.path.isfile(old_registry):
        try:
            with open(old_registry, encoding="utf-8") as fh:
                data["packages"][0]["environmentVariables"] = environment_variables(json.load(fh))
        except (OSError, ValueError):
            pass
    return data, validate(data)


def main(argv=None):
    """``python3 -m mcprack.manifest validate FILE...`` and
    ``... convert lhm.plugin.json [--package NAME] [--new-uuid] [-o OUT]``.
    Needs no mcprack configuration or database, so projects can run it in
    their own tests and autopkgtest."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="python3 -m mcprack.manifest", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="validate server.json file(s); exit 1 on any problem")
    v.add_argument("files", nargs="+")
    c = sub.add_parser("convert", help="convert a legacy lhm.plugin.json to server.json")
    c.add_argument("plugin_file")
    c.add_argument("--package", help="package / binary name, e.g. mcp-server-netbox")
    c.add_argument("--new-uuid", action="store_true", help="assign a uuid (only for a server that never had one)")
    c.add_argument("-o", "--output")
    args = parser.parse_args(argv)

    if args.command == "validate":
        failed = False
        for path in args.files:
            problems = validate_file(path)
            print(("FAIL  " if problems else "OK    ") + path)
            for problem in problems:
                print("      " + problem)
            failed = failed or bool(problems)
        return 1 if failed else 0

    data, todo = convert_file(args.plugin_file, args.package, args.new_uuid)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    for problem in todo:
        print("TODO  " + problem, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
