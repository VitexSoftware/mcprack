"""The unified MCP server manifest: schema, validation, normalisation.

One file per server, ``server.json``: a valid MCP Registry document plus the
VitexSoftware extension block (see schemas/mcp-server.schema.json and
MCP-SERVER-STANDARDS.md section 6). ``lhm.plugin.json`` is the legacy format
it replaces; mcprack still reads it, via :func:`from_legacy_plugin`, until all
server projects are converted (``mcprack server manifest-convert``).
"""

import json
import re
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
    author = re.sub(r"\s*<[^>]*>\s*$", "", plugin.get("author") or "").strip()  # drop "<email>"
    ext = {"author": {"name": author}}
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


def _project_version(directory):
    """Version from the project's pyproject.toml ([project] version), or None."""
    try:
        import tomllib

        with open(Path(directory) / "pyproject.toml", "rb") as fh:
            value = tomllib.load(fh).get("project", {}).get("version")
        return value if isinstance(value, str) and value else None
    except (OSError, ValueError, ImportError):
        return None


def convert_file(plugin_file, package_name=None, new_uuid=False):
    """(manifest dict, remaining problems) for a legacy lhm.plugin.json,
    merging environmentVariables from a server.json lying next to it."""
    import os
    import uuid as uuid_module

    with open(plugin_file, encoding="utf-8") as fh:
        plugin = json.load(fh)
    here = os.path.dirname(plugin_file) or "."
    if not plugin.get("version"):
        found = _project_version(here)
        if found:
            plugin = dict(plugin, version=found)
    data = from_legacy_plugin(plugin, package_name)
    ext = extension(data)
    if new_uuid and not ext.get("uuid"):
        ext["uuid"] = str(uuid_module.uuid4())
    for old_registry in (os.path.join(here, "debian", "server.json"), os.path.join(here, "server.json")):
        if not os.path.isfile(old_registry):
            continue
        try:
            with open(old_registry, encoding="utf-8") as fh:
                env = environment_variables(json.load(fh))
        except (OSError, ValueError):
            continue
        if env:
            data["packages"][0]["environmentVariables"] = env
            break
    return data, validate(data)


def introspect(argv, env=None, timeout=60.0):
    """Spawn an MCP server on stdio and ask it what it serves.

    Returns {"tools": [...], "prompts": [...], "resources": [...]} with
    name/description/title/annotations/inputSchema as the server reports them.
    Plain newline-delimited JSON-RPC, no MCP SDK needed, so it works for any
    server whatever it is written with. Raises RuntimeError on any failure."""
    import os
    import select
    import subprocess
    import time

    environment = dict(os.environ)
    environment.update(env or {})
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment, text=True, bufsize=1)
    deadline = time.monotonic() + timeout
    counter = [0]
    fd = proc.stdout.fileno()
    pending = bytearray()  # own line buffer: select() cannot see data a Python reader already holds

    def next_line(left):
        """One complete output line, or None on timeout / EOF (b"" at EOF)."""
        while b"\n" not in pending:
            ready, _, _ = select.select([fd], [], [], min(left, 1.0))
            if not ready:
                return None
            chunk = os.read(fd, 65536)
            if not chunk:
                return b""
            pending.extend(chunk)
            left = max(deadline - time.monotonic(), 0)
        line, _, rest = bytes(pending).partition(b"\n")
        pending[:] = rest
        return line

    def send(message):
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()

    def call(method, params=None):
        counter[0] += 1
        ident = counter[0]
        send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}})
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise RuntimeError(f"timeout waiting for {method}")
            line = next_line(left)
            if line is None:
                if proc.poll() is not None and not pending:
                    raise RuntimeError(f"server exited ({proc.returncode}) before answering {method}")
                continue
            if line == b"":
                raise RuntimeError(f"server closed stdout before answering {method}")
            try:
                reply = json.loads(line)
            except ValueError:
                continue  # stray non-protocol output
            if not isinstance(reply, dict):
                continue
            if reply.get("id") == ident:
                if "error" in reply:
                    raise _Unsupported(f"{method}: {reply['error'].get('message')}")
                return reply.get("result") or {}

    def listing(method, key):
        items, cursor = [], None
        while True:
            result = call(method, {"cursor": cursor} if cursor else {})
            items.extend(result.get(key) or [])
            cursor = result.get("nextCursor")
            if not cursor:
                return items

    try:
        call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcprack-manifest", "version": "1"}})
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        out = {}
        for method, key in (("tools/list", "tools"), ("prompts/list", "prompts"), ("resources/list", "resources")):
            try:
                out[key] = listing(method, key)
            except _Unsupported:
                out[key] = []  # capability not offered
        return out
    except OSError as exc:
        raise RuntimeError(str(exc)) from exc
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


class _Unsupported(RuntimeError):
    pass


def _one_line(text):
    return " ".join((text or "").split())


def to_extension_items(found):
    """The extension block's tools/prompts/resources from introspect()."""
    tools = []
    for t in found.get("tools", []):
        item = {"name": t["name"], "description": _one_line(t.get("description")) or t["name"]}
        if t.get("title"):
            item["title"] = t["title"]
        if isinstance(t.get("annotations"), dict) and t["annotations"]:
            item["annotations"] = {k: v for k, v in t["annotations"].items() if k in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")}
        if isinstance(t.get("inputSchema"), dict):
            item["inputSchema"] = t["inputSchema"]
        tools.append(item)
    prompts = [{"name": p["name"], "description": _one_line(p.get("description")) or p["name"]} for p in found.get("prompts", [])]
    resources = [{"name": r.get("name") or r.get("uri"), "description": _one_line(r.get("description")) or r.get("uri", ""), "uri": r.get("uri")} for r in found.get("resources", [])]
    return tools, prompts, resources


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
    sy = sub.add_parser("sync", help="list the tools/prompts/resources of a running server and write them into server.json (or --check that they match)")
    sy.add_argument("file")
    sy.add_argument("--check", action="store_true", help="do not write; exit 1 if server.json does not list exactly what the server serves")
    sy.add_argument("--env", action="append", default=[], metavar="KEY=VALUE", help="environment for the server (placeholder credentials are enough)")
    sy.add_argument("--timeout", type=float, default=60.0)
    sy.add_argument("server_command", nargs=argparse.REMAINDER, help="-- command [args...] that starts the server on stdio")
    args = parser.parse_args(argv)

    if args.command == "sync":
        command = [c for c in args.server_command if c != "--"] if args.server_command[:1] == ["--"] else args.server_command
        if not command:
            parser.error("sync needs the server command after --")
        env = dict(item.split("=", 1) for item in args.env if "=" in item)
        data = json.loads(Path(args.file).read_text(encoding="utf-8"))
        found = to_extension_items(introspect(command, env, args.timeout))
        ext = extension(data)
        names = lambda items: sorted(i["name"] for i in items)  # noqa: E731
        listed = (ext.get("tools") or [], ext.get("prompts") or [], ext.get("resources") or [])
        same = all(names(a) == names(b) for a, b in zip(found, listed))
        if args.check:
            if not same:
                for label, new, old in zip(("tools", "prompts", "resources"), found, listed):
                    if names(new) != names(old):
                        print(f"MISMATCH {label}: server serves {len(new)}, server.json lists {len(old)}; "
                              f"missing in file: {sorted(set(names(new)) - set(names(old)))}; "
                              f"not served: {sorted(set(names(old)) - set(names(new)))}")
                return 1
            print(f"OK    {args.file} lists exactly the {len(found[0])} tools the server serves")
            return 0
        meta = data.setdefault("_meta", {}).setdefault(PUBLISHER_KEY, {}).setdefault(EXTENSION_KEY, {})
        meta["tools"], prompts, resources = found
        for key, value in (("prompts", prompts), ("resources", resources)):
            if value:
                meta[key] = value
            else:
                meta.pop(key, None)
        Path(args.file).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {len(found[0])} tools, {len(prompts)} prompts, {len(resources)} resources to {args.file}")
        return 0

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
