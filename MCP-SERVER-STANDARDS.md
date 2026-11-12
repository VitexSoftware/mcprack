# MCP Server Standards (VitexSoftware / Vitexus)

**Applies to:** creating a new MCP server, or adapting/upgrading/packaging an existing one
(`mcp-server-*`, `*-mcp-server`, `mcprack-mcp-server-*`; found in `~/Projects/Packaging/`,
`~/Projects/Multi/`, `~/Projects/VitexSoftware/`).

Treat every item below as a requirement. Before finishing any MCP-server task, walk the
**Definition of Done** at the end and report which items pass, fail, or were not applicable.
Do not rename existing tools (breaking change for clients) without asking the user.

Canonical references — copy from these, do not rewrite from memory:
- Annotation constants: `~/Projects/Multi/multiflexi-mcp-server/src/multiflexi_mcp_server/server.py` (`READ_ONLY_ANNOTATIONS` … `MUTATE_ANNOTATIONS`)
- Annotation rationale + test: `~/Projects/Packaging/mcp-server-nextcloud/docs/ADR-017-mcp-tool-annotations.md`, `tests/server/test_annotations.py`
- Companion package: `~/Projects/VitexSoftware/mcprack/doc/PACKAGING-MCP-SERVERS.md` and `~/Projects/Multi/multiflexi-mcp-server/debian/`
- Extras: `SKILL.md`, `lhm.plugin.json` and `server.json` in `multiflexi-mcp-server`

---

## 1. Tools and annotations (every tool, no exceptions)

Each tool MUST have:
- `title` — human readable ("Create Job"), never the snake_case function name.
- a `description` (or docstring) saying what it does and, for mutating tools, what is changed.
- `Field(description=...)` on every parameter.
- `annotations=ToolAnnotations(...)` with **all four hints set explicitly**:
  `read_only_hint`, `destructive_hint`, `idempotent_hint`, `open_world_hint`.

Define shared constants once per server (not inline per tool):

```python
from mcp.types import ToolAnnotations

READ_ONLY_ANNOTATIONS = ToolAnnotations(read_only_hint=True,  destructive_hint=False, idempotent_hint=True,  open_world_hint=True)
CREATE_ANNOTATIONS    = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)
ASSIGN_ANNOTATIONS    = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True,  open_world_hint=True)
MUTATE_ANNOTATIONS    = ToolAnnotations(read_only_hint=False, destructive_hint=True,  idempotent_hint=True,  open_world_hint=True)
```

Classification (idempotent = same inputs → same end state):

| Operation | Constant | Notes |
|---|---|---|
| list / get / search / status | READ_ONLY | never destructive |
| create, send, post, launch job | CREATE | not idempotent |
| add / assign / set (same value again is a no-op) | ASSIGN | |
| full-replace update, delete, unassign | MUTATE | destructive; delete is idempotent |
| append, increment, update with etag/version | CREATE-like, `idempotent_hint=False` | second call differs |
| irreversible or external side effects (send message/mail, payment, code execution, share publicly) | MUTATE or CREATE with `destructive_hint=True` | say in `description` that user confirmation is expected |

`open_world_hint=True` for anything talking to an external system/API; `False` only for purely local, closed-domain tools.
A tool must never be `read_only_hint=True` and `destructive_hint=True` at once.

## 2. Security

- Secrets only via environment variables (or mcprack-injected env); never CLI arguments, never logged, never echoed in tool output or error messages. No hardcoded tokens/URLs with credentials.
- Validate all inputs (pydantic types, enums, length/range limits). File/path tools: confine to an allowed root, resolve symlinks. URL-fetching tools: prevent SSRF (scheme allowlist, no internal ranges unless the server's purpose requires it).
- Provide a **read-only mode** (env var `<PREFIX>_READ_ONLY`) that does not register mutating tools when set. For servers with destructive tools it is the default in the companion `postinst` (see §4).
- Timeouts on every outbound request; cap response size (truncate + say so) to protect model context.
- Errors: return actionable messages without stack traces, tokens, or full request headers.
- Run `pip-audit`/dependency review when bumping dependencies; do not vendor secrets in tests or fixtures.

## 3. Runtime / SDK

- **stdio transport is mandatory** (mcprack proxies stdio servers). If the server defaults to HTTP, add an env-selected stdio path (see `mcp-server-redmine` main.py); reject OAuth-only auth on the stdio path.
- Use the current `mcp`/`fastmcp` generation; upgrade the server code rather than pinning or downgrading the library. The dependency floor stays `fastmcp>=4.1.4` / `python3-fastmcp (>= 4.1.4)` in `debian/control`; do not pin old pre-releases (`4.0.0a2`, `4.0.0b1`, `4.0.0b3`). Our library packages track upstream per §9 and currently ship: `python3-fastmcp` = PrefectHQ/fastmcp main @ 4.2.0~a3-2 (upstream stable line is v4.1.6; all fastmcp GHSAs are patched ≤ 4.1.1) and `python3-mcp` = modelcontextprotocol/python-sdk v2.3.0 + main, packaged as `1:2.3.0-1` (all python-sdk GHSAs patched ≤ 2.2.0). Beware: **mcp SDK 2.x renamed `mcp.server.fastmcp.FastMCP` to `mcp.server.mcpserver.MCPServer`** — servers on the `mcp` package must use the 2.x API or depend on the `fastmcp` package instead.
- Console-script entry point installed as `/usr/bin/mcp-server-<name>` (see §3a), supports `--version` and `--help`.
- Implement resources/prompts only when useful; if present, list them in `server.json` (`cz.vitexsoftware.mcp.prompts` / `.resources`).

## 3a. Naming: package = binary = catalog entry (`mcp-server-<name>`)

One `<name>` (lowercase, hyphens, e.g. `multiflexi`, `abraflexi`, `cc-token-saver`) drives every identifier:

| Thing | Name |
|---|---|
| Debian source + server package | `mcp-server-<name>` |
| Companion package | `mcprack-mcp-server-<name>` |
| **Launcher script in `/usr/bin/`** | **`mcp-server-<name>`** (identical to the package name) |
| mcprack catalog entry (`mcprack server create <name>`) | `mcp-server-<name>` |
| Python distribution (`pyproject.toml` `name`) | `mcp-server-<name>` |
| Python module / import package | `mcp_server_<name>` |
| Console script (`[project.scripts]`) | `mcp-server-<name> = mcp_server_<name>.__main__:main` |
| Repo name (GitHub / Forgejo) | `mcp-server-<name>` |
| Env var prefix | `MCP_SERVER_<NAME>_…` or the upstream service prefix, documented in README |

Rules:
- The postinst `--command` MUST be `/usr/bin/mcp-server-<name>`, never a legacy name (`<name>-mcp-server`, `<name>-mcp`, `phone-mcp`, …).
- Do not add `python3-` to the server package name (it is an app); a `python3-mcp-server-<name>` package exists only if the code is also a reusable library.
- Renaming an existing server: rename binary, package, module and repo together; keep the old names working:
  - `Provides:`/`Replaces:`/`Breaks: <old-package> (<< <first-new-version>~)` in `debian/control`;
  - ship the old binary name as a compatibility symlink (`dh_link usr/bin/mcp-server-<name> usr/bin/<old-name>`) for at least one release, so existing client configs keep working;
  - update mcprack: the old catalog entry is replaced by the `mcp-server-<name>` entry (postinst re-registers; check `mcprack server show` for a stale old entry and delete it), plus the Ansible roles / `Suggests:` in `mcprack/debian/control` that mention the old name.
- Upstream forks packaged as-is (e.g. `netbox-mcp-server`, `mcp-server-ms-365`) still get the `mcp-server-<name>` Debian package/binary name; the upstream repo name may stay unchanged.
- Tool names inside the server are NOT part of this renaming (breaking for clients; see the top of this file).

## 4. Debian packaging + mcprack companion

Two binary packages from one source and one changelog:

1. `mcp-server-<name>` — the server (no `python-`/`python3-` prefix for apps/CLI tools). When renaming, add `Provides/Replaces/Breaks` for the old name.
2. `mcprack-mcp-server-<name>` — companion, ships no files, only `postinst`/`prerm`.

`debian/control` companion stanza:

```
Package: mcprack-mcp-server-<name>
Architecture: all
Depends: ${misc:Depends},
 mcprack (>= 1.6.0),
 mcp-server-<name> (= ${binary:Version}),
Description: Registers <Thing> MCP server into mcprack catalog
 Companion package for mcp-server-<name>. Installing it registers
 the mcp-server-<name> binary as an available MCP server in the local mcprack
 instance; removing it unregisters it again.
```

The `mcprack (>= 1.6.0)` floor is mandatory: the smoke test below runs
`mcprack server probe`, which only exists from 1.6.0 on.

`debian/mcprack-mcp-server-<name>.lintian-overrides`: `mcprack-mcp-server-<name>: empty-binary-package`

`debian/mcprack-mcp-server-<name>.postinst` (chmod 755):

```sh
#!/bin/sh
set -e

case "$1" in
  configure)
    if getent passwd mcprack >/dev/null 2>&1 && [ -d /usr/lib/mcprack ]; then
      su -s /bin/sh mcprack -c "cd /usr/lib/mcprack && set -a; . /etc/mcprack/env; set +a; \
        mcprack server create mcp-server-<name> \
          --label '<Human Readable Label>' \
          --transport stdio \
          --command /usr/bin/mcp-server-<name> \
          --category debian \
          --enabled" || true
    fi
    ;;
esac

#DEBHELPER#

exit 0
```

`debian/mcprack-mcp-server-<name>.prerm` (chmod 755):

```sh
#!/bin/sh
set -e

case "$1" in
  remove|deconfigure)
    if getent passwd mcprack >/dev/null 2>&1 && [ -d /usr/lib/mcprack ]; then
      su -s /bin/sh mcprack -c "cd /usr/lib/mcprack && set -a; . /etc/mcprack/env; set +a; \
        mcprack server delete mcp-server-<name> --yes" || true
    fi
    ;;
esac

#DEBHELPER#

exit 0
```

Rules:
- Catalog name = `mcp-server-<name>`; never reuse names from the `mcp_rack` Ansible role (`warden-mcp`, `mastodon-mcp`, …).
- Add `--arg VALUE` (repeatable) for CLI arguments; `--set-env KEY=VALUE` for **non-secret** env (e.g. `<PREFIX>_TRANSPORT=stdio`, and **`<PREFIX>_READ_ONLY=true` for any server with destructive tools**). Secrets are never set here.
- pybuild pitfall: with two binary packages `debian/rules` MUST have
  ```make
  override_dh_auto_install:
  	dh_auto_install --destdir=debian/mcp-server-<name>
  ```
  and any other hardcoded `debian/<old-name>/` paths updated. Always confirm with `dpkg-deb -c` that the module and `/usr/bin/mcp-server-<name>` are inside.
- `Depends` on `python3-mcp` etc. explicit; run tests via `debian/tests/control` (autopkgtest), not at build time if deps are absent from the chroot.
- **Smoke-test the installed binary via autopkgtest** — mandatory, see "Smoke test (DEP-8 autopkgtest)" below.
- AppStream: `debian/metainfo.xml` referenced with the `debian/` prefix in `.install` files.
- Add the server to the "MCP server projects" list in `~/Projects/VitexSoftware/mcprack/README.md`.

### Smoke test (DEP-8 autopkgtest) — mandatory for every server

`debian/tests/control` MUST contain a `smoke` test that runs the mcprack CLI
probe against the **installed** binary and prints the tools/resources/prompts
the server provides:

```
Tests: smoke
Depends: @, mcprack (>= 1.6.0)
Restrictions: allow-stderr
```

`debian/tests/smoke` (chmod 755):

```sh
#!/bin/sh
# DEP-8 smoke test: spawn the real installed binary, perform the MCP
# handshake, and print the tools/resources/prompts it serves. A broken
# runtime dependency (python3-fastmcp, python3-mcp, ...) makes the server
# process crash on import, which fails the probe with a non-zero exit.
set -e
mcprack server probe /usr/bin/mcp-server-<name> --set-env <PREFIX>_READ_ONLY=true
```

`mcprack server probe COMMAND [ARGS...]` (mcprack >= 1.6.0) spawns the
command, speaks MCP over stdio (`initialize`, `tools/list`,
`resources/list`, `prompts/list`) and exits 0 only when the server answers
them all — so the printed resource/tool list in the autopkgtest log doubles
as build proof that the package and its dependencies work. `Depends: @`
installs both binary packages from this source (the companion pulls in
mcprack), and the companion's `Depends: mcprack (>= …)` MUST be bumped to
the first release shipping `server probe` (1.6.0+). Keep any existing
`unit` test entry alongside `smoke`. Verify locally after `dpkg -i`:

```sh
mcprack server probe /usr/bin/mcp-server-<name> --set-env <PREFIX>_READ_ONLY=true
```

## 5. CI (Jenkins)

`debian/Jenkinsfile` and `debian/Jenkinsfile.release` both need `buildBlocker` exactly as specified in `~/Projects/AGENTS.md` ("Jenkinsfile buildBlocker — MANDATORY"). Do not add `debian:forky`, do not use `--ipc=host`. Use the `setup-jenkins-deb-pipeline` skill for new pipelines.

## 6. Documentation and metadata

- `README.md`: install (`apt install mcp-server-<name>` / `mcprack-mcp-server-<name>`), env variables (secret vs non-secret), read-only mode, table of tools with their annotation class.
- `SKILL.md`: when/how an agent should use the server (front matter `name`, `description`).
- **`server.json` — the ONE metadata file of the server** (the source of truth mcprack reads; an existing `lhm.plugin.json` is **kept, never deleted** - it may be used by other consumers such as marketplace listings - and is no longer read by mcprack once `server.json` exists. Keep the facts they share - title/name, description, version, author, homepage - identical in both). It is a valid [MCP Registry `server.json`](https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json) (so it can be published with `mcp-publisher`) that additionally satisfies our stricter schema, **`mcprack/schemas/mcp-server.schema.json`** (in the mcprack repository; the Registry schema allows extra keys, ours requires some). Validate with `python3 -m mcprack.manifest validate server.json` (exit 1 on any violation; needs no mcprack configuration - on an installed host `PYTHONPATH=/usr/lib/mcprack`; the same is `mcprack server manifest-validate` on a configured instance). Convert a legacy file with `python3 -m mcprack.manifest convert lhm.plugin.json --package mcp-server-<name> --new-uuid -o server.json`, then fix what it reports as `TODO`.
  Required content:
  - `name` (`io.github.vitexsoftware/mcp-server-<name>` - reverse-DNS, one slash), `title`, `description` (**one sentence, max 100 characters**), `version` (exact), `websiteUrl`, `repository` `{"url": "<GitHub project>", "source": "github"}`.
  - `packages[]` (at least one: `registryType`, `identifier`, `transport` `{"type": "stdio"}`) and in it **`environmentVariables`**: every variable the server reads - `name` (exact), `description`, `isRequired` only for values without which the server cannot start, `isSecret` for credentials (a secret never has a `default`), `default`/`choices` where sensible. mcprack pre-fills its config form from this list and shows it as the server's "Parameters". Keep it in sync with the README env table.
  - `_meta` → `io.modelcontextprotocol.registry/publisher-provided` → **`cz.vitexsoftware.mcp`** (our extension, the only place for our own fields): `uuid`, `author` `{name, url}`, `tools` (every registered tool: `name`, `description`, optionally `title`, `annotations`, `inputSchema`), and optionally `longDescription` (paragraphs for the page), `category`, `tags`, `prompts`, `resources`.
  ```json
  {"$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
   "name": "io.github.vitexsoftware/mcp-server-example", "title": "Example MCP Server",
   "description": "Manage Example from an AI assistant.", "version": "1.0.0",
   "websiteUrl": "https://github.com/VitexSoftware/mcp-server-example",
   "repository": {"url": "https://github.com/VitexSoftware/mcp-server-example", "source": "github"},
   "packages": [{"registryType": "pypi", "identifier": "mcp-server-example", "version": "1.0.0",
     "transport": {"type": "stdio"},
     "environmentVariables": [{"name": "EXAMPLE_URL", "description": "Base URL", "isRequired": true},
                              {"name": "EXAMPLE_TOKEN", "description": "API token", "isSecret": true}]}],
   "_meta": {"io.modelcontextprotocol.registry/publisher-provided": {"cz.vitexsoftware.mcp": {
     "uuid": "<uuid4>", "author": {"name": "Vítězslav Dvořák", "url": "https://github.com/VitexSoftware"},
     "tools": [{"name": "list_things", "description": "List things"}]}}}}
  ```
  - **Where the file lives.** Own projects: `server.json` in the repository root (the standard Registry location; installed with `server.json usr/share/<binary>/` in `debian/<package>.install`). **A fork of an upstream project that ships its own root `server.json`** (e.g. `mcp-server-googleoffice`, `mcp-server-librenms`): leave upstream's file untouched - it is managed by upstream's release tooling and would conflict on every merge - and keep ours in `debian/server.json` (installed with `debian/server.json usr/share/<binary>/`). Its `name` is ours (`io.github.vitexsoftware/...`), `repository` is our fork.
  - **Tools are listed by introspection, not by hand.** `python3 -m mcprack.manifest sync [--env K=V ...] server.json -- <command that starts the server on stdio>` starts the server, asks it for `tools/list`, `prompts/list` and `resources/list` and writes them (with titles, annotations and input schemas) into the extension block; with `--check` it only verifies that the file lists exactly what the server serves (exit 1 on a mismatch) - run it in CI/autopkgtest and after every change to the tools. Use placeholder credentials in `--env` (and enable write tools, e.g. `RAYNET_WRITE_ENABLED=true`, so the list is complete). Servers that proxy another server's tools (e.g. a bridge mode) are listed in their self-contained mode and say so in `longDescription`.
  - **`uuid` is the identity of the server kind.** Generate it once when the server is created (`python3 -c 'import uuid; print(uuid.uuid4())'`, or `--new-uuid` of the converter), commit it, and **never change or reuse it** - not when the server is renamed (§3a; `name`, `identifier` and the package name may change, the uuid may not), re-packaged, forked-and-continued or moved to another repository. mcprack adopts it, so the same server has the same UUID on every installation and its page `/server/<uuid>` survives renames. A new, unrelated server gets a new UUID.
  - **Install it** in the server package at `/usr/share/<binary>/server.json` (`debian/<package>.install`: `server.json usr/share/<binary>/`). A companion package may instead ship `/usr/share/mcprack/manifests/<binary>.json` for a server whose package it does not control. Until it is installed mcprack cannot see it. Maximum size 1 MiB (it lists every tool).
  - Do not repeat the same facts elsewhere by hand: author/description/homepage live here, the AppStream metainfo is kept consistent with it.
  - AppStream metainfo (distribution catalogues, and the fallback for the page): `<name>`, `<summary>`, `<description>`, `<project_license>`, `<developer><name>`, `<url type="homepage">`, `<url type="vcs-browser">` (many existing files lack it), `<url type="bugtracker">`, `<provides><binary>mcp-server-<name></binary></provides>` (how mcprack matches the metainfo to the server), `<icon>`.
  - Existing servers without a UUID: assign one in the next release; until then mcprack generates a per-instance UUID and says so on the page. A server that has only `lhm.plugin.json` is still read by mcprack as a fallback and flagged on its page until its `server.json` exists.
- `CHANGELOG.md` + `debian/changelog` kept in sync; `debian/copyright` present.

## 7. Tests

- Unit test (no live backend) that iterates the registered tools (`list_tools()` in-memory) and asserts for **every** tool: title present and ≠ name, annotations present with all four hints not `None`, and no `read_only ∧ destructive`.
- Name-consistency test: names starting `get_/list_/search_` ⇒ `read_only_hint=True`; names with `delete/remove` ⇒ `destructive_hint=True`.
- Read-only mode test: with `<PREFIX>_READ_ONLY=true` no non-read-only tool is registered.
- Manifest test: `python3 -m mcprack.manifest validate server.json` passes (run it in pytest or in the autopkgtest), the tool names in `server.json` equal the registered tools, every env variable the code reads is in `environmentVariables`, and the `uuid` equals the one in the previous release (identity must not drift).
- Test that secrets do not appear in error output.
- Pattern: `~/Projects/Packaging/mcp-server-nextcloud/tests/server/test_annotations.py` (adapt away from the integration fixture).

## 8. Adapting an existing server — procedure

1. Inventory: `grep -rn "@mcp.tool\|@app.tool\|add_tool" src/` and list tools lacking `annotations=`/`title=`.
2. Produce a table tool → class (§1) and show it to the user before large edits.
3. Add constants, apply to tools, add tests (§7), then packaging (§4), docs (§6), CI (§5).
4. Never change tool names/parameters as part of this; propose separately.
5. Follow the global commit rule (message via `mcp__cc-token-saver__generate_commit_message`).

## 9. Forks — track upstream releases and security fixes

If the project is a **fork** of an upstream project (e.g. under `Vitexus/` or `VitexSoftware/`
with an `upstream` remote, or packaged from a third-party repo), it must not be left to go stale:

- Whenever you touch a fork (adapt, upgrade, package, release), **first check whether upstream
  published a new release, tag, or security fix** since our last sync
  (`git remote -v` → add `upstream` if missing; `git fetch upstream --tags`;
  `git log HEAD..upstream/<default-branch> --oneline`; compare latest upstream release/tag,
  GitHub Security Advisories and CVEs for the project and its dependencies).
- **Backport** new releases and every security fix into our fork — merge/rebase upstream, or
  cherry-pick when our local changes (naming per §3a, annotations per §1, packaging) conflict.
  Security fixes take priority over feature releases.
- After the backport: re-verify the Definition of Done (tool annotations and naming can be
  overwritten by a merge), bump the Debian version (`debian/changelog`, mention the upstream
  version/CVE ids), update `debian/watch` so it follows the upstream, and release.
- Record the upstream base in `debian/changelog` / README (upstream version + date of last sync).
- If a backport is not possible or intentionally skipped, say so explicitly to the user and note
  the reason (and any open CVE) in the README or changelog — never skip silently.

## Definition of Done

- [ ] Every tool: title, description, parameter descriptions, four explicit annotation hints
- [ ] Shared annotation constants; classification matches §1 table
- [ ] Secrets from env only; inputs validated; timeouts and output caps; read-only mode
- [ ] Package, `/usr/bin` launcher, catalog entry, module and repo all follow `mcp-server-<name>` (§3a); old names kept as compat symlink/Provides
- [ ] stdio works; `--version`/`--help`; current mcp/fastmcp generation
- [ ] `mcp-server-<name>` + `mcprack-mcp-server-<name>` (control, postinst, prerm, lintian override, `--destdir`); companion `Depends: mcprack` bumped to >= 1.6.0
- [ ] Companion sets `--set-env <PREFIX>_READ_ONLY=true` if destructive tools exist
- [ ] `debian/tests/control` has a `smoke` test running `mcprack server probe /usr/bin/mcp-server-<name> --set-env <PREFIX>_READ_ONLY=true` (`Depends: @, mcprack (>= 1.6.0)`); it passes and prints the server's tools/resources in the autopkgtest log
- [ ] Jenkinsfile + Jenkinsfile.release with buildBlocker; no forky / `--ipc=host`
- [ ] ONE `server.json`, valid per `mcprack/schemas/mcp-server.schema.json` (`python3 -m mcprack.manifest validate server.json` passes): Registry fields, `packages[].environmentVariables` listing every env variable (name, required, secret, default, choices), and `cz.vitexsoftware.mcp` with `uuid` (fixed forever), `author` and every tool; installed to `/usr/share/<binary>/server.json`; a test asserts each variable name appears in the README env table
- [ ] AppStream metainfo has summary, description, license, developer, homepage, `vcs-browser`, bugtracker and `<provides><binary>`
- [ ] README, SKILL.md, server.json, metainfo, changelogs, mcprack README list updated
- [ ] Annotation, name-consistency and read-only tests pass (`pytest`)
- [ ] Fork only: upstream checked for new releases / security fixes, all backported (or skip reason documented), upstream base version recorded (§9)

Verification commands:
```sh
dpkg-buildpackage -us -uc -b
dpkg-deb -c ../mcp-server-<name>_*.deb | grep -E "usr/bin/mcp-server-<name>|dist-packages"
dpkg-deb -f ../mcprack-mcp-server-<name>_*.deb Depends
lintian ../mcp-server-<name>_*.deb ../mcprack-mcp-server-<name>_*.deb
sh -x debian/mcprack-mcp-server-<name>.postinst configure   # on host without mcprack: exits 0, does nothing
pytest
# the autopkgtest smoke test, run locally against the installed binary:
mcprack server probe /usr/bin/mcp-server-<name> --set-env <PREFIX>_READ_ONLY=true   # must exit 0 and list tools/resources
```
