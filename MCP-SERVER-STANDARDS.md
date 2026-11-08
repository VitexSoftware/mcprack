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
- Extras: `SKILL.md`, `lhm.plugin.json` in `multiflexi-mcp-server`

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
- Use the current `mcp`/`fastmcp` generation; upgrade the server code rather than pinning or downgrading the library. The current FastMCP release is **4.1.4** (https://github.com/PrefectHQ/fastmcp/releases/tag/v4.1.4). Depend on `fastmcp>=4.1.4` and, in `debian/control`, `python3-fastmcp (>= 4.1.4)`. Do not pin a pre-release (`4.0.0a2`, `4.0.0b1`, `4.0.0b3`).
- Console-script entry point installed as `/usr/bin/mcp-server-<name>` (see §3a), supports `--version` and `--help`.
- Implement resources/prompts only when useful; if present, list them in `lhm.plugin.json`.

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
- `lhm.plugin.json`: `identifier`, `name`, `description`, `category`, `prompts`, homepage/author.
- `server.json` (MCP Registry shape) — **the configuration manifest mcprack reads to pre-fill the server's config form**. Declares every env variable the server reads, so admins pick a name instead of typing it from memory:
  `{"environmentVariables": [{"name": "<PREFIX>_HOST", "description": "...", "isRequired": true, "isSecret": false, "default": "...", "choices": ["a","b"]}]}`.
  `name` is exact (case included); `isRequired` only for values without which the server cannot start; `isSecret` for credentials (a `default` is never pre-filled for a secret); `default` only when a sensible one exists (always a string). Include `<PREFIX>_READ_ONLY`/`_TRANSPORT` where supported. Installed by the server package at `/usr/share/<binary>/server.json` (e.g. `/usr/share/mcp-server-email/server.json`); a companion package may instead ship `/usr/share/mcprack/manifests/<binary>.json` for a server whose upstream package it does not control. Keep it in sync with the README env table.
- `CHANGELOG.md` + `debian/changelog` kept in sync; `debian/copyright` present.

## 7. Tests

- Unit test (no live backend) that iterates the registered tools (`list_tools()` in-memory) and asserts for **every** tool: title present and ≠ name, annotations present with all four hints not `None`, and no `read_only ∧ destructive`.
- Name-consistency test: names starting `get_/list_/search_` ⇒ `read_only_hint=True`; names with `delete/remove` ⇒ `destructive_hint=True`.
- Read-only mode test: with `<PREFIX>_READ_ONLY=true` no non-read-only tool is registered.
- Test that secrets do not appear in error output.
- Pattern: `~/Projects/Packaging/mcp-server-nextcloud/tests/server/test_annotations.py` (adapt away from the integration fixture).

## 8. Adapting an existing server — procedure

1. Inventory: `grep -rn "@mcp.tool\|@app.tool\|add_tool" src/` and list tools lacking `annotations=`/`title=`.
2. Produce a table tool → class (§1) and show it to the user before large edits.
3. Add constants, apply to tools, add tests (§7), then packaging (§4), docs (§6), CI (§5).
4. Never change tool names/parameters as part of this; propose separately.
5. Follow the global commit rule (message via `mcp__cc-token-saver__generate_commit_message`).

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
- [ ] `server.json` lists every env variable (name, required, secret, default, choices) and is installed to `/usr/share/<binary>/server.json`; a test asserts each name appears in the README env table
- [ ] README, SKILL.md, lhm.plugin.json, metainfo, changelogs, mcprack README list updated
- [ ] Annotation, name-consistency and read-only tests pass (`pytest`)

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
