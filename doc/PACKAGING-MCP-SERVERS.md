# Packaging an MCP server so it self-registers in mcprack

This describes the convention used across VitexSoftware/Vitexus MCP server
packages (`mcp-server-abraflexi`, `mcp-server-zabbix`, `mcp-server-webdriver`,
`mcp-server-datovka`, and others) to make a Debian package for a **stdio**
MCP server automatically add itself to a local mcprack catalog on install,
and remove itself on uninstall — with zero manual admin steps.

It is unrelated to the [Admin → Install](../README.md#installing-new-mcp-servers-pip--npm--docker)
pip/npm/docker installer described in the main README: that is a runtime,
admin-driven install into `/var/lib/mcprack/installs/`; this document
describes a **build-time** Debian package that ships its own binary via apt
and only *tells* an already-installed mcprack about it.

## Overview

Each MCP server project ships **two binary packages built from the same
source**:

1. **`mcp-server-<name>`** — the actual MCP server (unmodified apart from
   naming). This is the package that would exist regardless of mcprack.
2. **`mcprack-mcp-server-<name>`** — a small companion package containing
   nothing but a `postinst`/`prerm` pair. Installing it registers
   `mcp-server-<name>`'s binary into the local mcprack catalog; removing it
   unregisters that catalog entry. It does not ship any files of its own
   (lintian's `empty-binary-package` warning is expected and overridden).

Both packages share one `debian/changelog`/version. The companion package
`Depends:` on `mcprack (>= <version with the CLI options you use>)` and on
`mcp-server-<name> (= ${binary:Version})`, so apt always installs/upgrades
them together.

## Naming convention

- Debian `Source:`/`Package:` for the server itself: **`mcp-server-<name>`**
  (e.g. `mcp-server-abraflexi`, not `abraflexi-mcp-server`). If the project's
  existing name doesn't match, rename it — see
  [Renaming an existing package](#renaming-an-existing-package) below.
- Companion package: **`mcprack-mcp-server-<name>`**, same `<name>`.
- Catalog entry name passed to `mcprack server create`/`delete`:
  **`mcp-server-<name>`** — the same string as the main Debian package name.
  Do **not** reuse a name already used by the `mcp_rack` Ansible role's
  HTTP-proxy registrations (e.g. `warden-mcp`, `mastodon-mcp`,
  `abraflexi-dev`) — those are a *different* catalog entry (`transport: http`,
  proxied), and sharing a name means whichever mechanism runs last silently
  overwrites the other's `transport`/`command`.

## The companion package's `debian/control` stanza

```control
Package: mcprack-mcp-server-<name>
Architecture: all
Depends:
 ${misc:Depends},
 mcprack (>= 1.5.4),
 mcp-server-<name> (= ${binary:Version}),
Description: Registers <Thing> MCP server into mcprack catalog
 Companion package for mcp-server-<name>. Installing it registers
 the <actual-binary-name> binary as an available MCP server in the
 local mcprack instance; removing it unregisters it again.
```

Pin the `mcprack (>= X)` version to whatever CLI features you actually use
(see [`mcprack server create` reference](#mcprack-server-create-reference)
below) — `--set-env` needs `>= 1.5.4`, plain `--command`/`--arg` needs only
`>= 1.5.1` (the release that first shipped `server create` with working code).

Add a `debian/mcprack-mcp-server-<name>.lintian-overrides`:

```
mcprack-mcp-server-<name>: empty-binary-package
```

## `postinst` / `prerm`

Both scripts share the same defensive pattern: **do nothing (successfully)**
if mcprack isn't actually installed on this host, so the companion package
never blocks installation or removal on a machine that doesn't run mcprack.

`debian/mcprack-mcp-server-<name>.postinst`:

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
          --command /usr/bin/<actual-binary-name> \
          --category debian \
          --enabled" || true
    fi
    ;;
esac

#DEBHELPER#

exit 0
```

`debian/mcprack-mcp-server-<name>.prerm`:

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

Notes on why each piece is there:

- `getent passwd mcprack` + `[ -d /usr/lib/mcprack ]` — mcprack creates a
  system user and installs its app code there; both existing is a reasonable
  proxy for "mcprack is actually installed here."
- `su -s /bin/sh mcprack -c "..."` — run as the `mcprack` user, exactly like
  `debian/README.Debian`'s documented admin CLI usage
  (`su -s /bin/sh mcprack -c 'cd /usr/lib/mcprack && ... && mcprack ...'`).
- `cd /usr/lib/mcprack` — that's where the installed app lives; needed for
  relative imports/config discovery.
- `set -a; . /etc/mcprack/env; set +a` — sources mcprack's own config
  (`SQLALCHEMY_DATABASE_URI`, `SECRET_KEY`, etc.) so the CLI can talk to the
  real database, not a default in-memory/sqlite fallback.
- `|| true` at the end of the whole `su` invocation — a missing/misconfigured
  mcprack install (or the DB being briefly unavailable) must never fail the
  *server's own* package install/removal.
- `--yes` on `server delete` — skips the interactive confirmation prompt
  (`mcprack server delete` uses `click.confirmation_option`, which
  auto-registers `-y`/`--yes`); without it, a non-interactive `apt remove`
  would hang or error on the prompt.

Remember `chmod 755` both scripts before building.

## `mcprack server create` reference

```
mcprack server create <name> --label TEXT --transport {stdio,http,sse}
    [--command CMD] [--arg VALUE ...] [--url URL] [--category TEXT]
    [--enabled/--disabled] [--set-env KEY=VALUE ...]
```

Idempotent: if `<name>` already exists it's updated in place (safe to call
on every `apt install`/upgrade); if not, it's created. Relevant options for
a stdio server:

- `--command` — absolute path to the binary, e.g. `/usr/bin/foo-mcp-server`.
- `--arg` — repeatable; one positional CLI argument per flag, e.g.
  `--arg run --arg --transport --arg stdio` for a server whose invocation is
  `foo-mcp-server run --transport stdio`.
- `--category debian` — marks the entry as debian-package-managed in the
  catalog UI, distinguishing it from manually-registered or
  Ansible/mcp_rack-managed entries.
- `--set-env KEY=VALUE` — repeatable; sets a **non-secret** env var in the
  server's stored config, which mcprack injects into the spawned process at
  proxy time. Use this when the server needs an env var to *select* stdio
  mode rather than defaulting to it (see
  [When the server needs an env var to enable stdio](#when-the-server-needs-an-env-var-to-enable-stdio)).
  Needs `mcprack >= 1.5.4`.

`mcprack server delete <name> --yes` removes the catalog row and any stored
secrets for it.

## `debian/rules`: the pybuild two-binary-package pitfall

**This is the single most common way this pattern silently breaks.** If the
server is packaged with `--buildsystem=pybuild` (true for every Python/
FastMCP-based server in this family) and you add a second binary package
without also passing an explicit `--destdir`, `dh_auto_install` routes the
actual Python module into an unused `debian/python3-<name>/` staging
directory instead of `debian/mcp-server-<name>/` — the build succeeds,
lintian passes, but the shipped `mcp-server-<name>` package silently
**contains no code**. This happened for real during initial rollout
(`abraflexi-mcp-server` 1.4.0–1.4.2) and was only caught by checking
`dpkg-deb -c` output, not by the build log or lintian.

Fix: always pass `--destdir` explicitly once a second binary package exists:

```make
override_dh_auto_install:
	dh_auto_install --destdir=debian/mcp-server-<name>
```

If `override_dh_auto_install` already does other things (installing extra
scripts, generating a man page with `help2man`, bundling private
dependencies, etc.), every hardcoded `debian/<old-package-name>/...` path in
that recipe must be updated to `debian/mcp-server-<name>/...` too — grep the
whole `debian/rules` for the old package name, not just the `dh_auto_install`
line.

**Always verify with `dpkg-deb -c ../mcp-server-<name>_*.deb` after building**
that the actual Python module (`/usr/lib/python3/dist-packages/<module>/`)
and the binary (`/usr/bin/<binary>`) are present — a clean `lintian` run does
not prove this.

## When the server needs an env var to enable stdio

Some servers default to HTTP and only support stdio behind an env var (this
family's example: `mcp-server-redmine`, which needs
`REDMINE_MCP_TRANSPORT=stdio`). Set it at registration time with `--set-env`:

```sh
mcprack server create mcp-server-redmine \
  --label 'Redmine MCP Server' \
  --transport stdio \
  --command /usr/bin/redmine-mcp-server \
  --set-env REDMINE_MCP_TRANSPORT=stdio \
  --category debian \
  --enabled
```

If the server has no stdio support in its code at all yet, that is a real
code change in the server itself, not a packaging one — see
`mcp-server-redmine`'s `main.py` for a minimal example: a `transport` env var
check in the console-script entry point that calls the already-imported
FastMCP instance's `mcp.run(transport="stdio")` instead of starting uvicorn,
short-circuiting before any HTTP-only setup (OAuth providers, etc.) runs.
Reject authenticated/OAuth auth modes explicitly for the stdio path — stdio
has no browser to complete an OAuth flow — following
`mcp-server-nextcloud`'s `stdio.py` (a single-user, BasicAuth-only stripped
FastMCP instance) as the reference pattern.

## Registering a server in read-only mode

Some servers support a read-only/safe-by-default mode via an env var —
this family's example: `mcp-server-filesystem`, which defaults to
`FS_READONLY=true` and only exposes mutating tools (write/delete/move/copy)
when explicitly set to `false` (see the "Trying it out" section in the main
README). When packaging a companion package for a server like this, set the
read-only var explicitly at registration time with `--set-env`, the same
mechanism used for a stdio-enabling var:

```sh
mcprack server create mcp-server-filesystem \
  --label 'Filesystem MCP Server' \
  --transport stdio \
  --command /usr/bin/mcp-server-filesystem \
  --set-env FS_READONLY=true \
  --category debian \
  --enabled
```

Prefer registering read-only by default for any server whose backend
exposes destructive tools, even if the upstream binary itself defaults to
read-write — a companion package runs unattended at `apt install` time with
no admin review of the resulting catalog entry, so the safer default belongs
in the `postinst`, not left to whatever the binary ships with. An admin who
actually wants write access can flip it afterward with `mcprack server edit
<name> --set-env FS_READONLY=false` (or the equivalent var for that server).

This only applies to servers that have a real read-only mode in their own
code — like the stdio-enabling case above, adding one where none exists is
a code change in the server itself, not a packaging one.

## Renaming an existing package

When a server was originally packaged under a name that doesn't fit
`mcp-server-<name>` (e.g. `abraflexi-mcp-server`, `zabbix-mcp-server`), do a
straight Debian package rename rather than a fresh package:

```control
Package: mcp-server-<name>
...
Provides: <old-name>
Replaces: <old-name> (<< <next-version>~)
Breaks: <old-name> (<< <next-version>~)
```

This gives every existing install a clean `apt upgrade` path to the new name
instead of leaving the old package orphaned. Also update, in the same
change:

- `Source:` in `debian/control` (not just `Package:`).
- `Vcs-Git:`/`Vcs-Browser:` if the GitHub repo is renamed to match (`gh repo
  rename`) — only rename the repo if you have admin rights on its org; if
  not, leave `Vcs-Git` pointing at the real, unrenamed location rather than
  a URL that 404s.
- Every hardcoded `debian/<old-name>/...` path in `debian/rules`.
- Any `debian/<old-name>.install`/`.docs`/`.manpages` control file — rename
  the *file* to `debian/mcp-server-<name>.install` etc. (debhelper matches
  these by package name). Leave alone any file that names an actual
  installed *binary* rather than the package — e.g. a generated man page
  should stay named after the binary (`foo-mcp-server.1`), not the new
  package name, or lintian's `no-manual-page` check fires because it looks
  for a man page matching the binary on `PATH`.
- Downstream consumers that reference the old package name literally: check
  `mcprack`'s own `debian/control` `Suggests:` list (this repo) and any
  Ansible role/playbook that does `apt: name: <old-name>`.

## Servers that are excluded from this pattern

- **HTTP-only servers with no stdio code path** (verify by reading the
  entry point — see the pybuild pitfall note above about checking, not
  assuming) — either add stdio support first (see previous section) or
  leave them HTTP-only and register them via the `mcp_rack` Ansible role's
  proxy mechanism instead (`transport: http`, a different registration path
  entirely, documented in `spojeitisac/roles/mcp_rack/README.md`).
- **MCP clients, not servers** — a package whose entry point drives a chat
  REPL or connects *out* to other MCP servers (e.g. `mcp-client-for-ollama`)
  has nothing to register; don't force it into this pattern.

## Verification checklist

For both packages after every change:

1. `dpkg-buildpackage -us -uc -b` — must produce both `.deb` files.
2. `dpkg-deb -c ../mcp-server-<name>_*.deb | grep <module-or-binary>` — the
   actual code must be present (see the pybuild pitfall above).
3. `dpkg-deb -f ../mcprack-mcp-server-<name>_*.deb Depends` — confirm it
   depends on the exact `mcp-server-<name> (= <version>)` just built.
4. `lintian ../mcp-server-<name>_*.deb ../mcprack-mcp-server-<name>_*.deb` —
   should show no *new* findings versus before your change (pre-existing
   findings in mature packages, e.g. missing `debian/copyright`, are not
   yours to fix as part of this).
5. Run the `postinst`/`prerm` scripts directly (`sh -x debian/mcprack-mcp-server-<name>.postinst configure`)
   on a host without mcprack installed — they must exit 0 and do nothing.
6. On a host that does run mcprack: install both packages, confirm
   `mcprack server show mcp-server-<name>` reflects the right
   `command`/`transport`/`env config`; remove the companion package, confirm
   `mcprack server show mcp-server-<name>` reports "No such MCP server".
