# Configuring users' MCP access as an admin (no user login required)

This guide covers how an administrator can fully configure a non-technical
user's MCP setup — which servers they may use, which of those are actually
included in their generated config, and any individual (per-user)
credentials — entirely from Admin → Users or the `mcprack` CLI. The user
never has to log in, browse the catalog, or set anything themselves.

Every capability described here is available both from the web UI and from
the CLI, backed by the same underlying code (`mcprack/admin.py`,
`mcprack/catalog.py`, `mcprack/secret_store.py`), so the two stay
consistent and either can be scripted or clicked through interchangeably.

## Concepts

- **Server access (ACL)** — allow/deny per user per server
  (`UserServerPermission`). A user with no explicit rows for a server falls
  back to "allowed" (or "denied" if `STRICT_SERVER_PERMISSIONS=true`).
- **Config selection** — which of the *allowed* servers are actually
  included when a config is generated for that user (`UserServerSelection`).
  A server can be allowed but not selected (available but not currently
  wanted in the config).
- **Individual credentials** — per-user override values for one server
  (`UserServerOverride`, resolved through `secret_store.py`). These sit on
  top of the server's admin-set defaults and are stored securely (in
  Vaultwarden if configured, otherwise a local Fernet-encrypted column) —
  never in plain text, and never in a configuration template.
- **Configuration template** (`ConfigTemplate` / `ConfigTemplateServer`) —
  a reusable, named preset of ACL + selection state an admin defines once
  and applies to any number of users. Applying a template replaces that
  user's ACL and selection, but **never touches their individual
  credentials** — those survive untouched and can still be fine-tuned
  afterwards.

## Quick path: template + fine-tuning

1. Create a template once for a class of user (e.g. "field-support"):
   allow the servers that role needs, and pre-select the ones that should
   already be in their config.
2. Create the user account and apply the template to them — one action
   sets up their entire server access + selection.
3. If this particular user needs a personal API key/token for one of the
   servers, set their individual credentials for just that server.
4. Hand them their config file, or point their MCP client at the config
   URL — they never need to log in.

## Web UI

### Create the user

Admin → All Users → **Create local account**. Set username, password
(they can be told to change it, or never need to log in at all if you only
ever hand them a downloaded/exported config), and admin flag if needed.

### Create a configuration template (optional, recommended for groups)

Admin → Config Templates → **New template**. Give it a name and label,
then tick **Allowed** for every server this template's users may use, and
**Pre-selected** for the subset that should already be included in their
generated config.

### Apply a template to a user

Admin → All Users → edit the user → **Apply a configuration template** →
choose the template → **Apply template**. This replaces the user's
server ACL and selection with the template's. Their individual credentials
(if any were already set) are untouched.

### Fine-tune a user's access and selection directly

Admin → All Users → edit the user → **Server access & config selection**
table: pick **Allow**/**Deny** per server, and tick **Included in config**
for the subset that should be in their generated config. A denied server
is automatically excluded from the saved selection even if it was ticked.

### Set individual credentials for one user on one server

From the same table, click **Edit values** next to a server. This works
even when that server has self-service override disabled
(`allow_user_override=False`) — the admin can always set it, only the
user's own self-service page respects that flag. Use **Reset to Default**
to revert to the server's admin-set default credentials.

### Hand off the finished config

Admin → All Users → edit the user → **Client configs** → pick a client
(`claude`/`copilot`) to view or download that user's config file directly.

## CLI

All of the above is also available via `mcprack` (or `flask` in
development — see the main README's "Command-line administration"
section for how the launcher resolves to the Flask CLI).

```bash
# Server access (ACL) and config selection
mcprack user server list alice                       # allow/deny + selection state
mcprack user server allow alice jenkins
mcprack user server deny alice grafana                # also drops it from their selection
mcprack user server select alice --server jenkins --server postgres
                                                       # replaces the selection entirely;
                                                       # omit --server to clear it

# Individual (per-user) credentials
mcprack user override set alice jenkins JENKINS_TOKEN=abc123
mcprack user override list alice jenkins
mcprack user override reset alice jenkins             # revert to the server default

# Hand off the finished config
mcprack user config show alice copilot                # print JSON to stdout
mcprack user config download alice claude --out alice-claude.json

# Configuration templates
mcprack template create field-support --label "Field support"
mcprack template set-servers field-support --select jenkins --select grafana --deny admin-tools
mcprack template show field-support
mcprack template apply field-support alice
mcprack template list
mcprack template delete field-support --yes           # users it was applied to are unaffected
```

Every command has `--help` for the full option list.

### `PUBLIC_BASE_URL` and `mcprack user config show/download`

Some servers are stdio-implemented tools proxied over HTTP for remote
clients (see the main README's "Remote access to stdio MCP servers"
section) — their config entry needs a real, absolute URL back to this
mcprack instance. A browser download can infer that URL from the actual
HTTP request; a CLI invocation has no such request to infer it from. If
`mcprack user config show/download` is used for a user who has any
stdio-implemented, non-network server selected, set `PUBLIC_BASE_URL` in
`/etc/mcprack/env` first:

```bash
PUBLIC_BASE_URL=https://mcprack.example.com
```

Without it, the command fails with a clear error instead of producing a
config with a broken URL. Servers with a real `http`/`sse` URL of their
own don't need this at all.
