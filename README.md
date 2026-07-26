# mcprack

<div align="center">

![mcprack logo](static/mcprack-icon-composite.svg?raw=true)

**Model Context Protocol (MCP) Self-Service Catalog & Config Generator**

</div>

mcprack is a centralized platform for managing and distributing MCP (Model Context Protocol) server configurations across your organization. It solves the problem of how to securely provision AI clients (Claude Desktop, GitHub Copilot, and other MCP-compatible tools) with access to multiple backend services — without hardcoding secrets or requiring manual configuration on each machine.

## What mcprack Does

### The Problem
You have multiple MCP servers (tools that connect AI clients to your services: databases, APIs, knowledge bases, etc.). You want users to:
- Easily discover which servers are available
- Self-serve which ones they need
- Get a ready-to-use config file for their client
- Have credentials managed securely without access to raw secrets

### The Solution
mcprack provides:

1. **Admin UI** — Register MCP servers once, define environment variables and defaults, store secrets in Vaultwarden
2. **User Catalog** — Browse available servers, select which ones you need, choose your target client (Claude, Copilot, etc.)
3. **Config Generator** — Automatically builds a `.json` or `.env` config file tailored to each user with their chosen servers
4. **Credential Management** — Credentials never stored in mcprack's DB; every secret lives in Vaultwarden (optional override per user)
5. **HTTP Proxy** (optional) — Expose stdio-based MCP servers over HTTP so remote clients can access them

### Typical Workflow

1. **Admin** registers a new server (e.g., `mastodon-mcp`):
   - Command: `/usr/bin/mastodon-mcp`
   - Environment variables: `MASTODON_INSTANCE`, `MASTODON_ACCESS_TOKEN`
   - Saves defaults in Vaultwarden secure note: `MCP-mastodon-mcp`

2. **User** logs into mcprack (local account or Active Directory):
   - Sees available servers in the catalog
   - Selects which ones they need: ✓ mastodon-mcp, ✓ postgres-mcp
   - Chooses target: "Claude Desktop"
   - Downloads `claude_desktop_config.json` with only those servers

3. **AI Client** (Claude) loads the config:
   - Starts each selected MCP server as a subprocess
   - Can now call functions and access tools from all those backends

Credentials are never exposed to the user or stored insecurely — they come from Vaultwarden at runtime.

---

## Authentication

**Local accounts** are always available. **LDAP/Active Directory** is optional and disabled by default — enable it during installation if you want users to authenticate with AD credentials instead.

## Key Features

- **Secrets in Vaultwarden, plain config in the DB** — Only the values an admin marks "citlivé"/sensitive (API keys, tokens, passwords) go to Vaultwarden; everything else lives directly in mcprack's own database, no Vaultwarden round-trip needed
- **User-level credential override** — Users can optionally provide their own credentials for any server (stored as `MCP-<server>-user-<username>` in Vaultwarden, or locally encrypted if Vaultwarden isn't configured)
- **Multi-client support** — Generate configs for Claude Desktop, GitHub Copilot, and other MCP-compatible clients
- **Per-user proxy** — Every user connects remotely; stdio servers are spawned on demand, one isolated instance per (user, server) pair, with credentials resolved at spawn time — never embedded in a downloaded config
- **Vaultwarden integration** — Leverages the same `bw-cli` / Secure Note pattern used by the `mcp_rack` Ansible role
- **Works without Vaultwarden too** — If it's not configured, sensitive values fall back to a local Fernet-encrypted column instead; admins can migrate between the two deliberately from Admin → Vaultwarden diagnostics
- **LDAP/AD support** — Optional directory authentication for enterprise deployments

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    mcprack Web App (Flask)                  │
│  • Admin UI (register servers, manage credentials)          │
│  • User Catalog (browse, select, download config)           │
│  • Config Generator (build Claude/Copilot JSON)              │
│  • Per-user proxy (spawns stdio servers on demand)           │
└────────────┬───────────────────┬─────────────────────────────┘
             │                   │
      [SQLite/PG/MySQL]   [Vaultwarden (via bw-cli)]  — only if
      • Server registry    configured; otherwise a local
      • Non-secret config  Fernet-encrypted DB column takes
      • User accounts      over as the secret store instead
      • Server selections  • Sensitive credentials only
             │                   • User overrides
             └─────────┬─────────┘
                       │
                (user downloads config)
                       │
              network entry pointing at
          /proxy/mcp/<token>/<server_id>
                       │
        first connection spawns a dedicated
        fastmcp instance for that user+server,
        resolving credentials at that moment
```

**Components:**
- **Flask App**: Core web service, handles auth, server management, config generation, and the per-user proxy
- **Database**: Server registry, users, selections, and non-secret server config (SQLite, PostgreSQL, or MySQL)
- **Vaultwarden**: Stores sensitive credentials only, when configured — see `secret_store.py`
- **Local encrypted fallback**: Used instead of Vaultwarden when it isn't configured; never both at once for the same value

## Use Cases

**Scenario 1: Team with shared MCP servers**
- Your team has built MCP servers for PostgreSQL, internal APIs, Slack, Jira, etc.
- Developers use Claude Desktop or GitHub Copilot on their own machines
- They need access to different subsets of these servers based on their role
- Solution: Deploy mcprack once, register each server, let users self-serve their configs

**Scenario 2: Enterprise deployment**
- Multiple teams, each with different access controls
- Need to integrate with Active Directory for SSO
- Credentials managed centrally in Vaultwarden
- Solution: mcprack with LDAP enabled, per-team server configurations

**Scenario 3: Remote teams**
- MCP servers hosted on internal network
- Users on different networks/VPNs need to access them
- Solution: this is the default and only mode — every user connects remotely through mcprack's built-in per-user proxy, no extra service to deploy

**Scenario 4: Multi-client support**
- Some users prefer Claude Desktop, others use GitHub Copilot
- Different clients have different config formats
- Solution: mcprack generates client-specific configs automatically

## Authentication

**Local accounts** are always available. **LDAP/Active Directory** is optional and disabled by default — enable it during installation if you want users to authenticate with AD credentials instead.

## Quick start (development)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

cp .env.example .env   # edit as needed
export $(grep -v '^#' .env | xargs)

flask db upgrade
flask create-admin
flask run
```

Open http://127.0.0.1:5000, log in with the admin account you just created,
register a server under **Servers**, then visit the catalog to select it and
download a config.

## Database

`SQLALCHEMY_DATABASE_URI` defaults to SQLite but PostgreSQL
(`postgresql+psycopg2://...`, needs `psycopg2-binary` /
`python3-psycopg2`) and MySQL (`mysql+pymysql://...`, needs `PyMySQL` /
`python3-pymysql`) both work — see `requirements-db.txt`.

## Credentials (Vaultwarden)

In the server edit form, each environment variable row has a "citlivé"
(sensitive) checkbox. Only rows marked sensitive — API keys, tokens,
passwords, and the HTTP auth token key, which is always forced sensitive —
ever leave mcprack's own database. Non-sensitive config (base URLs, regions,
log levels, ...) stays directly in the DB and never touches Vaultwarden.

Sensitive values (a server's defaults, and any personal override a user
sets) live in Vaultwarden — mcprack talks to it the same way the `mcp_rack`
Ansible role does (`bw-cli`, Secure Notes named `MCP-<server-name>` /
`MCP-<server-name>-user-<username>`, plain `KEY=value` lines) — *when
Vaultwarden is configured*. If `BW_SERVER` is unset, the same sensitive
values are stored instead in a local Fernet-encrypted column, keyed off a
subkey derived from `SECRET_KEY`. Which backend is authoritative is decided
purely by configuration, never by live reachability — an unreachable but
configured Vaultwarden is a hard error, not a silent fallback. Admins can
move data between the two deliberately from Admin → Vaultwarden diagnostics
(e.g. after configuring Vaultwarden for the first time, or before a planned
Vaultwarden outage).

### 1. Get an API key from Vaultwarden

1. Log in to the Vaultwarden web vault you want mcprack to use (e.g. the same
   instance `mcp_rack` already uses, such as
   `https://vaultwarden-dev.proxy.spojenet.cz`).
2. Go to **Account Settings → Security → Keys** (or **API Key**) and
   generate/view the API key. Note the **client_id**, **client_secret**, and
   your account's **master password** — these three plus the server URL are
   everything mcprack needs.

### 2. Set the connection variables

Set these four (plus optionally `BW_ITEM_PREFIX`, default `MCP-`) in your
environment — `.env` for local development, `/etc/mcprack/env` in
production (see `debian/README.Debian`):

```bash
BW_SERVER=https://vaultwarden-dev.proxy.spojenet.cz
BW_CLIENTID=user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
BW_CLIENTSECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
BW_PASSWORD=your-vaultwarden-account-master-password
```

`BW_BIN` (default `/usr/bin/bw`) and `BITWARDENCLI_APPDATA_DIR` (where `bw`
keeps its login/session state) rarely need changing from their defaults.

### 3. Verify the connection

Log in as an admin and open **Vaultwarden diagnostics** in the nav bar (or
go straight to `/admin/vaultwarden/wizard`). It checks each prerequisite in
order — `bw` installed, `BW_SERVER` set and reachable, API key valid,
master password unlocks the vault — and stops at the first failing step
with a specific fix, instead of just showing `bw`'s raw error text. Re-run it
after editing `/etc/mcprack/env` and restarting `mcprack.service` so the
updated environment is loaded.

Once every step is green, admins can save server credentials (they're
written straight to a `MCP-<server-name>` Secure Note) and users can
download/view configs (which read those notes back and merge in any
personal override).

## Tests

```bash
pytest
```

## Packaging

See `debian/` — builds a `.deb` following the same conventions as other
VitexSoftware Flask apps (e.g. `abraflexi-yearend`): system Python packages,
no virtualenv, `gunicorn` + systemd. See `debian/README.Debian` for the
post-install configuration steps.

## Remote access to stdio MCP servers

Users always connect remotely — mcprack never assumes a user's Claude/Copilot
client runs on the same machine as mcprack itself. So a stdio server is never
handed to a client as a raw local spawn command: the downloaded config always
points at a per-user proxy URL (`/proxy/mcp/<token>/<server_id>`), served by
`mcprack.service` itself — no separate proxy service to install or enable.

The first time a user's client connects to that URL, mcprack spawns a
dedicated `fastmcp` subprocess for that (user, server) pair on demand,
resolving that user's credentials at that exact moment. Each user gets their
own isolated instance, even for a server several users have selected at once;
idle instances are cleaned up automatically after 15 minutes. This needs
`python3-fastmcp` installed (`apt install python3-fastmcp`) — see Admin →
Proxy instances for a live list of what's running.

See `debian/README.Debian` for more detail.

## Branding & Icons

mcprack includes several icon variants to represent the platform's five functional areas:

| Icon | Purpose | Colors |
|------|---------|--------|
| `mcprack-app-icon.svg` | App launcher / favicon (256×256) | 2×2 grid: Blue (Admin) / Green (Catalog) / Purple (Vault) / Teal+Orange (Registry/Proxy) |
| `mcprack-icon-composite.svg` | Hub diagram with labeled functions | Circular design with 5 surrounding functional rings |
| `mcprack-badge.svg` | Shield badge for documentation | Overlapping colored segments |
| `mcprack-rings.svg` | Concentric design | Rings around central MCP hub |
| `mcprack-functions-bar.svg` | Web header / banner | Horizontal stacked bar showing all 5 functions |

All icons are located in `static/` and are included in the AppStream metadata for app catalog discovery.

**Color scheme:**
- 🔵 Blue = Admin Panel (management & configuration)
- 🟢 Green = User Catalog (server selection)
- 🟣 Purple = Vaultwarden Vault (credential storage)
- 🟠 Orange = Server Registry (inventory)
- 🔷 Teal = HTTP Proxy (remote access)
