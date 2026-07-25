# mcprack

Self-service MCP server catalog and client config generator.

An admin registers each available MCP (Model Context Protocol) server once.
Users log in — with a local account or (optionally) their Active Directory credentials —
tick which servers they need and pick a target client (Claude or GitHub
Copilot), and download a ready-to-use config file for that client.

Credentials are never stored in mcprack's own database. Every secret lives in
Vaultwarden (the same `bw-cli` / Secure Note pattern already used by the
`mcp_rack` Ansible role): the admin sets default credentials/env vars per
server, and a user may optionally override them with their own for their
personal downloads.

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

Every credential (a server's default env vars/tokens, and any personal
overrides a user sets) lives in Vaultwarden, never in mcprack's own
database — mcprack talks to it the same way the `mcp_rack` Ansible role does
(`bw-cli`, Secure Notes named `MCP-<server-name>` / `MCP-<server-name>-user-<username>`,
plain `KEY=value` lines).

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
after editing `/etc/mcprack/env` (no service restart needed — the wizard
always checks live).

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

If users run Claude or Copilot on a different machine than the one hosting
your MCP servers, you need to expose stdio-based servers over HTTP. mcprack
includes support for this via `fastmcp`:

1. **Install python3-fastmcp** (Debian/Ubuntu):
   ```bash
   apt install python3-fastmcp
   ```

2. **In mcprack admin UI**, for each stdio server you want to expose remotely:
   - Keep "Command" field filled (e.g., `/usr/bin/mastodon-mcp`)
   - Add "URL": `http://YOUR-HOST:3100/mcp/`
   - Set auth header/env key if needed

3. **Enable the HTTP proxy service**:
   ```bash
   systemctl enable --now mcprack-proxy.service
   ```

4. When users download configs, they'll get network entries pointing to your
   HTTP proxy instead of local stdio commands.

See `debian/README.Debian` for full details on the proxy setup.
