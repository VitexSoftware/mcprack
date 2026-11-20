# MCprack Agent Notes

## Architecture (current)

Clients never spawn stdio binaries themselves and never receive raw backend
URLs or credentials. Every selected server is reached only through mcprack.

**Default client config** is one per-user FastMCP composition URL:

- `/proxy/mcp/aggregate/<token>` — signed user token in the path
- `/proxy/mcp/aggregate` — `Authorization: Bearer` (API token or OAuth)

Optional `?mode=servers` (also CLI `user config … --per-server`) emits one
relay URL per selected server instead:

- `/proxy/mcp/<token>/<server_id>` or `/proxy/mcp/<server_id>` when OAuth is on

The aggregate exposes only the user's currently **selected**, **enabled**, and
**permitted** servers, namespaced by server name. Individual relay URLs are
also shown on a server card after those same checks.

```text
AI client (Claude / Copilot / …)
        │
        ▼
  /proxy/mcp/aggregate/<token>  ← signed user token in path (default)
  /proxy/mcp/aggregate          ← Authorization: Bearer (API token or OAuth)
  /proxy/mcp/<token>/<id>       ← optional per-server mode / card URL
    │
    ▼
  per-user FastMCP composition (aggregate) or user_proxy (per server)
    ├─ server.command set  → per-user process via user_proxy
    └─ only server.url set → relay to network backend
             (inject auth header from secret_store)
```

Composition backends use `MCPRACK_COMPOSITION_BACKEND_TIMEOUT` (default 10s)
so one hung server cannot stall `tools/list` for the whole aggregate.

With `OAUTH_ENABLED`, mcprack also serves MCP Authorization Spec discovery
(`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`)
plus `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/revoke`
(see `mcprack/oauth.py`), including aggregate resource metadata. Path-token
URLs remain valid either way.

| Env | Default | Role |
|---|---|---|
| `OAUTH_ENABLED` | `false` | Turn on AS + tokenless `/proxy/mcp/aggregate` |
| `PUBLIC_BASE_URL` | empty | Issuer / absolute URLs (required for OAuth metadata + CLI configs) |
| `OAUTH_ACCESS_TOKEN_EXPIRES` | `3600` | Access-token lifetime (seconds) |
| `OAUTH_ALLOW_INSECURE_TRANSPORT` | `false` | Allow http:// authorize/token (lab only) |
| `STRICT_SERVER_PERMISSIONS` | `true` | No `UserServerPermission` rows → no servers (fail-closed) |
| `ALLOWED_COMMAND_DIRS` | empty | Optional allowlist for spawned `command` paths |
| `MCPRACK_COMPOSITION_BACKEND_TIMEOUT` | `10` | Per-backend timeout inside the aggregate (seconds) |

Config download (`/download/<client>`, `/view/<client>`) defaults to one
aggregate `url` (tokenless when OAuth is on). `config_formats.py` still has a
stdio fallback for unit tests / direct calls with no url — production catalog
paths never exercise it.

### Access control

- Non-admins: need an allow row when any ACL rows exist; with
  `STRICT_SERVER_PERMISSIONS` and no rows they see nothing.
- **Admins** may use every **enabled** server without an explicit allow row;
  an explicit **deny** still wins (so a server registered after their ACL was
  written is usable without requesting access).
- Users can request permission for a denied server from its card;
  administrator approval changes the ACL but **does not subscribe** it.

### Field meaning on `McpServer`

| Field | Role |
|---|---|
| `transport` | How the *backend* speaks (`stdio` / `http` / `sse`) — informational for admins |
| `command` + `args` | Local binary to spawn (wins over `url` when both are set) |
| `url` | Backend network endpoint to relay to (only used when `command` is empty) |
| `env_config` / secrets | Resolved at request time into the spawn env or auth header |

### Validation (admin form + API)

`admin.validate_server_endpoint()` also runs `endpoint_policy.url_errors()` and
`command_policy.command_errors()`:

- **Error** (blocks save): neither command nor url; `http`/`sse` without url;
  command in a volatile path (`/tmp`, …); command outside `ALLOWED_COMMAND_DIRS`
  when that allowlist is set; relative paths with `/`
- **Warning** (save continues): stdio with both command and url (url ignored);
  http/sse with both (command wins); stdio with only a url (relay, no spawn)

Do not paste a shared fastmcp proxy URL onto a stdio+command row — that was
the July 2026 incident (client got `ECONNREFUSED` on a dead `:3100`). Leave
`url` empty for normal stdio servers; mcprack's own proxy is enough.

The same command-policy check runs again when a process is started, so a row
written straight into the database cannot bypass it.

## Admin routes and reauth

Sensitive mutating admin/API endpoints require a fresh password (+ MFA code if
enabled) within `ADMIN_REAUTH_SECONDS` — see `mcprack/reauth.py`.
`tests/test_reauth.py` fails if a new mutating admin endpoint is added without
being classified in `SENSITIVE_ENDPOINTS`, `REVIEWED_NOT_SENSITIVE`, or
`CHECKED_IN_THE_VIEW`. Classify every new admin route in the same change.

Demo mode (`mcprack/demo.py`) blocks a separate allowlist of mutating routes;
keep both lists in mind when adding admin features.

## Secrets

`secret_store.py` resolves credentials lazily on first proxy connect (Vaultwarden
when configured, else the local encrypted store — never both for the same value).
Cold-start fan-out is coalesced/cached so parallel client connects do not pile up
as “Vaultwarden is busy” 502s; expired cache may be served briefly on lock timeout.

Never embed secrets in downloaded configs or logs.

## Env-var suggestions

`env_detection.detect_env_vars()` produces *suggestions* only (name, secret/
required guess, optional description, `source`). They are stored on
`McpServer.detected_env_vars` and shown as empty rows on the edit form with
a “suggested from …” hint. Only registry/manifest tiers may mark
`required=True`. Never auto-saved until an admin submits the form.

## MCP server packages / companions

When creating, adapting, upgrading, or packaging an MCP server
(`mcp-server-*`, companion `mcprack-mcp-server-*`), follow
`MCP-SERVER-STANDARDS.md` and `doc/PACKAGING-MCP-SERVERS.md`. Companions
self-register via `mcprack server create` / `delete` in postinst/prerm.

## Debian Suggests

`debian/control` `Suggests:` must list packages that actually resolve on
`repo.vitexsoftware.com` (check with `apt-cache policy`). Prefer real
package names over aspirational renames; update README “MCP server projects”
in the same change.
