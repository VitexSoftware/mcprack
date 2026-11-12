# MCprack Agent Notes

## Architecture (current)

Each selected MCP server has an individual HTTP relay URL shown only on its
server card. Generated client configs use one per-user FastMCP composition URL:
`/proxy/mcp/aggregate/<token>` by default or `/proxy/mcp/aggregate` when
Bearer/OAuth authentication is used. The aggregate exposes only the user's
currently selected, enabled, and permitted servers, namespaced by server name.
Clients never spawn stdio binaries themselves and never receive raw backend
URLs or credentials.

```text
AI client (Claude / Copilot / …)
        │
        ▼
  /proxy/mcp/aggregate/<token>  ← signed user token in path (default)
  /proxy/mcp/aggregate          ← Authorization: Bearer (API token or OAuth)
    │
    ▼
  per-user FastMCP composition process
    │  mounts signed per-server relay URLs under stable namespaces
    ├─ server.command set  → per-user process via user_proxy
    └─ only server.url set → relay to network backend
             (inject auth header from secret_store)
```

With `OAUTH_ENABLED`, mcprack also serves MCP Authorization Spec discovery
(`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`)
plus `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/revoke`
(see `mcprack/oauth.py`), including aggregate resource metadata. Path-token
URLs remain valid either way. Users can request permission for a denied server
from its card; administrator approval changes the ACL but does not subscribe it.

| Env | Default | Role |
|---|---|---|
| `OAUTH_ENABLED` | `false` | Turn on AS + tokenless `/proxy/mcp/aggregate` |
| `PUBLIC_BASE_URL` | empty | Issuer / absolute URLs (required for OAuth metadata + CLI configs) |
| `OAUTH_ACCESS_TOKEN_EXPIRES` | `3600` | Access-token lifetime (seconds) |
| `OAUTH_ALLOW_INSECURE_TRANSPORT` | `false` | Allow http:// authorize/token (lab only) |

Config download (`/download/<client>`, `/view/<client>`) emits one aggregate
`url` (tokenless when OAuth is on). Individual relay URLs are only rendered on
the corresponding server card after permission, enabled state, and selection
checks. The server discovery page lists all registrations, with subscription
controls only for servers the user may use.
`config_formats.py` still has a stdio fallback for unit tests / direct
calls with no url — production catalog paths never exercise it.

### Field meaning on `McpServer`

| Field | Role |
|---|---|
| `transport` | How the *backend* speaks (`stdio` / `http` / `sse`) — informational for admins |
| `command` + `args` | Local binary to spawn (wins over `url` when both are set) |
| `url` | Backend network endpoint to relay to (only used when `command` is empty) |
| `env_config` / secrets | Resolved at request time into the spawn env or auth header |

### Validation (admin form + API)

`admin.validate_server_endpoint()`:

- **Error** (blocks save): neither command nor url; `http`/`sse` without url
- **Warning** (save continues): stdio with both command and url (url ignored);
  http/sse with both (command wins)

Do not paste a shared fastmcp proxy URL onto a stdio+command row — that was
the July 2026 incident (client got `ECONNREFUSED` on a dead `:3100`). Leave
`url` empty for normal stdio servers; mcprack's own proxy is enough.

## Env-var suggestions

`env_detection.detect_env_vars()` produces *suggestions* only (name, secret/
required guess, optional description, `source`). They are stored on
`McpServer.detected_env_vars` and shown as empty rows on the edit form with
a “suggested from …” hint. Only registry/manifest tiers may mark
`required=True`. Never auto-saved until an admin submits the form.

## Debian Suggests

`debian/control` `Suggests:` must list packages that actually resolve on
`repo.vitexsoftware.com` (check with `apt-cache policy`). Prefer real
package names over aspirational renames; update README “MCP server projects”
in the same change.
