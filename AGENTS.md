# MCprack Agent Notes

## Architecture (current)

Every selected MCP server is exposed to AI clients as an HTTP relay URL
under `/proxy/mcp/<token>/<server_id>`. Clients never spawn stdio binaries
themselves and never receive raw backend URLs or credentials.

```
AI client (Claude / Copilot / …)
        │
        ▼
  /proxy/mcp/<token>/<id>     ← signed bearer in the path
        │
        ├─ server.command set  → spawn per-user process via user_proxy
        │                         (fastmcp streamable-HTTP on a local port)
        │                         then relay the request
        │
        └─ only server.url set → relay to that network backend
                                 (inject auth header from secret_store)
```

Config download (`/download/<client>`, `/view/<client>`) always fills
`url` with the per-user relay. `config_formats.py` still has a stdio
fallback for unit tests / direct calls with no url — production catalog
paths never exercise it.

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
