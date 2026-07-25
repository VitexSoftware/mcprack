# MCprack Agent Customization Notes

## MCP Server Configuration Issues

### Problem: stdio servers with HTTP URLs generate invalid network entries

**Date Discovered:** 2026-07-25  
**Severity:** High  
**Status:** ✅ FIXED - Database cleaned, mcp.json now generates correctly

#### Root Cause
In the database (`mcprack_servers` table), certain MCP servers have conflicting configurations:
- `transport` = `"stdio"` (meant to run as local CLI process)
- `url` = `"http://10.11.182.99:3100/mcp/"` (HTTP endpoint)

#### Affected Servers
1. **webdriver** 
   - Name: `webdriver`
   - Transport: `stdio`
   - Command: `mcp-server-webdriver`
   - URL (should be NULL): `http://10.11.182.99:3100/mcp/`

2. **mastodon**
   - Name: `mastodon`
   - Transport: `stdio`
   - Command: `/usr/bin/mastodon-mcp`
   - URL (should be NULL): `http://10.11.182.99:3100/mcp/`

#### How This Breaks mcp.json Generation
In `config_formats.py` (lines 67-73), the logic is:
```python
def _render(servers, include_stdio_type):
    result = {}
    for server in servers:
        if server.get("url"):
            result[server["name"]] = _network_entry(server)  # ← Always uses network if URL exists
        else:
            result[server["name"]] = _stdio_entry(server, include_stdio_type)
    return result
```

**The issue:** If `url` is present, it *always* generates a network entry (HTTP), regardless of `transport` value. This causes:
- webdriver → `{"type": "http", "url": "http://10.11.182.99:3100/mcp/"}`
- mastodon → `{"type": "http", "url": "http://10.11.182.99:3100/mcp/"}`

Both point to a non-existent endpoint (port 3100 is not listening) → VS Code Copilot gets ECONNREFUSED

#### Evidence
**Database query** on `instance/mcprack-test.db`:
```sql
SELECT name, transport, url, command FROM mcp_servers WHERE name IN ('webdriver', 'mastodon');
```
Results:
```
mastodon|stdio|http://10.11.182.99:3100/mcp/|/usr/bin/mastodon-mcp
webdriver|stdio|http://10.11.182.99:3100/mcp/|mcp-server-webdriver
```

**VS Code Copilot logs** (`~/.vscode-server/...` debug logs):
```
2026-07-25 03:41:00.429 [info] Connection state: Error Error sending message to http://10.11.182.99:3100/mcp/: TypeError: fetch failed: connect ECONNREFUSED 10.11.182.99:3100
```

#### Fix Required
1. **Option A (Recommended):** Remove URL from both servers in the database
   ```sql
   UPDATE mcp_servers SET url = NULL WHERE name IN ('webdriver', 'mastodon');
   ```
   This makes them true stdio entries, spawned locally by the client.

2. **Option B:** If these servers should be network-exposed via a proxy (like fastmcp), configure them with the correct proxy port and ensure the proxy is actually running.

#### Code Design Note
The current logic in `config_formats.py` assumes:
- `url` present → network server (http/sse)
- `url` absent → stdio server (local command spawn)

This is correct design; the bug is in data entry (database has contradictory values). Consider adding validation in the admin form to warn when setting a `url` on a `stdio` transport.

#### Implementation Checklist
- [x] Clean database: Remove URL from webdriver and mastodon servers
  ```sql
  UPDATE mcp_servers SET url = NULL WHERE name IN ('webdriver', 'mastodon');
  ```
- [x] Verify mcp.json generation: Now correctly renders stdio entries
  ```json
  {
    "servers": {
      "webdriver": {"command": "mcp-server-webdriver", "args": []},
      "mastodon": {"command": "/usr/bin/mastodon-mcp", "args": [], "env": {...}}
    }
  }
  ```
- [x] Verified VS Code Copilot will now spawn these as local processes
- [x] Generate fastmcp proxy config (`/var/lib/mcprack/proxy-mcp.json`)
- [x] Start fastmcp service on port 3100 exposing all stdio servers
- [x] Auto-detect remote clients and serve HTTP config instead of stdio
  - When user connects from different IP → HTTP entries pointing to fastmcp proxy
  - When user connects from localhost → stdio entries for direct spawn
- [ ] (Optional) Add database constraints or form validation to prevent this issue in the future

#### Solution Implementation

**For Local Clients (127.0.0.1):**
```json
{
  "servers": {
    "mastodon": {"command": "/usr/bin/mastodon-mcp", "args": []},
    "webdriver": {"command": "mcp-server-webdriver", "args": []}
  }
}
```
→ VS Code spawns binaries directly on the user's machine

**For Remote Clients (192.168.2.x behind NAT):**
```json
{
  "servers": {
    "mastodon": {"type": "http", "url": "http://10.11.182.99:3100/mcp/"},
    "webdriver": {"type": "http", "url": "http://10.11.182.99:3100/mcp/"}
  }
}
```
→ VS Code connects over HTTP to fastmcp proxy, which spawns binaries locally

#### Code Changes

1. **config_formats.py**: Added `proxy_host` and `proxy_port` parameters to render functions
   - Stdio servers become HTTP when `proxy_host` is provided
   - Allows same database entry to serve different configs based on client location

2. **catalog.py**: Auto-detect remote requests in `_build_client_config_json()`
   - Compares `request.remote_addr` against localhost and server IPs
   - Passes proxy_host to render functions for remote clients
   - Local clients get proxy_host=None (stdio entries)
   - Remote clients get proxy_host="10.11.182.99" (HTTP entries)

3. **bin/mcprack-generate-proxy-config**: Already existed, generates proxy-mcp.json
   - Queries database for all stdio servers (url IS NULL)
   - Outputs Claude-style config for fastmcp to proxy

#### System Architecture

```
LOCAL CLIENT (VS Code on 10.11.182.99)
  ↓
  /view/copilot (request.remote_addr = 127.0.0.1 or 10.11.182.99)
  ↓
  proxy_host = None
  ↓
  render_copilot_config(servers, proxy_host=None)
  ↓
  {"servers": {"mastodon": {"command": "/usr/bin/mastodon-mcp"}, ...}}
  ↓
  VS Code spawns /usr/bin/mastodon-mcp locally

---

REMOTE CLIENT (VS Code on 192.168.2.20 via NAT)
  ↓
  /view/copilot (request.remote_addr = 10.11.104.47 [router NAT])
  ↓
  proxy_host = "10.11.182.99"
  ↓
  render_copilot_config(servers, proxy_host="10.11.182.99")
  ↓
  {"servers": {"mastodon": {"type": "http", "url": "http://10.11.182.99:3100/mcp/"}, ...}}
  ↓
  VS Code connects to fastmcp proxy
  ↓
  fastmcp spawns /usr/bin/mastodon-mcp locally on 10.11.182.99
  ↓
  fastmcp exposes it over HTTP on port 3100
```
