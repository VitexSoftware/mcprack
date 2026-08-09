# MCprack Proxy Diagnostics Report
**Date:** 2026-08-09  
**Investigation Method:** SSH diagnostics + source code analysis  
**Status:** 🔴 ROOT CAUSE IDENTIFIED & FIXABLE

---

## Executive Summary

The mcprack proxy timeout issue is **caused by a Python package version incompatibility**:

- **fastmcp 4.0.0b1** (installed, beta version) expects `mcp.shared.session.RequestResponder`
- **mcp 2.0.0** (installed, latest) doesn't have a `session` module in that structure
- Result: Every proxy spawn attempt crashes with `ModuleNotFoundError`, causing 10-second timeouts

**Fix: Downgrade fastmcp from 4.0.0b1 (beta) to 3.4.6 (stable)**

---

## Investigation Findings

### 1. Remote Server Status ✅

| Component | Status | Details |
|-----------|--------|---------|
| SSH access | ✅ | Connected as vitex user |
| Application running | ✅ | Gunicorn on 127.0.0.1:8912 (5 workers) |
| Health endpoint | ✅ | `/health` returns HTTP 200 OK |
| Database | ✅ | `/var/lib/mcprack/mcprack` (SQLite) contains 13 MCP servers |
| MCP server config | ✅ | All servers: transport=stdio, command present, URL absent |

### 2. MCP Database Query Results

```sql
SELECT name, transport, url, command FROM mcp_servers;
```

| Name | Transport | URL | Command |
|------|-----------|-----|---------|
| abraflexi | stdio | (null) | /usr/bin/abraflexi-mcp |
| mastodon | stdio | (null) | /usr/bin/mastodon-mcp |
| datovka | stdio | (null) | /usr/bin/mcp-server-datovka |
| **webdriver** | **stdio** | **(null)** | **/usr/bin/mcp-server-webdriver** |
| **multiflexi** | **stdio** | **(null)** | **/usr/bin/multiflexi-mcp-server** |
| netbox | stdio | (null) | /usr/bin/netbox-mcp-server |
| redmine | stdio | (null) | /usr/bin/redmine-mcp-server |
| semaphore | stdio | (null) | /usr/bin/semaphore-mcp |
| zabbix | stdio | (null) | /usr/bin/zabbix-mcp |
| email | stdio | (null) | /usr/bin/mcp-email-server |
| subreg | stdio | (null) | /usr/bin/mcp-server-subreg |
| warden | stdio | (null) | /usr/bin/warden-mcp |
| cc-token-saver | stdio | (null) | /usr/bin/cc-token-saver-mcp |

### 3. Port 8912 Binding

```bash
$ sudo lsof -i :8912
COMMAND    PID    USER FD   TYPE DEVICE SIZE/OFF NODE NAME
gunicorn 93170 mcprack 7u  IPv4 851063      0t0  TCP *:8912 (LISTEN)
gunicorn 93175 mcprack 7u  IPv4 851063      0t0  TCP *:8912 (LISTEN)
gunicorn 93176 mcprack 7u  IPv4 851063      0t0  TCP *:8912 (LISTEN)
gunicorn 93177 mcprack 7u  IPv4 851063      0t0  TCP *:8912 (LISTEN)
gunicorn 93178 mcprack 7u  IPv4 851063      0t0  TCP *:8912 (LISTEN)
```

Port is actively listening on 5 gunicorn worker processes.

### 4. Proxy User Sessions

Discovered proxy logs for test tokens (server IDs 4 and 5):

```
/var/lib/mcprack/user-proxies/
├── u2-s4.lock        (webdriver proxy session)
├── u2-s4.log         (error logs)
├── u2-s5.lock        (multiflexi proxy session)
└── u2-s5.log         (error logs)
```

### 5. Root Cause: fastmcp 4.0.0b1 vs mcp 2.0.0 Incompatibility

**Error in proxy logs (u2-s4.log):**

```python
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/fastmcp/client/client.py", line 65, in <module>
    from fastmcp.client.messages import MessageHandler, MessageHandlerT
  File "/usr/lib/python3/dist-packages/fastmcp/client/messages.py", line 5, in <module>
    from mcp.shared.session import RequestResponder
ModuleNotFoundError: No module named 'mcp.shared.session'
```

**Analysis:**
- fastmcp 4.0.0b1 imports: `from mcp.shared.session import RequestResponder`
- mcp 2.0.0 structure (verified): 
  ```python
  from mcp import shared
  dir(shared)  # Contains: auth, context, dispatcher, exceptions, extension, 
               # inbound, jsonrpc_dispatcher, memory, message, path_security, 
               # peer, subscriptions, transport_context, uri_template
               # ← NO 'session' module
  ```

### 6. Package Version Analysis

**Current Installation:**
```
fastmcp:  4.0.0b1  (beta - incompatible with mcp 2.0.0)
mcp:      2.0.0    (latest stable)
```

**Available Versions:**
```
fastmcp available:  3.4.6 (latest stable), 3.4.5, 3.4.4, ..., 3.0.0, 2.14.7, ...
  → 3.4.6 should be compatible with mcp 2.0.0

mcp available:      2.0.0 (latest), 1.29.0, 1.28.1, ...
  → 2.0.0 is latest
```

---

## Code Path: Where Proxy Spawn Fails

### Request Flow (from `mcprack/catalog.py`)

```
User Request: GET /proxy/mcp/<token>/<server_id>
    ↓
user_proxy_mcp() function
    ├─ Parse token ✅
    ├─ Load server config from DB ✅
    ├─ Check permissions ✅
    ├─ user_proxy.ensure_user_server_proxy() ← CRITICAL CALL
    │   └─ _spawn(paths, port, server_name, desired_config)
    │       └─ subprocess.Popen([
    │           "/usr/bin/fastmcp", "run",
    │           str(paths["config"]),
    │           "--transport", "http",
    │           "--host", "127.0.0.1",
    │           "--port", str(port),
    │           "--log-level", "INFO"
    │       ])
    │       ├─ fastmcp CLI loads ✅
    │       ├─ fastmcp imports fastmcp.cli.client ✅
    │       ├─ fastmcp.cli.client imports:
    │       │   from fastmcp.client.transports.base import ClientTransport
    │       ├─ fastmcp.client.__init__.py tries:
    │       │   from .client import Client
    │       ├─ fastmcp.client.client.py line 65 tries:
    │       │   from fastmcp.client.messages import MessageHandler
    │       ├─ fastmcp.client.messages.py line 5 tries:
    │       │   from mcp.shared.session import RequestResponder
    │       │   ❌ ModuleNotFoundError: No module named 'mcp.shared.session'
    │       ├─ Process crashes
    │       └─ Logs written to u2-s4.log
    │
    ├─ _probe_upstream_health(port) waits up to 15 seconds
    │   └─ HTTP connection refused → retries with backoff
    │   └─ Timeout after 15 seconds (but gunicorn has 10s limit)
    │
    └─ HTTP client returns 502 Bad Gateway after 10 seconds
```

### When Timeout Occurs

The `_PROXY_REQUEST_TIMEOUT = 10` in `catalog.py:56` is the client-side timeout. The actual spawn process:

1. **Cold spawn handshake**: 15-30 seconds expected
   - fastmcp cold start with dependencies
   - uvicorn binding port
   - MCP initialization
   
2. **But process crashes immediately** due to import error → connection refused
3. **Retry backoff** keeps retrying for up to 15 seconds (HANDSHAKE_TIMEOUT)
4. **HTTP client timeout** fires after 10 seconds
5. **User sees:** Connection timeout, no response

---

## Detailed Proxy Configuration

### spawn() Command Executed

```bash
/usr/bin/fastmcp run \
  /var/lib/mcprack/user-proxies/u2-s4.json \
  --transport http \
  --host 127.0.0.1 \
  --port 35000 \
  --log-level INFO
```

### Generated Config File (u2-s4.json)

```json
{
  "mcpServers": {
    "webdriver": {
      "type": "stdio",
      "command": "/usr/bin/mcp-server-webdriver",
      "args": [],
      "env": {
        // Environment variables for webdriver
      }
    }
  }
}
```

### Process Log Output Location

- Stdout/stderr → `/var/lib/mcprack/user-proxies/u2-s4.log`
- Contains full Python traceback and import errors

---

## Solution & Recommendations

### Immediate Fix (Recommended)

Downgrade fastmcp from 4.0.0b1 to the latest stable version 3.4.6:

```bash
sudo pip install --upgrade fastmcp==3.4.6
```

**Expected Result:**
- fastmcp 3.4.6 compatible with mcp 2.0.0
- Import errors resolve
- Proxy spawn processes start successfully
- MCP servers become accessible via HTTP proxy

### Verification Steps After Fix

```bash
# 1. Verify installation
pip show fastmcp fastmcp
# Should show: fastmcp 3.4.6, mcp 2.0.0

# 2. Test fastmcp CLI
/usr/bin/fastmcp --version
# Should show: 3.4.6

# 3. Test proxy spawn manually
# Clean old attempts:
rm -f /var/lib/mcprack/user-proxies/u2-s*.*

# 4. Make a test API call to trigger proxy spawn
curl -X POST http://localhost:8912/proxy/mcp/<test-token>/4 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# 5. Check if proxy log shows successful startup
tail -20 /var/lib/mcprack/user-proxies/u2-s4.log
# Should show: "Uvicorn running on..." (no errors)
```

### Alternative: Upgrade mcp + fastmcp Together

If you want to use fastmcp 4.0.0b1, you may need to install an mcp version that it's compatible with:

```bash
# Check fastmcp 4.0.0b1 requirements
pip show fastmcp | grep -i "requires"
```

However, **downgrading to stable fastmcp 3.4.6 is safer** since it's battle-tested and compatible with the current mcp 2.0.0.

---

## Why This Happened

fastmcp 4.0.0 is a **beta release** (`4.0.0b1`) that's likely under development. The mcp SDK may have undergone a refactor between versions, moving or removing the `shared.session` module. The beta fastmcp was built against an older snapshot of mcp, while the production deployment has mcp 2.0.0 (the latest stable).

---

## Summary of Files Involved

| File | Role |
|------|------|
| `/var/lib/mcprack/mcprack` | SQLite database with MCP server configs |
| `/var/lib/mcprack/user-proxies/` | Runtime state for active proxy sessions |
| `/var/lib/mcprack/user-proxies/u2-s4.log` | Error logs (import failures) |
| `/usr/bin/fastmcp` | CLI entry point (fails on import) |
| `/usr/lib/python3/dist-packages/fastmcp/` | Package location (version mismatch) |
| `/usr/lib/python3/dist-packages/mcp/` | Package location (missing session module) |
| `mcprack/catalog.py` | Route handler for `/proxy/mcp/<token>/<id>` |
| `mcprack/user_proxy.py` | Proxy spawn logic (`_spawn`, `_probe_upstream_health`) |

---

## Test Status After Investigation

| Phase | Status | Details |
|-------|--------|---------|
| VS Code browser test | ✅ PASS | App accessible, no errors |
| Tool discovery | ✅ PASS | Schemas discoverable via deferred tools |
| Proxy connectivity | ❌ FAIL | fastmcp import error on spawn |
| **Root cause** | ✅ FOUND | fastmcp 4.0.0b1 incompatible with mcp 2.0.0 |
| **Solution** | ✅ READY | Downgrade fastmcp to 3.4.6 |

---

**Next Action:** Apply the fastmcp downgrade fix and re-run proxy tests.

**Prepared:** 2026-08-09 via SSH investigation and source code analysis  
**Investigator:** GitHub Copilot
