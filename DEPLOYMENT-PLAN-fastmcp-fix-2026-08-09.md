# python3-fastmcp Fix Deployment Plan
**Created:** 2026-08-09  
**Status:** Ready for execution after API rate limit reset (2026-08-10 01:00 CET)

---

## Overview

The mcprack proxy system was unable to start webdriver and multiflexi MCP servers due to a Python package incompatibility:

- **Problem:** `python3-fastmcp 4.0.0~a2-1.2.21~trixie` (installed) imports `mcp.shared.session` which doesn't exist in `python3-mcp 2.0.0` (installed)
- **Impact:** 100% of stdio→HTTP MCP proxy attempts fail with immediate import error
- **Solution:** Rebuild python3-fastmcp package from fixed upstream code (commit 8b76710e includes mcp 2.0.0 migration)
- **Status:** Source fixed and committed, awaiting Jenkins build & deployment

---

## Phase 1: Trigger Package Build
**Timeline:** After 2026-08-10 01:00 CET (API limit reset)

### Trigger Jenkins Job

**Method 1: Web UI**
```
1. Navigate to: https://jenkins.vitexsoftware.com
2. Job: Foregin/fastmcp
3. Click "Build Now"
4. Monitor build #22 (expected)
```

**Method 2: Jenkins CLI** (if available)
```bash
# After API reset
curl -X POST https://jenkins.vitexsoftware.com/job/Foregin/fastmcp/build \
  -u vitex:$JENKINS_TOKEN
```

### Expected Build Result

| Metric | Expected Value |
|--------|-----------------|
| Job Name | Foregin/fastmcp |
| Build Number | #22 (or next sequential) |
| SCM Source | Vitexus/python3-fastmcp#e1fec7b8 (main branch) |
| Package Version | python3-fastmcp 4.0.0~b1-1 |
| Build Duration | ~5-10 minutes |
| Build Status | SUCCESS ✅ |
| Published Artifact | repo.vitexsoftware.com/pool/main/p/python3-fastmcp/python3-fastmcp_4.0.0~b1-1_all.deb |

### Verification During Build

Monitor Jenkins console for:
```
dpkg-buildpackage -us -uc ...
[✓] build-depends satisfied
[✓] pre-build checks
[✓] python3 setup.py sdist_wheel
[✓] Source and binary packages built successfully
[✓] Package published to repo.vitexsoftware.com
```

---

## Phase 2: Deploy to Production Server
**Timeline:** Immediately after successful build

### Prerequisites

- SSH access to vyvojar.spoje.net (vitex user with sudo)
- Current package installed: `python3-fastmcp 4.0.0~a2-1.2.21~trixie`
- Target package: `python3-fastmcp 4.0.0~b1-1`

### Deployment Steps

**Step 1: Verify package is published**
```bash
ssh vyvojar.spoje.net "apt-cache policy python3-fastmcp"
# Should show: Candidate: 4.0.0~b1-1 (or newer)
```

**Step 2: Update package repository index**
```bash
ssh vyvojar.spoje.net "sudo apt update"
# Should show: Get:X ... repo.vitexsoftware.com ... python3-fastmcp
```

**Step 3: Upgrade package**
```bash
ssh vyvojar.spoje.net "sudo apt install --only-upgrade python3-fastmcp"
# Confirms: python3-fastmcp will be upgraded from 4.0.0~a2-1.2.21~trixie to 4.0.0~b1-1
# Accepts upgrade
```

**Step 4: Verify installation**
```bash
ssh vyvojar.spoje.net "sudo /usr/bin/fastmcp --version"
# Expected: 4.0.0b1 (no ImportError)
```

**Step 5: Confirm no import errors**
```bash
ssh vyvojar.spoje.net "sudo python3 -c 'import fastmcp; print(fastmcp.__version__)'"
# Expected: 4.0.0b1 (no errors)
```

### Installation Commands (Combined)

```bash
#!/bin/bash
set -e

echo "=== Step 1: Update repository index ==="
ssh vyvojar.spoje.net "sudo apt update"

echo "=== Step 2: Upgrade python3-fastmcp ==="
ssh vyvojar.spoje.net "sudo apt install --only-upgrade python3-fastmcp"

echo "=== Step 3: Verify fastmcp CLI ==="
ssh vyvojar.spoje.net "sudo /usr/bin/fastmcp --version"

echo "=== Step 4: Verify Python import ==="
ssh vyvojar.spoje.net "sudo python3 -c 'import fastmcp; print(fastmcp.__version__)'"

echo "=== Deployment successful ==="
```

---

## Phase 3: Verify Fix on Production
**Timeline:** 5-10 minutes after successful upgrade

### Pre-Test Cleanup

Clear old proxy session files (failed spawns):
```bash
ssh vyvojar.spoje.net "sudo rm -f /var/lib/mcprack/user-proxies/u2-s*.log /var/lib/mcprack/user-proxies/u2-s*.json /var/lib/mcprack/user-proxies/u2-s*.meta.json"
```

### Test 1: Manual fastmcp Run

**Test webdriver proxy spawn:**
```bash
ssh vyvojar.spoje.net "cat > /tmp/webdriver-test.json << 'EOF'
{
  \"mcpServers\": {
    \"webdriver\": {
      \"type\": \"stdio\",
      \"command\": \"/usr/bin/mcp-server-webdriver\",
      \"args\": [],
      \"env\": {}
    }
  }
}
EOF
"

# Attempt to run fastmcp with this config (timeout after 3 seconds)
ssh vyvojar.spoje.net "timeout 3 sudo /usr/bin/fastmcp run /tmp/webdriver-test.json --transport http --host 127.0.0.1 --port 35555" || echo "Process timed out (expected - background HTTP server started)"

# Verify port is bound
ssh vyvojar.spoje.net "sudo netstat -tuln | grep 35555"
# Expected: tcp 0 0 127.0.0.1:35555 0.0.0.0:* LISTEN

# Kill the background process if still running
ssh vyvojar.spoje.net "sudo pkill -f 'fastmcp run /tmp/webdriver-test.json'" || true
```

### Test 2: Via mcprack Proxy Endpoint

**Generate test token** (requires mcprack admin or CLI):
```bash
# Option A: Generate signed token manually
# (Requires SECRET_KEY from mcprack config)

# Option B: Use existing test tokens from AGENTS.md
# webdriver token: eyJ1IjoyLCJzIjo0fQ.anhXeA.1azYkU0StIhRCOnm8ZdLgl69l40
# multiflexi token: eyJ1IjoyLCJzIjo1fQ.anhXeA.CQFZw3rrX_NC3gbwZkF0jt9WzN0
```

**Test webdriver proxy via mcprack:**
```bash
curl -X POST "http://vyvojar.spoje.net:8912/proxy/mcp/eyJ1IjoyLCJzIjo0fQ.anhXeA.1azYkU0StIhRCOnm8ZdLgl69l40/4" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2024-11-05",
      "capabilities":{},
      "clientInfo":{"name":"test","version":"1.0"}
    }
  }'
```

**Expected Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {}
    },
    "serverInfo": {
      "name": "webdriver",
      "version": "..."
    }
  }
}
```

**Test multiflexi proxy:**
```bash
curl -X POST "http://vyvojar.spoje.net:8912/proxy/mcp/eyJ1IjoyLCJzIjo1fQ.anhXeA.CQFZw3rrX_NC3gbwZkF0jt9WzN0/5" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2024-11-05",
      "capabilities":{},
      "clientInfo":{"name":"test","version":"1.0"}
    }
  }'
```

**Expected Response:** Same structure, serverInfo.name = "multiflexi"

### Test 3: Check Proxy Logs

```bash
# Verify successful handshake (no import errors)
ssh vyvojar.spoje.net "tail -20 /var/lib/mcprack/user-proxies/u2-s4.log"
# Expected: "Uvicorn running on http://127.0.0.1:..." (no Python errors)

ssh vyvojar.spoje.net "tail -20 /var/lib/mcprack/user-proxies/u2-s5.log"
# Expected: "Uvicorn running on http://127.0.0.1:..." (no Python errors)
```

### Test 4: Smoke Test from Client

Once proxy is working, reproduce the original smoke test:

```python
# Use tool_search to discover webdriver and multiflexi tools
tool_search("webdriver browser automation")
tool_search("multiflexi abraflexi contact")

# Both should return tool schemas (not timeouts)
```

---

## Rollback Plan (If Needed)

If the upgrade causes unexpected issues:

```bash
ssh vyvojar.spoje.net "sudo apt install python3-fastmcp=4.0.0~a2-1.2.21~trixie"
```

However, this rolls back to the broken state. A better rollback would be to:
1. Downgrade to python3-mcp 1.x (if available)
2. Or wait for a newer python3-fastmcp that fully supports mcp 2.0.0

---

## Success Criteria

| Criterion | Verification Method | Pass ✅ | Fail ❌ |
|-----------|-------------------|--------|--------|
| Package built | Jenkins job #22 status | SUCCESS | FAILURE |
| Package published | `apt-cache search fastmcp \| grep 4.0.0~b1-1` | Returns entry | No entry |
| Installation successful | `python3-fastmcp --version` returns 4.0.0b1 | Yes | Error or old version |
| No import errors | `python3 -c 'import fastmcp'` | No error | ImportError |
| Proxy spawn works | `/usr/bin/fastmcp run` starts HTTP server | Port bound | Process exits |
| webdriver proxy responds | HTTP POST to /proxy/mcp/.../4 | JSON response (initialize result) | Timeout or error |
| multiflexi proxy responds | HTTP POST to /proxy/mcp/.../5 | JSON response (initialize result) | Timeout or error |

---

## Timeline & Execution Order

```
2026-08-10 01:00 CET  ← API rate limit resets
2026-08-10 01:05      → Trigger Jenkins job Foregin/fastmcp
2026-08-10 01:15      → Build completes, package published
2026-08-10 01:20      → Deploy to production (apt upgrade)
2026-08-10 01:25      → Run verification tests
2026-08-10 01:35      → Full smoke test (optional, comprehensive)
```

---

## Communication & Documentation

### After Successful Deployment

1. **Update deployment log:**
   ```bash
   echo "2026-08-10 01:XX: python3-fastmcp upgraded from 4.0.0~a2 to 4.0.0~b1-1; mcprack proxy now functional" \
     >> /var/log/mcprack/deployment.log
   ```

2. **Close related issues:**
   - GitHub: Vitexus/python3-fastmcp (if any)
   - Jira/internal: MCP proxy timeout issue

3. **Update AGENTS.md or project README:**
   - Note: fastmcp 4.0.0~b1-1 (or newer) required for mcprack proxy functionality

---

## Contact & Support

If issues arise during any phase:

1. **Build failure** → Check Jenkins console for dpkg-buildpackage errors
2. **Deployment failure** → Check apt logs: `ssh vyvojar.spoje.net "sudo apt install python3-fastmcp -y"` (verbose)
3. **Proxy still timing out** → Check /var/lib/mcprack/user-proxies/*.log for new import errors
4. **Partial functionality** → Verify all transitive dependencies: `python3-mcp`, `uvicorn`, `starlette`

---

**Document prepared by:** GitHub Copilot  
**Last updated:** 2026-08-09 18:45 CET  
**Status:** Ready for execution
