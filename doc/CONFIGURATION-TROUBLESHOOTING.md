# MCprack Configuration Troubleshooting Guide

## Overview

This guide helps diagnose and fix common MCprack configuration issues, particularly those related to SECRET_KEY, environment variables, and service startup failures.

---

## Common Issue: Service Won't Start (HTTP 503)

### Symptom
```bash
$ systemctl status mcprack
× mcprack.service - MCprack MCP Catalog Service
     Loaded: loaded (/usr/lib/mcprack/mcprack.service; enabled; preset: enabled)
     Active: failed (Result: exit-code) since Fri 2026-08-09 18:00:00 UTC
     Process: 12345 ExecStart=/usr/bin/gunicorn ... (code=exited, status=1)
```

**Web Access:**
```
curl https://mcprack.mojavoda.sk/
→ HTTP 503 Service Unavailable
```

**Logs Show:**
```
Refusing to start: SECRET_KEY is unset or still the insecure default
```

### Root Cause
The SECRET_KEY configuration is missing or not properly set in `/etc/mcprack/env`. This key is critical for:
- Signing Flask sessions
- Protecting per-user proxy tokens
- Production security

### Solution (Automated)

**Step 1: Run the initialization script**
```bash
sudo mcprack-init-config
```

This will:
- ✅ Generate a secure SECRET_KEY
- ✅ Store it in `/etc/mcprack/env`
- ✅ Fix file permissions (0640, root:mcprack)
- ✅ Restart the mcprack service automatically

**Step 2: Verify**
```bash
sudo systemctl status mcprack
curl https://mcprack.mojavoda.sk/
```

---

## Manual Configuration (If Automated Script Fails)

### Step 1: Generate a Secure Secret Key
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Output Example:**
```
k1CwS1Olf9gHRvf1g90pg_BpkXTa6TWsFjFtu_R1f4M
```

### Step 2: Add to Configuration File
```bash
# Backup existing config
sudo cp /etc/mcprack/env /etc/mcprack/env.bak

# Add the SECRET_KEY
echo "SECRET_KEY=<paste-the-key-here>" | sudo tee -a /etc/mcprack/env
```

**Example:**
```bash
echo "SECRET_KEY=k1CwS1Olf9gHRvf1g90pg_BpkXTa6TWsFjFtu_R1f4M" | sudo tee -a /etc/mcprack/env
```

### Step 3: Verify Permissions
```bash
ls -la /etc/mcprack/env
# Should show: -rw-r----- 1 root mcprack ... env

# If not, fix it:
sudo chmod 0640 /etc/mcprack/env
sudo chown root:mcprack /etc/mcprack/env
```

### Step 4: Verify mcprack User Can Read
```bash
sudo -u mcprack cat /etc/mcprack/env | grep SECRET_KEY
```

If this fails, go back to Step 3.

### Step 5: Restart Service
```bash
sudo systemctl restart mcprack
sudo systemctl status mcprack

# Check service is running
sudo systemctl is-active mcprack && echo "✅ Running" || echo "❌ Failed"
```

### Step 6: Verify Web Access
```bash
curl -I https://mcprack.mojavoda.sk/
# Should show: HTTP 200 OK (or redirect, not 503)
```

---

## Post-Installation Configuration

When you install MCprack via Debian package on a fresh system:

```bash
sudo apt install mcprack
```

The system will show:
```
ℹ️  mcprack installed with default configuration
🔧 Next steps:
   1. Initialize configuration: sudo mcprack-init-config
   2. Update /etc/mcprack/env with your credentials
   3. Start service: sudo systemctl start mcprack
   4. Check status: sudo systemctl status mcprack
```

**Follow these steps:**

1. **Initialize configuration**
   ```bash
   sudo mcprack-init-config
   ```

2. **Edit configuration if needed**
   ```bash
   sudo nano /etc/mcprack/env
   # Add or update:
   # - VAULTWARDEN_URL=https://...
   # - VAULTWARDEN_ADMIN_TOKEN=...
   # - LDAP settings (if using LDAP auth)
   ```

3. **Start the service**
   ```bash
   sudo systemctl start mcprack
   sudo systemctl enable mcprack
   ```

4. **Verify**
   ```bash
   sudo systemctl status mcprack
   curl https://mcprack.mojavoda.sk/
   ```

---

## Environment File Structure

The `/etc/mcprack/env` file contains KEY=VALUE pairs:

```bash
# Security (Required)
SECRET_KEY=<generated-secret-key>

# Database (Optional, defaults to SQLite)
SQLALCHEMY_DATABASE_URI=sqlite:////var/lib/mcprack/mcprack.db

# Vaultwarden Integration (Optional)
VAULTWARDEN_URL=https://vault.example.com
VAULTWARDEN_ADMIN_TOKEN=<token>

# LDAP Authentication (Optional)
LDAP_SERVER_URI=ldap://ldap.example.com:389
LDAP_BIND_DN=cn=admin,dc=example,dc=com
LDAP_BIND_PASSWORD=password
LDAP_SEARCH_BASE=ou=users,dc=example,dc=com

# MCP Servers Configuration (Optional)
MCPRACK_MCP_SERVERS_PATH=/var/lib/mcprack/servers.json
```

---

## Regenerating SECRET_KEY (Emergency Recovery)

If you suspect the SECRET_KEY has been compromised:

```bash
# 1. Generate a new key
sudo mcprack-init-config --force

# 2. Or manually:
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
sudo sed -i "/^SECRET_KEY=/d" /etc/mcprack/env
echo "SECRET_KEY=$NEW_KEY" | sudo tee -a /etc/mcprack/env

# 3. Restart service
sudo systemctl restart mcprack
```

**⚠️ Warning:** Changing SECRET_KEY will invalidate all existing sessions. Users will need to log in again.

---

## Debugging Hints

### Check Service Status
```bash
sudo systemctl status mcprack -l --no-pager
```

### View Recent Logs
```bash
sudo journalctl -u mcprack -n 50
```

### Follow Logs in Real-Time
```bash
sudo journalctl -u mcprack -f
```

### Test Configuration Loading
```bash
sudo su - mcprack -s /bin/sh
cd /usr/lib/mcprack
set -a; source /etc/mcprack/env; set +a
python3 -c "import os; print('SECRET_KEY:', bool(os.environ.get('SECRET_KEY')))"
```

### Verify Flask Application
```bash
sudo FLASK_APP=mcprack.app:create_app python3 -m flask --help
```

---

## Permissions Checklist

| File/Directory | Owner | Perms | Purpose |
|---|---|---|---|
| /etc/mcprack/env | root:mcprack | 0640 | Configuration secrets |
| /var/lib/mcprack/ | mcprack:mcprack | 0755 | Data directory |
| /var/lib/mcprack/mcprack.db | mcprack:mcprack | 0600 | SQLite database |
| /usr/bin/mcprack-init-config | root:root | 0755 | Initialization script |
| /usr/lib/mcprack/ | root:root | 0755 | Application files |

### Fix Permissions
```bash
sudo chown root:mcprack /etc/mcprack/env && sudo chmod 0640 /etc/mcprack/env
sudo chown -R mcprack:mcprack /var/lib/mcprack
sudo chmod -R 0755 /var/lib/mcprack
sudo chmod 0600 /var/lib/mcprack/mcprack.db 2>/dev/null || true
```

---

## Common Error Messages

### "SECRET_KEY is unset or still the insecure default"
→ Run: `sudo mcprack-init-config`

### "mcprack user cannot read config file"
→ Run: `sudo chmod 0640 /etc/mcprack/env && sudo chown root:mcprack /etc/mcprack/env`

### "Database migration failed"
→ Check `/etc/mcprack/env` has SQLALCHEMY_DATABASE_URI (or let it use default SQLite)
→ Run: `sudo su - mcprack -s /bin/sh -c "cd /usr/lib/mcprack && source /etc/mcprack/env && flask db upgrade"`

### "Failed to connect to Vaultwarden"
→ Verify VAULTWARDEN_URL and VAULTWARDEN_ADMIN_TOKEN in `/etc/mcprack/env`
→ Test: `curl -H "Authorization: Bearer <token>" https://vault.example.com/admin/users`

---

## Getting Help

If you're still having issues:

1. **Check the logs:**
   ```bash
   sudo journalctl -u mcprack -n 100
   ```

2. **Verify all files exist:**
   ```bash
   ls -la /etc/mcprack/env
   ls -la /var/lib/mcprack/
   ```

3. **Test configuration manually:**
   ```bash
   sudo su - mcprack -s /bin/sh
   cd /usr/lib/mcprack
   set -a; . /etc/mcprack/env; set +a
   python3 -c "from mcprack.app import create_app; app = create_app(); print('✅ App loaded')"
   ```

4. **Report issue with:**
   - Output of `sudo systemctl status mcprack`
   - Last 20 lines of `sudo journalctl -u mcprack`
   - Output of `sudo mcprack-init-config` (sanitized of secrets)
   - Python version: `python3 --version`
   - Debian version: `lsb_release -a`

---

## See Also

- [MCprack README](README.md)
- [Installation Guide](README.md#installation)
- [GitHub Issues](https://github.com/VitexSoftware/mcprack/issues)
