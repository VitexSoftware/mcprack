# mcprack — improvement backlog

Prioritized suggestions (not committed roadmap). Highest leverage first.

## Security / auth

1. **Default to OAuth (or strongly recommend it) for public installs** — path tokens still can’t be revoked; OAuth + `proxy:access` ApiTokens close that gap.
2. **Short-lived path tokens by default on internet-facing deploys** — or refuse to mint path tokens when OAuth is on (admin toggle). (`?next=` on login is already fixed for the OAuth authorize flow.)
3. **Web-UI OIDC/SSO** — README still calls this out; LDAP alone isn’t enough for many orgs.
4. ~~**`mcprack-mcp-probe --bearer`**~~ — done: `--bearer` reads `MCPRACK_TOKEN`; `mcprack user config verify` probes a whole generated configuration.

## Operator UX

5. **First-run / health dashboard** — one page: OAuth, Vaultwarden, `PUBLIC_BASE_URL`, proxy instances, last probe failures (wizards already exist; unify them).
6. **Clearer “why 401/502” in the catalog** — surface last relay error per selected server for the current user.
7. **Config sync status** — show whether Claude/Cursor/VS Code sync tokens exist and when they last pulled.

## Reliability

8. **Shared rate-limit / secret-cache backend (Redis)** — login throttling is now database-backed (shared by all workers); the other Flask-Limiter budgets, the BW lock and the secret cache are still per-worker.
9. **Warm/pool proxies for heavy servers** — cold spawn (15s+) is a recurring pain.
10. **Per-server relay timeout** — global 10s `_PROXY_REQUEST_TIMEOUT` is wrong for slow tools (IMAP, etc.).

## Product

11. **Per-server OAuth scopes / ACLs** — today `mcp` is all-or-nothing across selected servers.
12. **Client ID Metadata Documents (CIMD)** — MCP is moving past DCR; worth tracking for Claude/Copilot compatibility.
13. **Template-based onboarding wizard for non-technical users** — “pick role → apply template → download/connect” in one flow.
14. **Audit UI filters for proxy/OAuth events** — consent grants, token mint/revoke, failed Bearer attempts.

## Housekeeping

15. **Clarify web login vs MCP proxy auth in docs/UI** — one glossary block in the catalog helps.
16. **Keep architecture SVG in sync** when auth modes change (README path: `mcprack/static/mcprack-architecture.svg`).
17. **Debian Suggests vs real packages** — keep verifying with `apt-cache policy` as the mcp-server rename rolls out.

## Security hardening — still open

From the November 2026 audit (`docs/AUDIT-2026-11.md`, status table in §13). Everything not listed here is done.

### B-09 · Outbound requests to admin-supplied URLs (SSRF) — partly done

The relay connects, from the mcprack host and with the server's credentials, to a URL only an administrator can set — so this matters when an admin account is compromised, not for ordinary users.

*Done:* `endpoint_policy.py` refuses non-http(s) schemes, credentials in the URL, link-local/cloud-metadata, unspecified and multicast destinations (numeric IPv4 spellings such as `2852039166` / `0xa9fea9fe` included), when a server is saved **and** again when the relay connects. Redirects are not followed.

*Open, in the order I would do them:*

- **DNS rebinding.** Host *names* are never resolved by the check, so a name that resolves to a public address today and to `169.254.169.254` at connect time passes. Resolve at connect time in the relay (`catalog._forward_to_backend_url`), apply the same policy to **every** resulting address, and connect to the checked IP (keep the name for `Host`/SNI). The same goes for the capability probes below.
- **Port-scan oracle.** `health.check_http_reachable` opens a TCP connection to every server's `host:port` each time Admin → Servers is rendered (`admin._compute_server_health`). A compromised admin can map the internal network just by registering servers and looking at the page. Cache the result (TTL), take it off the request path or make it on-demand, and run the destination policy first.
- **Capability probes use the wrong transport.** `health.get_server_capabilities` talks plain HTTP to `/mcp` without authentication even for an `https://` URL. Use the server's real scheme, path and auth header, and the same policy (`probe_http_capabilities` already does most of that).
- **Egress filter for the service user.** The nftables per-UID example in `debian/README.Debian` is documentation only; MCP server processes can reach anything. Decide a deployment default — e.g. systemd `IPAddressDeny=` / `IPAddressAllow=` in `debian/mcprack.service` — and document how to open it for internal backends.

### Other open audit items

- **B-17** — run `debsecan` / `apt-cache policy` for the trixie packages on the target (notably `python3-authlib`, `python3-cryptography`); needs the server.
- **B-10** — database-level append-only for the audit table (triggers differ per SQLite/PostgreSQL/MySQL and clash with `audit-archive`) and automatic shipping of the audit mirror off the host (`systemd-journal-upload`). Today: tamper *evidence* via `flask audit-verify`.
- **A-04** — per-server uid/container isolation of MCP processes; the loopback `fastmcp` ports (35000+) are predictable and unauthenticated.
- **MFA** — QR code for enrolment (needs `python3-qrcode`; ask before adding a dependency); Czech translations of the new MFA / re-authentication strings.
- **B-13** — the internal start-up probe still sends `protocolVersion` 2024-11-05 and does not record the negotiated version (`user config verify` does).
- **Docker demo** — the non-root `USER mcprack` / `cap_drop` change is untested; rebuild and run it on the demo host.

## Suggested next cluster

**B-09: DNS-rebinding-safe connect + remove the port-scan oracle** — small, self-contained, and it closes the one way round the destination policy that already exists. After that, “OAuth-only configs” (no path tokens): small code, big clarity for the new auth path.
