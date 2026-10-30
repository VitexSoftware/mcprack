# mcprack — improvement backlog

Prioritized suggestions (not committed roadmap). Highest leverage first.

## Security / auth

1. **Default to OAuth (or strongly recommend it) for public installs** — path tokens still can’t be revoked; OAuth + `proxy:access` ApiTokens close that gap.
2. **Short-lived path tokens by default on internet-facing deploys** — or refuse to mint path tokens when OAuth is on (admin toggle). (`?next=` on login is already fixed for the OAuth authorize flow.)
3. **Web-UI OIDC/SSO** — README still calls this out; LDAP alone isn’t enough for many orgs.
4. **`mcprack-mcp-probe --bearer`** — OAuth URLs can’t be probed today without a path token.

## Operator UX

5. **First-run / health dashboard** — one page: OAuth, Vaultwarden, `PUBLIC_BASE_URL`, proxy instances, last probe failures (wizards already exist; unify them).
6. **Clearer “why 401/502” in the catalog** — surface last relay error per selected server for the current user.
7. **Config sync status** — show whether Claude/Cursor/VS Code sync tokens exist and when they last pulled.

## Reliability

8. **Shared rate-limit / secret-cache backend (Redis)** — multi-worker BW lock and login limits are still per-worker with `memory://`.
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

## Suggested next cluster

**Probe Bearer support + optional “OAuth-only configs” (no path tokens)** — small code, big clarity for the new auth path.
