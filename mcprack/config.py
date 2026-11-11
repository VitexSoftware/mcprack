import os


class Config:
    # Production settings by default
    DEBUG = False
    TESTING = False
    
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")
    # Previous keys, comma separated, still accepted for VERIFYING / DECRYPTING
    # (sessions, proxy URLs, reset links, locally encrypted secrets) while
    # everything new is signed with SECRET_KEY. Lets the key be rotated without
    # logging everybody out, breaking every client configuration and losing the
    # local secret store (docs/AUDIT-2026-11.md B-16). Remove an entry once
    # nothing signed with it is still in circulation.
    SECRET_KEY_FALLBACKS = [k.strip() for k in os.environ.get("SECRET_KEY_FALLBACKS", "").split(",") if k.strip()]

    # --- Babel (I18n) ---
    BABEL_DEFAULT_LOCALE = "en"
    BABEL_DEFAULT_TIMEZONE = "UTC"
    BABEL_TRANSLATION_DIRECTORIES = "translations;/usr/share/locale"

    # --- Session / cookie hardening ---
    # SECURE defaults to true: an internet-facing mcprack must sit behind a
    # TLS-terminating reverse proxy (see wsgi.py's ProxyFix and
    # debian/apache-mcprack.conf) so the browser actually sees an https://
    # origin - otherwise it silently refuses to send the cookie back. A
    # plain-HTTP intranet deployment with no reverse proxy in front must set
    # SESSION_COOKIE_SECURE=false in /etc/mcprack/env.
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() in ("true", "1", "yes")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME_SECONDS", str(8 * 3600)))

    # Minimum length of any newly set password (ASVS V2.1.1: 12).
    PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", "12"))

    # --- CSRF (Flask-WTF) ---
    WTF_CSRF_TIME_LIMIT = None

    # The secret-free relay URL /proxy/mcp/<id> authenticated by Authorization:
    # Bearer (an API token with the proxy:access scope). Always available next
    # to the OAuth server; set false to allow it only when OAUTH_ENABLED.
    PROXY_BEARER_ENABLED = os.environ.get("PROXY_BEARER_ENABLED", "true").lower() in ("true", "1", "yes")
    # API tokens created without an explicit expiry expire after this many days
    # (0 = never). A token is as good as a password.
    API_TOKEN_DEFAULT_EXPIRY_DAYS = int(os.environ.get("API_TOKEN_DEFAULT_EXPIRY_DAYS", "90"))

    # Backend URLs in the link-local range (169.254.0.0/16, fe80::/10: cloud
    # metadata services) are refused when a server is registered; set true only
    # when a real MCP backend lives there. (mcprack/endpoint_policy.py)
    BACKEND_ALLOW_LINK_LOCAL = os.environ.get("BACKEND_ALLOW_LINK_LOCAL", "false").lower() in ("true", "1", "yes")

    # --- Second factor (TOTP) ------------------------------------------------
    # Administrators must have MFA enabled to use the admin pages and the admin
    # REST API in a browser session: an administrator without it is sent to the
    # enrolment page instead. (API tokens are not affected - they are created
    # from an already authenticated session. Ignored in DEMO_MODE.) Set false
    # only on a trusted private network.
    MFA_REQUIRED_FOR_ADMINS = os.environ.get("MFA_REQUIRED_FOR_ADMINS", "true").lower() in ("true", "1", "yes")
    # The name an authenticator app shows next to the account.
    MFA_ISSUER = os.environ.get("MFA_ISSUER", "mcprack")
    # How long a user has between a correct password and the code (seconds).
    MFA_PENDING_SECONDS = int(os.environ.get("MFA_PENDING_SECONDS", "300"))
    MFA_RECOVERY_CODE_COUNT = int(os.environ.get("MFA_RECOVERY_CODE_COUNT", "10"))

    # Where a server's `command` may live (mcprack/command_policy.py). A command in
    # /tmp, /var/tmp, /dev/shm ... or given as a relative path is always refused.
    # ALLOWED_COMMAND_DIRS (comma or colon separated absolute directories) is the
    # strict mode: the command must be inside one, checked when a server is saved
    # AND when its process is started. Unset = off. A sensible production value:
    # /usr/bin,/usr/local/bin,/var/lib/mcprack/installs
    ALLOWED_COMMAND_DIRS = os.environ.get("ALLOWED_COMMAND_DIRS", "")
    COMMAND_ALLOW_VOLATILE_DIRS = os.environ.get("COMMAND_ALLOW_VOLATILE_DIRS", "false").lower() in ("true", "1", "yes")

    # --- Login brute-force protection (database backed, see throttle.py) ---
    LOGIN_THROTTLE_ENABLED = os.environ.get("LOGIN_THROTTLE_ENABLED", "true").lower() in ("true", "1", "yes")
    # per account AND client address: stops guessing from one place without
    # letting a stranger lock the real owner out (who comes from elsewhere)
    LOGIN_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "5"))
    # per account over ALL addresses: backstop against guessing spread over many
    LOGIN_ACCOUNT_MAX_FAILURES = int(os.environ.get("LOGIN_ACCOUNT_MAX_FAILURES", "50"))
    LOGIN_IP_MAX_FAILURES = int(os.environ.get("LOGIN_IP_MAX_FAILURES", "30"))
    LOGIN_FAILURE_WINDOW = int(os.environ.get("LOGIN_FAILURE_WINDOW_SECONDS", "900"))
    LOGIN_LOCK_BASE = int(os.environ.get("LOGIN_LOCK_BASE_SECONDS", "30"))
    LOGIN_LOCK_MAX = int(os.environ.get("LOGIN_LOCK_MAX_SECONDS", "3600"))

    # --- Rate limiting (Flask-Limiter) ---
    # memory:// is per gunicorn worker, so the effective ceiling across the
    # 4 workers configured in debian/mcprack.service is LOGIN_RATE_LIMIT x 4.
    # Point RATELIMIT_STORAGE_URI at a shared redis:// backend for a single
    # global limit across all workers.
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "10 per minute;50 per hour")
    PASSWORD_RESET_RATE_LIMIT = os.environ.get("PASSWORD_RESET_RATE_LIMIT", "5 per minute;20 per hour")  # NOSONAR - rate-limit spec, not a credential
    OAUTH_TOKEN_RATE_LIMIT = os.environ.get("OAUTH_TOKEN_RATE_LIMIT", "30 per minute")
    # Flask-Limiter injects Retry-After / X-RateLimit-* from its own
    # after_request hook, which is also what reaches app.py's custom 429
    # page - without this the rendered page would carry no backoff hint.
    RATELIMIT_HEADERS_ENABLED = True

    # Extra environment variable NAMES a spawned MCP server process may inherit
    # from mcprack's own environment (comma separated), on top of PATH, LANG,
    # LC_*, HOME, proxy and CA-bundle settings. mcprack's secrets (SECRET_KEY,
    # BW_*, LDAP_*, ...) can never be added here. Prefer the server's own
    # configuration (Admin -> Servers) over this.
    MCP_CHILD_ENV_ALLOW = os.environ.get("MCP_CHILD_ENV_ALLOW", "")

    # --- Package installer (docs/AUDIT-2026-11.md B-07) ---
    # Require an exact version / tag / digest for pip, npm and Docker installs.
    INSTALL_REQUIRE_PINNED = os.environ.get("INSTALL_REQUIRE_PINNED", "true").lower() in ("true", "1", "yes")
    # Let pip build source distributions (their setup code runs at install
    # time). Default: wheels only.
    INSTALL_ALLOW_SOURCE_BUILDS = os.environ.get("INSTALL_ALLOW_SOURCE_BUILDS", "false").lower() in ("true", "1", "yes")

    # --- Request body size cap ---
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(2 * 1024 * 1024)))

    # --- Per-user MCP server access control ---
    # Which variable names a user may add to an MCP server beyond those the
    # server declares: "credentials" (default) = credential-looking names such
    # as MY_API_TOKEN only; "any" = free-form names, minus the process-altering
    # denylist in env_policy.py (intranet / trusted-users opt-in).
    OVERRIDE_UNDECLARED_KEYS = os.environ.get("OVERRIDE_UNDECLARED_KEYS", "credentials").strip().lower()

    # True (default, fail-closed): a user with no UserServerPermission rows
    # sees NO server until an admin grants access (Admin -> Users, or apply a
    # template) - docs/AUDIT-2026-11.md A-06. The upgrade migration
    # `materialize_server_permissions` gives every existing user an explicit
    # row per enabled server, so nobody loses what they had. Set false only
    # for a trusted intranet where every user should implicitly see every
    # enabled server (the behaviour before this release).
    STRICT_SERVER_PERMISSIONS = os.environ.get("STRICT_SERVER_PERMISSIONS", "true").lower() in ("true", "1", "yes")

    # Hosts the application answers to (Flask TRUSTED_HOSTS; comma separated,
    # a leading dot allows subdomains). Empty = derived from PUBLIC_BASE_URL
    # (plus localhost for health checks from the reverse proxy host); with
    # neither set, any Host is accepted (development).
    TRUSTED_HOSTS = [h.strip() for h in os.environ.get("TRUSTED_HOSTS", "").split(",") if h.strip()] or None

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SQLALCHEMY_DATABASE_URI", "sqlite:////var/lib/mcprack/mcprack.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Base URL mcprack is actually reachable at (e.g. "https://mcprack.example.com"),
    # used only by `mcprack user config show/download` (see cli.py) to build
    # proxy URLs for stdio-implemented servers when generating a config outside
    # of a real web request — a normal browser download always has a real
    # request to infer this from, a CLI invocation does not. Leave empty if
    # you only ever generate configs for such servers from the web UI.
    PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "")

    LDAP_ENABLED = os.environ.get("LDAP_ENABLED", "false").lower() in ("true", "1", "yes")
    LDAP_SERVER = os.environ.get("LDAP_SERVER", "ldap://10.11.25.3:389")
    LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=spojent,dc=cz")
    LDAP_USER_OU = os.environ.get("LDAP_USER_OU", "ou=Users,dc=spojent,dc=cz")
    LDAP_USER_FILTER = os.environ.get("LDAP_USER_FILTER", "(sAMAccountName=%(user)s)")
    # Optional: DN of a group (matched against the user's memberOf values,
    # case-insensitively) whose members are the only ones allowed to log in
    # through LDAP. Empty = every account the directory authenticates. Without
    # it, any directory account is provisioned an mcprack account on first
    # login (it sees no servers until granted, see STRICT_SERVER_PERMISSIONS).
    LDAP_REQUIRED_GROUP = os.environ.get("LDAP_REQUIRED_GROUP", "")
    # Transport security (docs/AUDIT-2026-11.md B-11). Use ldaps:// in
    # LDAP_SERVER, or keep ldap:// and set LDAP_STARTTLS=true. The directory's
    # certificate is verified (LDAP_CA_FILE = the CA bundle to verify against,
    # default: the system store); LDAP_TLS_VALIDATE=false is for a lab only.
    LDAP_STARTTLS = os.environ.get("LDAP_STARTTLS", "false").lower() in ("true", "1", "yes")
    LDAP_CA_FILE = os.environ.get("LDAP_CA_FILE", "")
    LDAP_TLS_VALIDATE = os.environ.get("LDAP_TLS_VALIDATE", "true").lower() in ("true", "1", "yes")
    LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
    LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")

    BW_SERVER = os.environ.get("BW_SERVER", "")
    BW_CLIENTID = os.environ.get("BW_CLIENTID", "")
    BW_CLIENTSECRET = os.environ.get("BW_CLIENTSECRET", "")
    BW_PASSWORD = os.environ.get("BW_PASSWORD", "")
    BW_ITEM_PREFIX = os.environ.get("BW_ITEM_PREFIX", "MCP-")
    BW_COMMAND_TIMEOUT = float(os.environ.get("BW_COMMAND_TIMEOUT", "12"))
    # A full unlock() -> get_notes() -> lock() cycle chains 4-5 sequential
    # `bw` CLI invocations, and each one carries multi-second startup
    # overhead of its own (measured ~1.9-3.5s per call on se-mcp-rack01, even
    # for calls that do no real work like `config server`) - so a single,
    # completely uncontended cold resolution can legitimately take
    # 9-13 seconds. The old 8s default was shorter than that, so even two
    # servers' resolutions merely overlapping (no misbehavior involved) was
    # enough to make the second one time out waiting for the lock. Must stay
    # comfortably above the slowest real resolution observed, not just above
    # the average.
    BW_LOCK_TIMEOUT = float(os.environ.get("BW_LOCK_TIMEOUT", "20"))
    # How long a resolved secret stays cached in memory (per gunicorn worker)
    # before secret_store re-resolves it from Vaultwarden. Each `bw` CLI
    # invocation is slow (multi-second) and resolve_server_env() is called on
    # every single proxied MCP request, not once per connection - without
    # this cache, two concurrent MCP connections are enough to blow past
    # BW_LOCK_TIMEOUT constantly. Explicit invalidation on secret writes
    # (see secret_store.py) keeps this from masking real edits; the TTL is
    # only a safety net for the multi-worker case.
    BW_ENV_CACHE_TTL = float(os.environ.get("BW_ENV_CACHE_TTL", "60"))
    BITWARDENCLI_APPDATA_DIR = os.environ.get(
        "BITWARDENCLI_APPDATA_DIR", "/opt/mcprack/.bw"
    )
    BW_BIN = os.environ.get("BW_BIN", "/usr/bin/bw")
    FASTMCP_BIN = os.environ.get("FASTMCP_BIN", "")

    # Public demo mode: catalog browsing/selection and everything else still
    # works normally, but registering/editing/deleting MCP servers is
    # blocked, since the "command" an admin sets there is executed as-is
    # (never sandboxed) whenever any user connects to that server -- not
    # something a public demo admin account should be able to change.
    DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() in ("true", "1", "yes")

    # Shown on the login page whenever DEMO_MODE is on and the request has
    # no username/password query string of its own — notably the common
    # case of a bare "/" redirecting to "/login?next=%2F" with nothing to
    # prefill from. An explicit query string (see the demo link below)
    # still takes priority over these.
    DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "demo")
    DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "demo")

    # How many days of audit_log_entries to keep before `flask audit-archive`
    # exports and purges them. The audit log itself is always on — this only
    # controls the retention window, not whether logging happens.
    AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "90"))

    # Every audit event is also written, authenticated with a MAC, outside the
    # database - so changes to the table can be detected (`flask audit-verify`,
    # mcprack/audit_mirror.py). Sinks: standard error (the systemd journal) and a
    # file. AUDIT_LOG_FILE unset = /var/log/mcprack/audit.log when that
    # directory is writable; a path = that file; "off" = no file.
    AUDIT_MIRROR_ENABLED = os.environ.get("AUDIT_MIRROR_ENABLED", "true").lower() in ("true", "1", "yes")
    AUDIT_MIRROR_STDERR = os.environ.get("AUDIT_MIRROR_STDERR", "true").lower() in ("true", "1", "yes")
    AUDIT_LOG_FILE = os.environ.get("AUDIT_LOG_FILE")

    # Monitoring (GET /health/servers, used by the Zabbix template). The
    # endpoint is disabled (404) unless MONITORING_TOKEN is set. Every
    # enabled server is probed as MONITORING_USER_ID (a normal mcprack user
    # whose credentials/overrides apply); results are refreshed in the
    # background at most every MONITORING_CACHE_TTL seconds.
    MONITORING_TOKEN = os.environ.get("MONITORING_TOKEN", "")
    MONITORING_USER_ID = int(os.environ.get("MONITORING_USER_ID", "0") or 0)
    MONITORING_CACHE_TTL = int(os.environ.get("MONITORING_CACHE_TTL", "120"))

    # OpenTelemetry — off by default (no-op, no opentelemetry-* packages
    # required) unless explicitly enabled. See telemetry.py and README
    # "Observability (OpenTelemetry)".
    OTEL_ENABLED = os.environ.get("OTEL_ENABLED", "false").lower() in ("true", "1", "yes")
    OTEL_EXPORTER_OTLP_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    OTEL_SERVICE_NAME = os.environ.get("OTEL_SERVICE_NAME", "mcprack")
    # Only "grpc" and "http/protobuf" are actually supported by the Python
    # OTLP exporter — telemetry.py silently falls back to http/protobuf for
    # anything else (notably "http/json", which the JS SDK has but Python
    # does not) rather than failing startup.
    OTEL_EXPORTER_OTLP_PROTOCOL = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
    OTEL_TRACES_SAMPLER = os.environ.get("OTEL_TRACES_SAMPLER", "parentbased_always_on")
    # URL template for the "View trace" link on the audit log detail page,
    # e.g. Grafana Explore/Tempo: "https://grafana.example/explore?traceID={request_id}"
    OTEL_TRACE_UI_URL_TEMPLATE = os.environ.get("OTEL_TRACE_UI_URL_TEMPLATE", "")

    # --- Outbound mail (forgot-password reset links only) ---
    # SMTP_HOST empty (default) means "not configured" — the forgot-password
    # page then explains that a real password reset must be requested from
    # an admin instead of pretending to send an email nothing delivers.
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")
    SMTP_FROM = os.environ.get("SMTP_FROM", "mcprack <noreply@localhost>")
    # How long a password-reset link stays valid.
    PASSWORD_RESET_MAX_AGE = int(os.environ.get("PASSWORD_RESET_MAX_AGE_SECONDS", str(3600)))

    # How long a user's per-server MCP proxy URL (see catalog.py's
    # _make_proxy_token/_parse_proxy_token, used by `mcprack user config
    # show/download` and the "Config" download button) stays valid before
    # the proxy starts rejecting it with 403. Empty (default) means the
    # token never expires on its own - only regenerating a user's config
    # (which mints a fresh token) or rotating SECRET_KEY invalidates it.
    # Set to a positive integer to re-enable time-limited tokens, e.g. for
    # an internet-facing instance where a leaked config URL should stop
    # working on its own after a while.
    _proxy_token_max_age_raw = os.environ.get("PROXY_TOKEN_MAX_AGE_SECONDS", "").strip()
    PROXY_TOKEN_MAX_AGE = int(_proxy_token_max_age_raw) if _proxy_token_max_age_raw else None

    # Optional MCP OAuth 2.1 Authorization Server (RFC8414 + RFC9728 + RFC7591).
    # Off by default: clients keep using the signed path token in
    # /proxy/mcp/<token>/<server_id>. When true, mcprack also exposes
    # /proxy/mcp/<server_id> authenticated via Authorization: Bearer
    # (OAuth access token or an ApiToken with the proxy:access scope),
    # plus the .well-known discovery / authorize / token / register
    # endpoints MCP clients need for the standard OAuth dance. Downloaded
    # configs then emit the tokenless URL so the path secret can be skipped.
    OAUTH_ENABLED = os.environ.get("OAUTH_ENABLED", "false").lower() in ("true", "1", "yes")
    # Access-token lifetime for tokens minted by /oauth/token.
    OAUTH_ACCESS_TOKEN_EXPIRES = int(os.environ.get("OAUTH_ACCESS_TOKEN_EXPIRES", str(3600)))
    OAUTH_REFRESH_TOKEN_EXPIRES = int(os.environ.get("OAUTH_REFRESH_TOKEN_EXPIRES", str(30 * 86400)))
    # authlib requires HTTPS for authorize/token. Leave false in production
    # (terminate TLS at the reverse proxy). Set true only for plain-HTTP
    # lab installs — never on the public internet.
    # Redirect URI policy for dynamic client registration (oauth_policy.py):
    # loopback is always allowed; https only to these hosts ("*.suffix" ok);
    # extra prefixes allow custom schemes such as "vscode://".
    OAUTH_ALLOWED_REDIRECT_HOSTS = os.environ.get("OAUTH_ALLOWED_REDIRECT_HOSTS", "claude.ai,claude.com")
    OAUTH_ALLOWED_REDIRECT_PREFIXES = os.environ.get("OAUTH_ALLOWED_REDIRECT_PREFIXES", "")
    # Registrations are open to anyone who can reach the server, so they are
    # capped; clients that never received a token are dropped after this long.
    OAUTH_MAX_CLIENTS = int(os.environ.get("OAUTH_MAX_CLIENTS", "500"))
    OAUTH_UNUSED_CLIENT_TTL_HOURS = int(os.environ.get("OAUTH_UNUSED_CLIENT_TTL_HOURS", "24"))
    # A client younger than this is never evicted to make room (it is probably
    # about to authorize), and registration has its own, tighter rate limit.
    OAUTH_CLIENT_MIN_AGE_SECONDS = int(os.environ.get("OAUTH_CLIENT_MIN_AGE_SECONDS", "900"))
    OAUTH_REGISTER_RATE_LIMIT = os.environ.get("OAUTH_REGISTER_RATE_LIMIT", "10 per minute;100 per hour")
    OAUTH_ALLOW_INSECURE_TRANSPORT = os.environ.get(
        "OAUTH_ALLOW_INSECURE_TRANSPORT", "false"
    ).lower() in ("true", "1", "yes")
