import os


class Config:
    # Production settings by default
    DEBUG = False
    TESTING = False
    
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")

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
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME_SECONDS", str(8 * 3600)))

    # --- CSRF (Flask-WTF) ---
    WTF_CSRF_TIME_LIMIT = None

    # --- Rate limiting (Flask-Limiter) ---
    # memory:// is per gunicorn worker, so the effective ceiling across the
    # 4 workers configured in debian/mcprack.service is LOGIN_RATE_LIMIT x 4.
    # Point RATELIMIT_STORAGE_URI at a shared redis:// backend for a single
    # global limit across all workers.
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "10 per minute;50 per hour")

    # --- Request body size cap ---
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(2 * 1024 * 1024)))

    # --- Per-user MCP server access control ---
    # False (default) preserves existing installs' behavior: a user with no
    # UserServerPermission rows at all sees every enabled server. Set true
    # for a fail-closed internet-facing deployment - but only after
    # confirming every user (including admins) has been explicitly granted
    # access to the servers they need via Admin -> Users, since flipping
    # this with no permission rows granted locks everyone out of everything.
    STRICT_SERVER_PERMISSIONS = os.environ.get("STRICT_SERVER_PERMISSIONS", "false").lower() in ("true", "1", "yes")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SQLALCHEMY_DATABASE_URI", "sqlite:////var/lib/mcprack/mcprack.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    LDAP_ENABLED = os.environ.get("LDAP_ENABLED", "false").lower() in ("true", "1", "yes")
    LDAP_SERVER = os.environ.get("LDAP_SERVER", "ldap://10.11.25.3:389")
    LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=spojent,dc=cz")
    LDAP_USER_OU = os.environ.get("LDAP_USER_OU", "ou=Users,dc=spojent,dc=cz")
    LDAP_USER_FILTER = os.environ.get("LDAP_USER_FILTER", "(sAMAccountName=%(user)s)")
    LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
    LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")

    BW_SERVER = os.environ.get("BW_SERVER", "")
    BW_CLIENTID = os.environ.get("BW_CLIENTID", "")
    BW_CLIENTSECRET = os.environ.get("BW_CLIENTSECRET", "")
    BW_PASSWORD = os.environ.get("BW_PASSWORD", "")
    BW_ITEM_PREFIX = os.environ.get("BW_ITEM_PREFIX", "MCP-")
    BW_COMMAND_TIMEOUT = float(os.environ.get("BW_COMMAND_TIMEOUT", "12"))
    BW_LOCK_TIMEOUT = float(os.environ.get("BW_LOCK_TIMEOUT", "8"))
    BITWARDENCLI_APPDATA_DIR = os.environ.get(
        "BITWARDENCLI_APPDATA_DIR", "/opt/mcprack/.bw"
    )
    BW_BIN = os.environ.get("BW_BIN", "/usr/bin/bw")

    # Public demo mode: catalog browsing/selection and everything else still
    # works normally, but registering/editing/deleting MCP servers is
    # blocked, since the "command" an admin sets there is executed as-is
    # (never sandboxed) whenever any user connects to that server -- not
    # something a public demo admin account should be able to change.
    DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() in ("true", "1", "yes")

    # How many days of audit_log_entries to keep before `flask audit-archive`
    # exports and purges them. The audit log itself is always on — this only
    # controls the retention window, not whether logging happens.
    AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "90"))

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
