import os


class Config:
    # Production settings by default
    DEBUG = False
    TESTING = False
    
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")

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
