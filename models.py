import json
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def _utcnow():
    return datetime.now(timezone.utc)


def _safe_json_loads(raw, default):
    if not raw:
        return default
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return default
    return value


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    auth_type = db.Column(db.String(10), nullable=False, default="local")  # 'local' | 'ldap'
    password_hash = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_active_flag = db.Column("is_active", db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)

    selections = db.relationship(
        "UserServerSelection", back_populates="user", cascade="all, delete-orphan"
    )
    overrides = db.relationship(
        "UserServerOverride", back_populates="user", cascade="all, delete-orphan"
    )
    permissions = db.relationship(
        "UserServerPermission", back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def is_active(self):
        return self.is_active_flag

    def set_password(self, raw_password):
        self.auth_type = "local"
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw_password)

    @property
    def display_name(self):
        parts = [p for p in (self.first_name, self.last_name) if p]
        return " ".join(parts) if parts else self.username


class McpServer(db.Model):
    __tablename__ = "mcp_servers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False, index=True)
    label = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    transport = db.Column(db.String(10), nullable=False)  # 'stdio' | 'http' | 'sse'

    # stdio
    command = db.Column(db.String(500), nullable=True)
    args_json = db.Column(db.Text, nullable=True)  # JSON-encoded list[str]

    # http / sse
    url = db.Column(db.String(500), nullable=True)
    auth_header_name = db.Column(db.String(150), nullable=True)
    auth_env_key = db.Column(db.String(150), nullable=True)

    # non-secret hints only — actual values live in Vaultwarden
    env_var_names_json = db.Column(db.Text, nullable=True)  # JSON-encoded list[str]
    vaultwarden_item_name = db.Column(db.String(255), nullable=True)

    # Non-secret environment variables for this server (JSON dict), stored
    # directly in the app DB — no Vaultwarden round-trip needed for these.
    # Example: {"MASTODON_INSTANCE": "https://fosstodon.org"}
    env_config_json = db.Column(db.Text, nullable=True, default='{}')

    # Fallback store for secret values (admin defaults) when Vaultwarden is
    # not configured at all. Fernet-encrypted JSON dict; see secret_store.py.
    # Never populated while Vaultwarden is configured — see secret_store.py
    # for the single source-of-truth switch.
    env_secrets_encrypted = db.Column(db.Text, nullable=True)

    allow_user_override = db.Column(db.Boolean, nullable=False, default=True)
    category = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    # Install tracking — NULL/absent means "registered manually or via
    # autodetect", exactly like every server before this feature existed.
    # Only set when mcprack itself installed the server (see installer.py).
    install_method = db.Column(db.String(10), nullable=True)  # 'pip' | 'npm' | 'docker'
    package_spec = db.Column(db.String(500), nullable=True)
    expected_binary = db.Column(db.String(255), nullable=True)
    install_path = db.Column(db.String(500), nullable=True)
    install_status = db.Column(db.String(20), nullable=True)  # queued|running|success|failed
    install_log_path = db.Column(db.String(500), nullable=True)
    install_error = db.Column(db.String(500), nullable=True)
    installed_version = db.Column(db.String(100), nullable=True)
    installed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    selections = db.relationship(
        "UserServerSelection", back_populates="server", cascade="all, delete-orphan"
    )
    overrides = db.relationship(
        "UserServerOverride", back_populates="server", cascade="all, delete-orphan"
    )
    permissions = db.relationship(
        "UserServerPermission", back_populates="server", cascade="all, delete-orphan"
    )

    @property
    def args(self):
        value = _safe_json_loads(self.args_json, [])
        return value if isinstance(value, list) else []

    @args.setter
    def args(self, value):
        self.args_json = json.dumps(list(value or []))

    @property
    def env_var_names(self):
        value = _safe_json_loads(self.env_var_names_json, [])
        return value if isinstance(value, list) else []

    @env_var_names.setter
    def env_var_names(self, value):
        self.env_var_names_json = json.dumps(list(value or []))

    @property
    def env_config(self):
        value = _safe_json_loads(self.env_config_json, {})
        return value if isinstance(value, dict) else {}

    @env_config.setter
    def env_config(self, value):
        self.env_config_json = json.dumps(dict(value or {}))

    @property
    def vault_item(self):
        return self.vaultwarden_item_name or f"MCP-{self.name}"


class UserServerSelection(db.Model):
    __tablename__ = "user_server_selections"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey("mcp_servers.id"), primary_key=True)
    selected_at = db.Column(db.DateTime(timezone=True), default=_utcnow)

    user = db.relationship("User", back_populates="selections")
    server = db.relationship("McpServer", back_populates="selections")


class UserServerOverride(db.Model):
    """Records that a personal override exists for this user+server.

    When Vaultwarden is configured, the actual override values live in
    Vaultwarden under '<server.vault_item>-user-<username>' and
    `env_secrets_encrypted` here stays empty — this row is just bookkeeping.
    When Vaultwarden is not configured, `env_secrets_encrypted` holds the
    Fernet-encrypted fallback copy instead. See secret_store.py."""

    __tablename__ = "user_server_overrides"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey("mcp_servers.id"), primary_key=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    env_secrets_encrypted = db.Column(db.Text, nullable=True)

    user = db.relationship("User", back_populates="overrides")
    server = db.relationship("McpServer", back_populates="overrides")


class AuditLogEntry(db.Model):
    """Append-only security audit trail. Rows are written once by
    audit.log_audit_event() and never modified — this model deliberately
    exposes no update/delete helpers, and no admin route may edit or delete
    a row (see admin.py audit_log view). Never store request/response
    bodies or credential values here — only that an action happened, by
    whom, against which server, and its outcome."""

    __tablename__ = "audit_log_entries"

    ACTIONS = (
        "tool_call",
        "config_download",
        "credential_access",
        "proxy_start",
        "proxy_stop",
        "admin_change",
        "login",
        "login_failed",
    )
    RESULTS = ("success", "error")

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow, index=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    server_id = db.Column(
        db.Integer, db.ForeignKey("mcp_servers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Denormalized snapshot of the server's name at the time of the event,
    # so history stays readable even after the McpServer row is deleted.
    server_name = db.Column(db.String(150), nullable=True)

    action = db.Column(db.String(30), nullable=False)
    result = db.Column(db.String(10), nullable=False, default="success")
    error_code = db.Column(db.String(50), nullable=True)
    error_message = db.Column(db.String(500), nullable=True)

    source_ip = db.Column(db.String(64), nullable=True)
    hostname = db.Column(db.String(255), nullable=True)

    duration_ms = db.Column(db.Integer, nullable=True)
    request_id = db.Column(db.String(36), nullable=True, index=True)

    __table_args__ = (
        db.Index("ix_audit_server_timestamp", "server_id", "timestamp"),
        db.Index("ix_audit_user_timestamp", "user_id", "timestamp"),
    )

    user = db.relationship("User")
    server = db.relationship("McpServer")


class UserServerPermission(db.Model):
    """Explicit per-user server access policy.

    If a row exists, `is_allowed` decides whether the user may use that
    server. If no rows exist for a user yet (legacy users), behavior falls
    back to allow-all-enabled for backward compatibility.
    """

    __tablename__ = "user_server_permissions"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey("mcp_servers.id"), primary_key=True)
    is_allowed = db.Column(db.Boolean, nullable=False, default=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    user = db.relationship("User", back_populates="permissions")
    server = db.relationship("McpServer", back_populates="permissions")
