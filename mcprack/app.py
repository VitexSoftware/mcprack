import os
from urllib.parse import urlsplit

import click
from flask import current_app, Flask, jsonify, render_template, request, Response, session
from flask_babel import gettext as _
from flask_migrate import stamp
from sqlalchemy import inspect
from werkzeug.exceptions import SecurityError

from .config import Config
from .extensions import babel, csrf, db, limiter, login_manager, migrate
from .secret_store import INSECURE_DEFAULT_SECRET_KEY

# Bundled inside the package (mcprack/migrations) rather than resolved
# relative to the current working directory - Flask-Migrate's own default -
# so `flask db upgrade` / the automatic create_all()+stamp() bootstrap below
# work the same whether mcprack is run from a git checkout, a Debian
# install, or a plain `pip install mcprack`, regardless of cwd.
MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations")


_PLACEHOLDER_PREFIXES = ("change", "dev-", "dev_", "example", "test", "secret", "password", "default", "insecure")
MIN_SECRET_KEY_LENGTH = 32


def _weak_secret_key(key):
    """Why `key` is not acceptable as a production SECRET_KEY, or None."""
    if not key or key == INSECURE_DEFAULT_SECRET_KEY:
        return "it is missing or still the well-known default"
    if key.lower().startswith(_PLACEHOLDER_PREFIXES):
        return "it looks like a placeholder"
    if len(key) < MIN_SECRET_KEY_LENGTH:
        return f"it is shorter than {MIN_SECRET_KEY_LENGTH} characters"
    if len(set(key)) < 8:
        return "it has too little variety"
    return None


def _enforce_secret_key(app):
    """Refuse to boot in production with a weak SECRET_KEY - it signs Flask
    sessions, per-user proxy tokens and reset links, and is the root of the
    key that encrypts the local secret store (secret_store.py). The old guard
    rejected only the literal default, so `change-me` from .env.example or
    `change-me-<epoch>` slipped through (docs/AUDIT-2026-11.md B-16)."""
    if app.config.get("DEBUG") or app.config.get("TESTING"):
        return
    key = app.config.get("SECRET_KEY", "")
    problem = _weak_secret_key(key)
    # A fallback key still VERIFIES signatures (sessions, proxy URLs, reset
    # links) and decrypts the local secret store, so a weak one is as bad as a
    # weak SECRET_KEY: anybody who guesses it can forge what it verifies.
    for index, old_key in enumerate(app.config.get("SECRET_KEY_FALLBACKS") or [], start=1):
        weak = _weak_secret_key(old_key)
        if weak and not problem:
            problem = f"SECRET_KEY_FALLBACKS entry #{index} is not acceptable: {weak}"
    if problem:
        error_msg = (
            "\n"
            "MCprack cannot start: the secret key configuration is not acceptable - " + problem + ".\n"
            "\n"
            "SECRET_KEY signs Flask sessions and per-user proxy tokens and protects the\n"
            "locally encrypted secrets, so it must be a strong random value.\n"
            "\n"
            "Fix (as root):\n"
            "    sudo mcprack-init-config --force      # generates a new one and restarts\n"
            "or generate one yourself:\n"
            "    python3 -c \"import secrets; print('SECRET_KEY=' + secrets.token_hex(32))\"\n"
            "and put it in /etc/mcprack/env, then: sudo systemctl restart mcprack\n"
            "\n"
            "Rotating an existing key? Keep the old one in SECRET_KEY_FALLBACKS so existing\n"
            "sessions, client configurations and local secrets keep working - but only a\n"
            "strong old key is accepted there, and a weak one must be re-created, not kept.\n"
        )
        raise RuntimeError(error_msg)


def _derive_trusted_hosts(app):
    """With a public URL configured, refuse requests for any other Host
    (docs/AUDIT-2026-11.md A-05: Host-header poisoning of links, redirects and
    OAuth metadata). Loopback names stay valid so the reverse proxy host's own
    health checks keep working. An explicit TRUSTED_HOSTS wins."""
    if app.config.get("TRUSTED_HOSTS"):
        return
    public = urlsplit(app.config.get("PUBLIC_BASE_URL") or "").hostname
    if public:
        app.config["TRUSTED_HOSTS"] = [public, "localhost", "127.0.0.1", "[::1]"]


def get_locale():
    # If a locale is manually stored in the session, use it
    loc = session.get("locale")
    if loc in ["cs", "sk", "en"]:
        return loc
    # Otherwise, detect from browser/accept headers
    return request.accept_languages.best_match(["cs", "sk", "en"]) or "en"


def create_app(config_object=Config):
    """Build a configured Flask app. The factory shape is what lets the
    tests and the CLI build an isolated instance per use instead of
    importing one global app."""
    app = Flask(__name__)
    app.config.from_object(config_object)
    _enforce_secret_key(app)
    _derive_trusted_hosts(app)
    from . import audit_mirror

    audit_mirror.init_app(app)
    if (
        app.config.get("LDAP_ENABLED")
        and not str(app.config.get("LDAP_SERVER", "")).lower().startswith("ldaps://")
        and not app.config.get("LDAP_STARTTLS")
    ):
        app.logger.warning(
            "LDAP is enabled over unencrypted ldap://: directory passwords (and the bind password) cross "
            "the network in clear text. Use ldaps:// or set LDAP_STARTTLS=true."
        )

    db.init_app(app)
    migrate.init_app(app, db, directory=MIGRATIONS_DIR)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    babel.init_app(app, locale_selector=get_locale)

    # SQLite with several gunicorn workers writing (audit rows on every
    # proxy start/stop, selections, tokens) hits "database is locked" under
    # concurrent commits. WAL lets readers proceed while a writer commits,
    # and busy_timeout makes a colliding writer wait (up to 15s, i.e. well
    # past any single fast transaction) instead of failing instantly.
    # WAL is a persistent property of the database file, so this also
    # covers CLI/one-off connections opened against the same DB.
    if str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("sqlite"):
        from sqlalchemy import event
        from sqlalchemy.engine import Engine

        @event.listens_for(Engine, "connect")
        def _sqlite_tune(dbapi_connection, _connection_record):
            # Fires for every engine built by this process - keep it a no-op
            # for any non-sqlite3 driver (e.g. a future PostgreSQL switch).
            if type(dbapi_connection).__module__ != "sqlite3":
                return
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=15000")
                cursor.execute("PRAGMA synchronous=NORMAL")
            finally:
                cursor.close()

    @app.after_request
    def _set_security_headers(response):
        """Harden every response for a public-internet deployment. Applied
        here rather than in the reverse proxy so the guarantee holds even
        when mcprack is reached directly or the vhost is misconfigured;
        setdefault so a view that needs its own value still wins."""
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        # Pages and API answers are per-user and carry client configurations,
        # tokens and secrets: a shared proxy or the browser's back/forward
        # cache must not keep them. Only static assets may be cached.
        if not request.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        # No 'unsafe-inline' for styles: every style comes from style.css
        # now (templates and JS set classes, never style attributes), so a
        # successful XSS cannot inject CSS either.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; script-src 'self'",
        )
        # Only makes sense once we know we're actually behind HTTPS (i.e.
        # ProxyFix's x_proto=1 saw X-Forwarded-Proto: https) - setting it
        # unconditionally would be wrong for a plain-HTTP intranet install.
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        response.headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        )
        if not (
            request.path.startswith("/proxy/mcp/")
            or request.path.startswith("/.well-known/")
            or request.path.startswith("/oauth/")
        ):
            response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")

        # The user-proxy MCP endpoint is bearer-token authenticated via the
        # signed token in the URL path (or Authorization: Bearer when
        # OAuth is on), not cookies - so, unlike the rest of the app, it's
        # safe to open up to cross-origin callers. Remote MCP clients
        # (Claude Desktop, claude.ai) are browser/Electron-based and
        # enforce CORS: without these headers their preflight OPTIONS - or
        # the browser's post-preflight block of the real request - fails
        # before mcprack's response ever gets read, even though the request
        # itself would have succeeded (curl doesn't enforce CORS, so this is
        # invisible outside a real browser-based client). The same CORS
        # applies to OAuth discovery / token / register so the client's
        # browser-side OAuth dance can reach them.
        if (
            request.path.startswith("/proxy/mcp/")
            or request.path.startswith("/.well-known/")
            or request.path.startswith("/oauth/")
        ):
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = (
                "Content-Type, Accept, Authorization, Mcp-Session-Id, "
                "Mcp-Protocol-Version, Last-Event-ID"
            )
            response.headers["Access-Control-Expose-Headers"] = "Mcp-Session-Id"
            response.headers["Access-Control-Max-Age"] = "86400"
        return response

    def _is_api_or_proxy_request():
        """Whether this caller wants a machine-readable error. An MCP
        client or API consumer handed a rendered HTML error page cannot
        parse it, and the proxy and OAuth paths are never browsed."""
        return (
            request.path.startswith("/api/")
            or request.path.startswith("/proxy/mcp/")
            or request.path.startswith("/oauth/")
            or request.accept_mimetypes.best == "application/json"
        )

    @app.errorhandler(SecurityError)
    def handle_untrusted_host(err):
        """A Host header outside TRUSTED_HOSTS. Answered without a template:
        rendering the error page would itself need request.host / url_for."""
        return Response("Bad Request: unknown host\n", status=400, mimetype="text/plain")

    @app.errorhandler(400)
    def handle_bad_request(err):
        """400 as JSON for API/proxy callers, as a translated page for
        browsers."""
        if _is_api_or_proxy_request():
            return jsonify({"error": "bad_request", "message": getattr(err, "description", str(err))}), 400
        return render_template(
            "error.html",
            error_code=400,
            error_title=_("Bad Request"),
            error_message=getattr(err, "description", _("The request could not be understood by the server.")),
        ), 400

    @app.errorhandler(403)
    def handle_forbidden(err):
        """403 as JSON for API/proxy callers, as a translated page for
        browsers."""
        if _is_api_or_proxy_request():
            return jsonify({"error": "forbidden", "message": getattr(err, "description", str(err))}), 403
        return render_template(
            "error.html",
            error_code=403,
            error_title=_("Access Denied"),
            error_message=getattr(err, "description", _("You do not have permission to access this resource.")),
        ), 403

    @app.errorhandler(404)
    def handle_not_found(err):
        """404 as JSON for API/proxy callers, as a translated page for
        browsers."""
        if _is_api_or_proxy_request():
            return jsonify({"error": "not_found", "message": getattr(err, "description", str(err))}), 404
        return render_template(
            "error.html",
            error_code=404,
            error_title=_("Page Not Found"),
            error_message=getattr(err, "description", _("The page or resource you requested could not be found.")),
        ), 404

    @app.errorhandler(413)
    def handle_payload_too_large(err):
        """413 from the MAX_CONTENT_LENGTH cap. The generic message is
        deliberate - the limit itself is not the submitter's business."""
        if _is_api_or_proxy_request():
            return jsonify({"error": "payload_too_large", "message": getattr(err, "description", str(err))}), 413
        return render_template(
            "error.html",
            error_code=413,
            error_title=_("Request Too Large"),
            error_message=_("The data you submitted is larger than this server accepts."),
        ), 413

    @app.errorhandler(429)
    def handle_rate_limit(err):
        """429 from Flask-Limiter. Flask-Limiter adds Retry-After and the
        X-RateLimit-* headers from its own after_request hook, so this only
        has to supply the body."""
        if _is_api_or_proxy_request():
            return jsonify({"error": "rate_limit_exceeded", "message": getattr(err, "description", str(err))}), 429
        return render_template(
            "error.html",
            error_code=429,
            error_title=_("Too Many Requests"),
            error_message=_("Too many requests from your IP address. Please slow down and try again later."),
        ), 429

    @app.errorhandler(500)
    def handle_internal_server_error(err):
        """500 with the detail logged and withheld. Unlike the other
        handlers this never echoes the description: an unexpected
        exception's text can carry paths, SQL or credentials."""
        current_app.logger.exception("Internal server error")
        if _is_api_or_proxy_request():
            return jsonify({"error": "internal_error", "message": "An unexpected error occurred."}), 500
        return render_template(
            "error.html",
            error_code=500,
            error_title=_("Internal Server Error"),
            error_message=_("An unexpected server error occurred. Please contact the administrator."),
        ), 500

    @app.errorhandler(502)
    def handle_bad_gateway(err):
        """502 for an upstream that did not answer properly - a relayed MCP
        backend, or Vaultwarden."""
        if _is_api_or_proxy_request():
            return jsonify({"error": "bad_gateway", "message": getattr(err, "description", str(err))}), 502
        return render_template(
            "error.html",
            error_code=502,
            error_title=_("Bad Gateway"),
            error_message=getattr(err, "description", _("The upstream service did not respond properly.")),
        ), 502

    from .auth import bp as auth_bp
    from .admin import bp as admin_bp
    from .catalog import bp as catalog_bp
    from .api import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(catalog_bp)
    app.register_blueprint(api_bp)
    # Bearer-token requests carry no ambient cookie for a forged cross-site
    # request to exploit, and no browser JS calls into /api/v1/* exist today
    # - see api.py's module docstring for the full rationale.
    csrf.exempt(api_bp)

    # One central DEMO_MODE write guard for HTML *and* API routes.
    from . import demo

    app.before_request(demo.guard)

    from . import oauth

    oauth.init_oauth(app)

    from . import api_auth  # noqa: F401 - registers the bearer-token request_loader

    from . import telemetry

    telemetry.init_app(app)

    from . import models  # noqa: F401 - Register models for table creation
    with app.app_context():
        # Once Alembic has taken ownership of this database (alembic_version
        # exists), let `flask db upgrade` own all schema evolution. Calling
        # create_all() here too would create tables for any model whose
        # migration hasn't run yet, so that migration then fails with
        # "table already exists" the moment it does run. Only bootstrap via
        # create_all() for a database Alembic has never touched -- and stamp
        # it to head immediately after, so a later `flask db upgrade` sees
        # the schema as already current instead of trying to recreate it
        # from the first migration and colliding on "table already exists".
        if not inspect(db.engine).has_table("alembic_version"):
            db.create_all()
            stamp()

    from .version import get_version

    app.jinja_env.globals["app_version"] = get_version()

    register_cli(app)
    register_static_routes(app)

    return app


def register_static_routes(app):
    @app.route("/favicon.ico")
    def favicon():
        return app.send_static_file("favicon.ico")

    @app.route("/health")
    def health_check():
        """Unauthenticated liveness endpoint for load balancers/monitoring.
        Deliberately reports only boolean check results — never config
        values, URLs, or tokens — since this route has no auth."""
        from flask import jsonify
        from sqlalchemy import text

        from .extensions import db

        checks = {}
        try:
            db.session.execute(text("SELECT 1"))
            checks["database"] = True
        except Exception:
            db.session.rollback()
            checks["database"] = False

        healthy = all(checks.values())
        status_code = 200 if healthy else 503
        return jsonify(status="ok" if healthy else "degraded", checks=checks), status_code


    @app.route("/health/servers")
    def health_servers():
        """Per-server end-to-end status for Zabbix (see monitoring.py).
        Bearer-token protected and disabled unless MONITORING_TOKEN is set;
        reports names, booleans, tool counts and short error strings only."""
        import hmac

        from flask import abort, jsonify

        from . import monitoring

        token = current_app.config.get("MONITORING_TOKEN")
        if not token:
            abort(404)
        header = request.headers.get("Authorization", "")
        supplied = header[7:] if header.lower().startswith("bearer ") else ""
        if not hmac.compare_digest(supplied.encode(), token.encode()):
            abort(401)
        return jsonify(monitoring.get_snapshot(current_app._get_current_object()))


def register_cli(app):
    from .cli import register_management_cli

    register_management_cli(app)

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--password", default=None, help="Password (visible in the process list - prefer --password-file).")
    @click.option(
        "--password-file",
        type=click.Path(exists=True, dir_okay=False, readable=True),
        default=None,
        help="Read the password from this file (first line). Without either option you are prompted.",
    )
    @click.option("--email", default="")
    def create_admin(username, password, password_file, email):
        """Create the first local admin account."""
        from . import passwords
        from .models import User

        if password_file:
            with open(password_file, encoding="utf-8") as handle:
                password = handle.readline().rstrip("\r\n")
        elif password is None:
            password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

        if User.query.filter_by(username=username).first():
            click.echo(f"User '{username}' already exists.")
            return
        problem = passwords.check_strength(password, username)
        if problem:
            raise click.ClickException(problem)

        user = User(username=username, email=email, auth_type="local", is_admin=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Admin user '{username}' created.")

    @app.cli.command("audit-verify")
    @click.option(
        "--log",
        "logs",
        multiple=True,
        type=click.Path(),
        help="Mirror log to check (repeatable; rotated copies audit.log.1, audit.log.2.gz ... are included). "
        "Default: AUDIT_LOG_FILE.",
    )
    @click.option("--days", type=int, default=None, help="Only check the last N days (defaults to AUDIT_RETENTION_DAYS).")
    @click.option("--strict", is_flag=True, help="Treat rows without a mirror line, and unreadable lines, as failures too.")
    @click.option("--max-report", type=int, default=20, show_default=True, help="Most ids to list per category.")
    def audit_verify_command(logs, days, strict, max_report):
        """Compare the audit mirror with the audit table and report tampering.

        Exit status 1 if a mirror line has a wrong MAC, a row is missing or was
        changed; with --strict also if a row has no mirror line. 2 if there is no
        log to check."""
        from . import audit_mirror, audit_verify

        configured = audit_mirror.resolve_file(current_app.config.get("AUDIT_LOG_FILE"))
        paths = []
        for requested in logs or ([configured] if configured else []):
            paths.extend(audit_verify.log_files(requested))
        if not paths:
            click.echo(
                "No mirror log found. Pass --log PATH, or set AUDIT_LOG_FILE (default /var/log/mcprack/audit.log) - "
                "the journal copy (`journalctl -u mcprack | grep ^AUDIT`) can be saved to a file and checked too.",
                err=True,
            )
            raise SystemExit(2)

        retention = days if days is not None else current_app.config["AUDIT_RETENTION_DAYS"]
        report = audit_verify.verify(paths, keys=audit_mirror._keys(), retention_days=retention)

        def listing(items):
            shown = ", ".join(str(item) for item in items[:max_report])
            return shown + (f" ... (+{len(items) - max_report} more)" if len(items) > max_report else "")

        click.echo(f"Read {report.lines} line(s) from {len(report.files)} file(s); {report.checked} event(s) checked"
                   + (f" since {report.window_start.isoformat(timespec='seconds')}." if report.window_start else "."))
        if report.unwritten:
            click.echo(f"note: {report.unwritten} event(s) could not be written to the database at the time (logged with no id).")
        if report.bad_mac:
            click.echo(f"TAMPERED LOG: {len(report.bad_mac)} line(s) with an invalid MAC: "
                       + listing([f"{name}:{number}" for name, number in report.bad_mac]))
        if report.missing_in_db:
            click.echo(f"DELETED: {len(report.missing_in_db)} event(s) are in the log but not in the database: "
                       + listing(report.missing_in_db))
        if report.altered:
            click.echo(f"ALTERED: {len(report.altered)} row(s) differ from the log: "
                       + listing([f"{rid} ({', '.join(fields)})" for rid, fields in report.altered]))
        if report.unmirrored:
            click.echo(f"{'UNMIRRORED' if strict else 'warning'}: {len(report.unmirrored)} row(s) have no line in the log "
                       f"(inserted, or written while the mirror was off): " + listing(report.unmirrored))
        if report.garbled:
            click.echo(f"{'UNREADABLE' if strict else 'warning'}: {report.garbled} line(s) could not be read.")
        failed = report.tampering or (strict and report.warnings)
        if report.window_start is None and not report.bad_mac:
            click.echo("Nothing to check: the log holds no authentic events.", err=True)
            raise SystemExit(2)
        click.echo("FAILED" if failed else "OK: the audit table agrees with the mirror.")
        if failed:
            raise SystemExit(1)

    @app.cli.command("audit-archive")
    @click.option(
        "--days",
        type=int,
        default=None,
        help="Archive entries older than this many days (defaults to AUDIT_RETENTION_DAYS).",
    )
    @click.option(
        "--format",
        "export_format",
        type=click.Choice(["json", "csv"]),
        default="json",
        help="Export format for the archive file.",
    )
    @click.option(
        "--output",
        "output_path",
        default=None,
        help="Path to write the archive to (default: audit-archive-<cutoff-date>.<format> in the current directory).",
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        help="Only report how many entries would be archived, without exporting or deleting anything.",
    )
    def audit_archive(days, export_format, output_path, dry_run):
        """Export audit_log_entries older than the retention window to
        JSON/CSV, then delete them from the database. The archival run
        itself is recorded as a new (never-deleted) audit entry."""
        from . import audit
        from . import audit_retention

        retention_days = days if days is not None else current_app.config["AUDIT_RETENTION_DAYS"]
        cutoff = audit_retention.cutoff_datetime(retention_days)
        entries = audit_retention.entries_older_than(cutoff)

        if not entries:
            click.echo(f"No audit entries older than {retention_days} days ({cutoff.isoformat()}).")
            return

        if dry_run:
            click.echo(f"{len(entries)} entries older than {cutoff.isoformat()} would be archived.")
            return

        path = output_path or audit_retention.default_archive_path(cutoff, export_format)
        audit_retention.export_entries(entries, path, export_format)
        count = audit_retention.delete_entries(entries)

        audit.log_audit_event(
            "admin_change",
            "success",
            error_message=f"audit-archive: purged {count} entries older than {cutoff.date()} to {path}",
        )
        click.echo(f"Archived {count} entries to {path} and removed them from the database.")
