import click
from flask import current_app, Flask
from sqlalchemy import inspect

from config import Config
from extensions import db, login_manager, migrate


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    from auth import bp as auth_bp
    from admin import bp as admin_bp
    from catalog import bp as catalog_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(catalog_bp)

    import telemetry

    telemetry.init_app(app)

    import models  # noqa: F401 - Register models for table creation
    with app.app_context():
        # Once Alembic has taken ownership of this database (alembic_version
        # exists), let `flask db upgrade` own all schema evolution. Calling
        # create_all() here too would create tables for any model whose
        # migration hasn't run yet, so that migration then fails with
        # "table already exists" the moment it does run. Only bootstrap via
        # create_all() for a database Alembic has never touched.
        if not inspect(db.engine).has_table("alembic_version"):
            db.create_all()

    from version import get_version

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

        from extensions import db

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


def register_cli(app):
    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    @click.option("--email", default="")
    def create_admin(username, password, email):
        """Create the first local admin account."""
        from models import User

        if User.query.filter_by(username=username).first():
            click.echo(f"User '{username}' already exists.")
            return

        user = User(username=username, email=email, auth_type="local", is_admin=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Admin user '{username}' created.")

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
        import audit
        import audit_retention

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
