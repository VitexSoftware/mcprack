import click
from flask import Flask

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

    register_cli(app)

    return app


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
