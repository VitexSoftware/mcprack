"""Command-line administration for mcprack: user accounts, MCP catalog
servers, and their per-server credential (secret env var) values.

Invoked via `flask --app app:create_app <group> <command>` (or the `mcprack`
launcher script, which forwards its arguments here). Kept separate from
app.py's own top-level create-admin/audit-archive commands, which existing
scripts (debian/postinst) already call by name and must keep working
unchanged.
"""

import click
from flask.cli import AppGroup

import secret_store
from extensions import db
from models import McpServer, User


user_cli = AppGroup("user", help="Manage mcprack user accounts.")
server_cli = AppGroup("server", help="Manage MCP catalog servers.")
secret_cli = AppGroup("secret", help="Manage a server's credential (secret env var) values.")


def _get_user_or_fail(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        raise click.ClickException(f"No such user: '{username}'.")
    return user


def _get_server_or_fail(name):
    server = McpServer.query.filter_by(name=name).first()
    if not server:
        raise click.ClickException(f"No such MCP server: '{name}'.")
    return server


@user_cli.command("list")
def user_list():
    """List all user accounts."""
    users = User.query.order_by(User.username).all()
    if not users:
        click.echo("No users.")
        return
    for u in users:
        flags = []
        if u.is_admin:
            flags.append("admin")
        if not u.is_active_flag:
            flags.append("disabled")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        click.echo(f"{u.id}\t{u.username}\t{u.auth_type}\t{u.email or '-'}{flag_str}")


@user_cli.command("create")
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@click.option("--email", default="")
@click.option("--admin", is_flag=True, help="Grant admin privileges.")
def user_create(username, password, email, admin):
    """Create a local user account."""
    if User.query.filter_by(username=username).first():
        raise click.ClickException(f"User '{username}' already exists.")
    user = User(username=username, email=email, auth_type="local", is_admin=admin)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f"User '{username}' created{' (admin)' if admin else ''}.")


@user_cli.command("delete")
@click.argument("username")
@click.confirmation_option(prompt="This permanently deletes the user and their selections/overrides. Continue?")
def user_delete(username):
    """Delete a user account."""
    user = _get_user_or_fail(username)
    db.session.delete(user)
    db.session.commit()
    click.echo(f"User '{username}' deleted.")


@user_cli.command("passwd")
@click.argument("username")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def user_passwd(username, password):
    """Reset a local user's password."""
    user = _get_user_or_fail(username)
    if user.auth_type != "local":
        raise click.ClickException(
            f"User '{username}' authenticates via {user.auth_type}, not a local password."
        )
    user.set_password(password)
    db.session.commit()
    click.echo(f"Password updated for '{username}'.")


@user_cli.command("enable")
@click.argument("username")
def user_enable(username):
    """Re-enable a disabled user account."""
    user = _get_user_or_fail(username)
    user.is_active_flag = True
    db.session.commit()
    click.echo(f"User '{username}' enabled.")


@user_cli.command("disable")
@click.argument("username")
def user_disable(username):
    """Disable a user account (blocks login without deleting it)."""
    user = _get_user_or_fail(username)
    user.is_active_flag = False
    db.session.commit()
    click.echo(f"User '{username}' disabled.")


@user_cli.command("promote")
@click.argument("username")
def user_promote(username):
    """Grant admin privileges to a user."""
    user = _get_user_or_fail(username)
    user.is_admin = True
    db.session.commit()
    click.echo(f"User '{username}' is now an admin.")


@user_cli.command("demote")
@click.argument("username")
def user_demote(username):
    """Revoke admin privileges from a user."""
    user = _get_user_or_fail(username)
    user.is_admin = False
    db.session.commit()
    click.echo(f"User '{username}' is no longer an admin.")


@server_cli.command("list")
def server_list():
    """List all MCP catalog servers."""
    servers = McpServer.query.order_by(McpServer.name).all()
    if not servers:
        click.echo("No servers.")
        return
    for s in servers:
        state = "enabled" if s.enabled else "disabled"
        click.echo(f"{s.id}\t{s.name}\t{s.transport}\t{state}\t{s.category or '-'}")


@server_cli.command("show")
@click.argument("name")
def server_show(name):
    """Show a server's non-secret configuration."""
    s = _get_server_or_fail(name)
    click.echo(f"name:        {s.name}")
    click.echo(f"label:       {s.label}")
    click.echo(f"transport:   {s.transport}")
    click.echo(f"enabled:     {s.enabled}")
    click.echo(f"category:    {s.category or '-'}")
    if s.transport == "stdio":
        click.echo(f"command:     {s.command}")
        click.echo(f"args:        {s.args}")
    else:
        click.echo(f"url:         {s.url}")
        click.echo(f"auth header: {s.auth_header_name or '-'}")
    click.echo(f"env config:  {s.env_config}")
    click.echo(f"secret keys: {s.env_var_names or '-'}")
    if s.install_method:
        click.echo(f"installed:   {s.install_method} ({s.installed_version or 'unknown version'})")


@server_cli.command("enable")
@click.argument("name")
def server_enable(name):
    """Enable a server so users can select it."""
    s = _get_server_or_fail(name)
    s.enabled = True
    db.session.commit()
    click.echo(f"Server '{name}' enabled.")


@server_cli.command("disable")
@click.argument("name")
def server_disable(name):
    """Disable a server, hiding it from the catalog."""
    s = _get_server_or_fail(name)
    s.enabled = False
    db.session.commit()
    click.echo(f"Server '{name}' disabled.")


@server_cli.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="This permanently deletes the server and any stored credentials. Continue?")
def server_delete(name):
    """Delete a server and its stored secrets."""
    s = _get_server_or_fail(name)
    if secret_store.server_needs_secrets(s):
        secret_store.save_server_secrets(s, {})
    db.session.delete(s)
    db.session.commit()
    click.echo(f"Server '{name}' deleted.")


@secret_cli.command("backend")
def secret_backend():
    """Show which secret store backend is currently active."""
    if secret_store.is_vaultwarden_configured():
        click.echo("Vaultwarden (BW_SERVER is set).")
    else:
        click.echo("Local encrypted fallback (BW_SERVER is unset).")


@secret_cli.command("list")
@click.argument("server_name")
def secret_list(server_name):
    """List which of a server's declared secret keys currently have a value."""
    s = _get_server_or_fail(server_name)
    if not s.env_var_names:
        click.echo(f"'{server_name}' declares no secret env vars.")
        return
    values = secret_store.load_server_secrets(s)
    for key in s.env_var_names:
        click.echo(f"{key}\t{'set' if values.get(key) else 'unset'}")


@secret_cli.command("set")
@click.argument("server_name")
@click.argument("key")
@click.option("--value", prompt=True, hide_input=True, help="Omit to be prompted (hidden input).")
def secret_set(server_name, key, value):
    """Set (or overwrite) one credential value for a server."""
    s = _get_server_or_fail(server_name)
    values = secret_store.load_server_secrets(s)
    values[key] = value
    secret_store.save_server_secrets(s, values)
    db.session.commit()
    click.echo(f"'{key}' set for server '{server_name}'.")


@secret_cli.command("unset")
@click.argument("server_name")
@click.argument("key")
def secret_unset(server_name, key):
    """Remove one credential value from a server."""
    s = _get_server_or_fail(server_name)
    values = secret_store.load_server_secrets(s)
    if key not in values:
        raise click.ClickException(f"'{key}' is not set for server '{server_name}'.")
    del values[key]
    secret_store.save_server_secrets(s, values)
    db.session.commit()
    click.echo(f"'{key}' unset for server '{server_name}'.")


def register_management_cli(app):
    app.cli.add_command(user_cli)
    app.cli.add_command(server_cli)
    app.cli.add_command(secret_cli)
