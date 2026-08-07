"""Command-line administration for mcprack: user accounts, MCP catalog
servers, and their per-server credential (secret env var) values.

Invoked via `flask --app mcprack.app:create_app <group> <command>` (or the
`mcprack` launcher script / console entry point, which forwards its
arguments here). Kept separate from
app.py's own top-level create-admin/audit-archive commands, which existing
scripts (debian/postinst) already call by name and must keep working
unchanged.
"""

import click
from dotenv import dotenv_values
from flask.cli import AppGroup

from . import secret_store
from .env_detection import SENSITIVE_NAME_HINTS
from .extensions import db
from .models import McpServer, User


def _looks_sensitive_name(name):
    upper = name.upper()
    return any(hint in upper for hint in SENSITIVE_NAME_HINTS)


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


@server_cli.command("import-env")
@click.argument("server_name")
@click.argument("dotenv_path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--overwrite/--no-overwrite",
    default=True,
    help="Overwrite keys that already have a value (default: overwrite).",
)
def server_import_env(server_name, dotenv_path, overwrite):
    """Import KEY=VALUE pairs from a .env file into a server's config.

    Keys matching common credential-name patterns (KEY, SECRET, TOKEN,
    PASSWORD, PASSWD, CREDENTIAL, APIKEY) are stored as secrets via the
    configured secret store; everything else is stored as plain config.
    Review the result with `server show` / `secret list` and fix
    misclassifications with `secret set`/`secret unset`.
    """
    s = _get_server_or_fail(server_name)
    parsed = {k: v for k, v in dotenv_values(dotenv_path).items() if v is not None}
    if not parsed:
        click.echo("No KEY=VALUE pairs found in the file.")
        return

    non_secret = dict(s.env_config or {})
    secret_values = secret_store.load_server_secrets(s) if s.env_var_names else {}
    secret_keys = set(s.env_var_names or [])

    added_plain, added_secret, skipped = [], [], []
    for key, value in parsed.items():
        already_set = key in non_secret or key in secret_keys
        if already_set and not overwrite:
            skipped.append(key)
            continue
        if _looks_sensitive_name(key):
            secret_values[key] = value
            secret_keys.add(key)
            non_secret.pop(key, None)
            added_secret.append(key)
        else:
            non_secret[key] = value
            secret_keys.discard(key)
            secret_values.pop(key, None)
            added_plain.append(key)

    s.env_config = non_secret
    s.env_var_names = sorted(secret_keys)
    if not s.vaultwarden_item_name:
        s.vaultwarden_item_name = f"MCP-{s.name}"
    if secret_values or secret_keys:
        secret_store.save_server_secrets(s, secret_values)
    db.session.commit()

    if added_plain:
        click.echo(f"Plain:  {', '.join(sorted(added_plain))}")
    if added_secret:
        click.echo(f"Secret: {', '.join(sorted(added_secret))}")
    if skipped:
        click.echo(f"Skipped (already set, use --overwrite): {', '.join(sorted(skipped))}")
    if not added_plain and not added_secret:
        click.echo("Nothing imported.")


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
