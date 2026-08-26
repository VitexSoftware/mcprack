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


def _parse_key_value_pair(raw_value, option_name):
    if "=" not in raw_value:
        raise click.ClickException(f"{option_name} expects KEY=VALUE, got '{raw_value}'.")
    key, value = raw_value.split("=", 1)
    key = key.strip()
    if not key:
        raise click.ClickException(f"{option_name} expects non-empty KEY in KEY=VALUE.")
    return key, value


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


@server_cli.command("edit")
@click.argument("name")
@click.option("--label", help="Set display label.")
@click.option("--description", help="Set description text.")
@click.option("--clear-description", is_flag=True, help="Clear description.")
@click.option("--category", help="Set category.")
@click.option("--clear-category", is_flag=True, help="Clear category.")
@click.option("--enabled/--disabled", "enabled", default=None, help="Enable/disable this server.")
@click.option(
    "--allow-user-override/--disallow-user-override",
    "allow_user_override",
    default=None,
    help="Allow or block user-level credential overrides.",
)
@click.option("--command", help="Set stdio command (stdio transport only).")
@click.option("--arg", "args_values", multiple=True, help="Set stdio args list (repeatable).")
@click.option("--clear-args", is_flag=True, help="Clear stdio args list.")
@click.option("--url", help="Set URL (http/sse transports only).")
@click.option("--auth-header-name", help="Set auth header name (http/sse transports only).")
@click.option("--auth-env-key", help="Set env var name used for auth header value.")
@click.option("--vault-item-name", help="Set Vaultwarden item name used for secret storage.")
@click.option(
    "--set-env",
    "set_env_pairs",
    multiple=True,
    metavar="KEY=VALUE",
    help="Set a non-secret env var in server config (repeatable).",
)
@click.option(
    "--unset-env",
    "unset_env_keys",
    multiple=True,
    metavar="KEY",
    help="Remove a non-secret env var from server config (repeatable).",
)
@click.option(
    "--add-secret-key",
    "add_secret_keys",
    multiple=True,
    metavar="KEY",
    help="Declare an env var key as secret (repeatable).",
)
@click.option(
    "--remove-secret-key",
    "remove_secret_keys",
    multiple=True,
    metavar="KEY",
    help="Undeclare an env var key as secret and delete its stored value (repeatable).",
)
@click.option(
    "--add-required-key",
    "add_required_keys",
    multiple=True,
    metavar="KEY",
    help="Mark env var key as required before proxy spawn (repeatable).",
)
@click.option(
    "--remove-required-key",
    "remove_required_keys",
    multiple=True,
    metavar="KEY",
    help="Unmark env var key as required (repeatable).",
)
def server_edit(
    name,
    label,
    description,
    clear_description,
    category,
    clear_category,
    enabled,
    allow_user_override,
    command,
    args_values,
    clear_args,
    url,
    auth_header_name,
    auth_env_key,
    vault_item_name,
    set_env_pairs,
    unset_env_keys,
    add_secret_keys,
    remove_secret_keys,
    add_required_keys,
    remove_required_keys,
):
    """Edit an existing MCP server's non-secret and secret-key metadata."""
    s = _get_server_or_fail(name)

    if clear_description and description is not None:
        raise click.ClickException("Use either --description or --clear-description, not both.")
    if clear_category and category is not None:
        raise click.ClickException("Use either --category or --clear-category, not both.")
    if clear_args and args_values:
        raise click.ClickException("Use either --arg or --clear-args, not both.")

    if s.transport != "stdio" and (command is not None or args_values or clear_args):
        raise click.ClickException(
            f"Server '{name}' uses transport '{s.transport}', so --command/--arg are not applicable."
        )
    if s.transport == "stdio" and (url is not None or auth_header_name is not None or auth_env_key is not None):
        raise click.ClickException(
            f"Server '{name}' uses transport 'stdio', so --url/--auth-* are not applicable."
        )

    changed = []

    if label is not None and label != s.label:
        s.label = label
        changed.append("label")

    if description is not None and description != s.description:
        s.description = description
        changed.append("description")
    elif clear_description and s.description is not None:
        s.description = None
        changed.append("description")

    if category is not None and category != s.category:
        s.category = category
        changed.append("category")
    elif clear_category and s.category is not None:
        s.category = None
        changed.append("category")

    if enabled is not None and enabled != s.enabled:
        s.enabled = enabled
        changed.append("enabled")

    if allow_user_override is not None and allow_user_override != s.allow_user_override:
        s.allow_user_override = allow_user_override
        changed.append("allow_user_override")

    if command is not None and command != s.command:
        s.command = command
        changed.append("command")

    if args_values:
        new_args = list(args_values)
        if new_args != s.args:
            s.args = new_args
            changed.append("args")
    elif clear_args and s.args:
        s.args = []
        changed.append("args")

    if url is not None and url != s.url:
        s.url = url
        changed.append("url")

    if auth_header_name is not None and auth_header_name != s.auth_header_name:
        s.auth_header_name = auth_header_name
        changed.append("auth_header_name")

    if auth_env_key is not None and auth_env_key != s.auth_env_key:
        s.auth_env_key = auth_env_key
        changed.append("auth_env_key")

    if vault_item_name is not None and vault_item_name != s.vaultwarden_item_name:
        s.vaultwarden_item_name = vault_item_name
        changed.append("vaultwarden_item_name")

    env_config = dict(s.env_config or {})
    for raw_pair in set_env_pairs:
        key, value = _parse_key_value_pair(raw_pair, "--set-env")
        if env_config.get(key) != value:
            env_config[key] = value
            changed.append(f"env_config:{key}")

    for key in unset_env_keys:
        if key in env_config:
            del env_config[key]
            changed.append(f"env_config:{key}")

    secret_keys = set(s.env_var_names or [])
    had_secret_mutation = False
    secret_values = secret_store.load_server_secrets(s) if secret_keys else {}

    for key in add_secret_keys:
        if key not in secret_keys:
            secret_keys.add(key)
            env_config.pop(key, None)
            had_secret_mutation = True
            changed.append(f"secret_keys:{key}")

    for key in remove_secret_keys:
        if key in secret_keys:
            secret_keys.remove(key)
            if key in secret_values:
                del secret_values[key]
            had_secret_mutation = True
            changed.append(f"secret_keys:{key}")

    required_keys = set(s.required_env_keys or [])
    for key in add_required_keys:
        if key not in required_keys:
            required_keys.add(key)
            changed.append(f"required_keys:{key}")

    for key in remove_required_keys:
        if key in required_keys:
            required_keys.remove(key)
            changed.append(f"required_keys:{key}")

    if env_config != (s.env_config or {}):
        s.env_config = env_config

    normalized_secret_keys = sorted(secret_keys)
    if normalized_secret_keys != (s.env_var_names or []):
        s.env_var_names = normalized_secret_keys

    normalized_required_keys = sorted(required_keys)
    if normalized_required_keys != (s.required_env_keys or []):
        s.required_env_keys = normalized_required_keys

    if had_secret_mutation:
        if not s.vaultwarden_item_name:
            s.vaultwarden_item_name = f"MCP-{s.name}"
        secret_store.save_server_secrets(s, secret_values)

    if not changed:
        click.echo(f"No changes for server '{name}'.")
        return

    db.session.commit()
    click.echo(f"Server '{name}' updated: {', '.join(sorted(set(changed)))}")


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


@click.command("init-config")
@click.option(
    "--force",
    is_flag=True,
    help="Regenerate SECRET_KEY even if one already exists.",
)
def init_config(force):
    """Initialize or repair mcprack configuration (SECRET_KEY, permissions).
    
    This command:
    • Generates a secure SECRET_KEY if missing
    • Updates /etc/mcprack/env with proper permissions (0640)
    • Ensures mcprack user can read the configuration
    • Optionally restarts the mcprack service
    
    Use 'sudo mcprack-init-config' or 'sudo flask --app mcprack.app:create_app init-config'
    """
    import os
    import secrets
    import subprocess
    from pathlib import Path
    
    ENV_FILE = Path("/etc/mcprack/env")
    
    # Check if we're running as root
    if os.geteuid() != 0:
        raise click.ClickException(
            "This command must run as root. Use: sudo mcprack-init-config"
        )
    
    # Read current env file
    env_content = {}
    if ENV_FILE.exists():
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_content[key] = value
    
    # Check if SECRET_KEY needs generation
    has_key = "SECRET_KEY" in env_content and env_content["SECRET_KEY"] != "dev-insecure-secret-change-me"
    
    if has_key and not force:
        click.echo("✅ SECRET_KEY is already configured in /etc/mcprack/env")
        return
    
    # Generate new SECRET_KEY
    new_key = secrets.token_urlsafe(32)
    env_content["SECRET_KEY"] = new_key
    
    # Write updated env file
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ENV_FILE, "w") as f:
        for key, value in env_content.items():
            f.write(f"{key}={value}\n")
    
    # Set correct permissions
    os.chmod(ENV_FILE, 0o640)
    os.chown(ENV_FILE, 0, os.getgrp("mcprack").gr_gid)  # root:mcprack
    
    click.echo("✅ Configuration initialized:")
    click.echo(f"   • SECRET_KEY generated and stored in {ENV_FILE}")
    click.echo(f"   • File permissions set to 0640 (root:mcprack)")
    click.echo("")
    
    # Try to restart service
    try:
        result = subprocess.run(
            ["systemctl", "restart", "mcprack"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            click.echo("✅ mcprack service restarted successfully")
            click.echo("")
            click.echo("Run 'systemctl status mcprack' to verify.")
        else:
            click.echo("⚠️  Failed to restart mcprack service:")
            click.echo(result.stderr)
            click.echo("   Run manually: systemctl restart mcprack")
    except subprocess.TimeoutExpired:
        click.echo("⚠️  Restart timed out. Run manually: systemctl restart mcprack")
    except FileNotFoundError:
        click.echo("⚠️  systemctl not found. Restart the service manually.")


def register_management_cli(app):
    app.cli.add_command(user_cli)
    app.cli.add_command(server_cli)
    app.cli.add_command(secret_cli)
    app.cli.add_command(init_config)
