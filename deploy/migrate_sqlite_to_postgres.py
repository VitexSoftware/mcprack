#!/usr/bin/env python3
"""One-shot migration of an mcprack SQLite database to PostgreSQL.

Intended to be run ON THE TARGET HOST as root, with the mcprack service
STOPPED (the source SQLite file is copied live data; copying while the app
writes to it produces a torn snapshot).

What it does, in order:
1. Generates a random password and creates the `mcprack` role + `mcprack`
   database in the local PostgreSQL cluster (idempotent - safe to re-run).
2. Boots the mcprack app against the empty PostgreSQL database, which
   builds the full schema via db.create_all() + stamps Alembic to head
   (the standard bootstrap in mcprack/app.py).
3. Copies every table's rows from SQLite to PostgreSQL, parents before
   children so foreign keys hold, fixing boolean columns and id
   sequences on the way. Audit rows referencing since-deleted servers
   get their FK column nulled, matching the model's own
   ondelete="SET NULL" (server_name stays as the readable snapshot).
4. Verifies row counts match on every table.
5. ONLY THEN rewrites SQLALCHEMY_DATABASE_URI in /etc/mcprack/env
   (backing the file up first), so a failed migration leaves the host
   untouched. The SQLite file itself is never modified - reverting is
   just restoring the old env line.

The generated password is written only to /etc/mcprack/env (root-readable)
and to PostgreSQL itself - never to stdout or a log.

Usage:
    sudo systemctl stop mcprack
    sudo python3 migrate_sqlite_to_postgres.py --sqlite /var/lib/mcprack/mcprack.db
    sudo systemctl start mcprack
"""

import argparse
import os
import secrets
import subprocess
import sys
from datetime import datetime

ENV_FILE = "/etc/mcprack/env"
PG_HOST = "127.0.0.1"
PG_PORT = 5432
DB_NAME = "mcprack"
DB_USER = "mcprack"

# FK-safe copy order: every referenced table before its referencing tables.
TABLE_ORDER = [
    "config_templates",
    "users",
    "mcp_servers",
    "config_template_servers",
    "api_tokens",
    "user_server_selections",
    "user_server_overrides",
    "user_server_permissions",
    "audit_log_entries",
]


def parse_env_file(path):
    values = {}
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def write_env_file(path, values):
    with open(path) as fh:
        lines = fh.readlines()
    out = []
    replaced = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("SQLALCHEMY_DATABASE_URI="):
            out.append(f"SQLALCHEMY_DATABASE_URI={values['SQLALCHEMY_DATABASE_URI']}\n")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"SQLALCHEMY_DATABASE_URI={values['SQLALCHEMY_DATABASE_URI']}\n")
    with open(path, "w") as fh:
        fh.writelines(out)


def create_role_and_database(password):
    # Idempotent role creation with a password we never print.
    subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c",
         f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{DB_USER}') THEN "
         f"CREATE ROLE {DB_USER} LOGIN PASSWORD '{password}'; "
         f"ELSE ALTER ROLE {DB_USER} PASSWORD '{password}'; END IF; END $$;"],
        check=True,
    )
    exists = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-Atc",
         f"SELECT 1 FROM pg_database WHERE datname = '{DB_NAME}'"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if not exists:
        subprocess.run(["sudo", "-u", "postgres", "createdb", "-O", DB_USER, DB_NAME], check=True)


def pg_connect(uri):
    import psycopg2
    return psycopg2.connect(uri)


def table_columns(conn, table):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_name = %s",
            (table,),
        )
        return {name: dtype for name, dtype in cur.fetchall()}


def copy_table(conn, sqlite_path, table, log, dangling_fk_columns=None):
    import sqlite3
    import psycopg2.extras

    # Columns whose FK target rows may legitimately be gone (SQLite never
    # enforced foreign keys). The model declares these with
    # ondelete="SET NULL" - e.g. audit_log_entries keeps a denormalized
    # server_name so history stays readable after the McpServer row is
    # deleted - so nulling matches what the schema itself would have done.
    parent_ids = {}
    if dangling_fk_columns:
        lite = sqlite3.connect(sqlite_path)
        for column, parent in dangling_fk_columns.items():
            parent_ids[column] = {
                row[0] for row in lite.execute(f"SELECT id FROM {parent}")
            }
        lite.close()

    lite = sqlite3.connect(sqlite_path)
    lite.row_factory = sqlite3.Row
    lite_cols = [row[1] for row in lite.execute(f"PRAGMA table_info({table})")]
    pg_cols = table_columns(conn, table)
    common = [c for c in lite_cols if c in pg_cols]
    missing = [c for c in pg_cols if c not in lite_cols]
    if missing:
        log(f"  {table}: PG-only columns keep their default/NULL: {missing}")

    booleans = {c for c, dtype in pg_cols.items() if dtype == "boolean"}
    nullified = {c: 0 for c in (dangling_fk_columns or {})}

    rows = lite.execute(f"SELECT {', '.join(common)} FROM {table}").fetchall()
    converted = []
    for row in rows:
        record = dict(row)
        for col in booleans & set(common):
            value = record[col]
            if value is not None:
                record[col] = bool(value)
        for col, ids in parent_ids.items():
            if record[col] is not None and record[col] not in ids:
                record[col] = None
                nullified[col] += 1
        converted.append(tuple(record[c] for c in common))
    for col, count in nullified.items():
        if count:
            log(f"  {table}.{col}: {count} rows referenced a deleted {dangling_fk_columns[col]}"
                f" row - set to NULL (ondelete=SET NULL, name snapshot kept)")

    if converted:
        psycopg2.extras.execute_values(
            conn.cursor(),
            f"INSERT INTO {table} ({', '.join(common)}) VALUES %s",
            converted,
            page_size=1000,
        )
    lite.close()
    return len(converted)


def fix_sequence(conn, table):
    # Association tables (e.g. config_template_servers) use composite PKs
    # with no id column - nothing to advance there.
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = %s AND column_name = 'id'",
            (table,),
        )
        if not cur.fetchone():
            return
        cur.execute("SELECT pg_get_serial_sequence(%s, 'id')", (table,))
        seq = cur.fetchone()[0]
        if seq:
            cur.execute(
                f"SELECT setval('{seq}', COALESCE((SELECT MAX(id) FROM {table}), 0) + 1, false)"
            )


def count_rows(conn, table):
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        return cur.fetchone()[0]


def sqlite_count(path, table):
    import sqlite3
    lite = sqlite3.connect(path)
    try:
        return lite.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        lite.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite", default="/var/lib/mcprack/mcprack.db")
    parser.add_argument("--env-file", default=ENV_FILE)
    args = parser.parse_args()

    def log(msg):
        print(msg, flush=True)

    if subprocess.run(["systemctl", "is-active", "--quiet", "mcprack"]).returncode == 0:
        sys.exit("mcprack service is still running - stop it first, the source "
                 "database must not change mid-copy")

    env = parse_env_file(args.env_file)
    if not env.get("SECRET_KEY"):
        sys.exit("SECRET_KEY missing from the env file - refusing to boot the app")

    password = secrets.token_urlsafe(24)
    log("Creating/refreshing PostgreSQL role and database (password not shown)...")
    create_role_and_database(password)
    pg_uri = f"postgresql+psycopg2://{DB_USER}:{password}@{PG_HOST}:{PG_PORT}/{DB_NAME}"

    backup = f"{args.env_file}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}-prepostgres"
    log("PostgreSQL role/database ready (password not shown)")

    # Build the schema by booting the app against the empty database -
    # mcprack's own bootstrap does db.create_all() + Alembic stamp("head").
    # NOTE: the env file is deliberately rewritten only AFTER the copy and
    # the verification below succeed - a failed migration must leave the
    # host exactly as it was (service still pointed at SQLite).
    os.environ.update(env)
    os.environ["SQLALCHEMY_DATABASE_URI"] = pg_uri
    log("Bootstrapping schema on PostgreSQL (db.create_all + alembic stamp)...")
    if os.path.isdir("/usr/lib/mcprack"):
        # Debian install - the package lives outside site-packages.
        sys.path.insert(0, "/usr/lib/mcprack")
    from mcprack.app import create_app  # noqa: E402 - env must be set first
    from mcprack.config import Config  # noqa: E402

    app = create_app(Config)
    with app.app_context():
        pass  # create_all + stamp already ran inside create_app

    psycopg_uri = f"postgresql://{DB_USER}:{password}@{PG_HOST}:{PG_PORT}/{DB_NAME}"
    conn = pg_connect(psycopg_uri)
    conn.autocommit = False

    total_copied = 0
    try:
        for table in TABLE_ORDER:
            existing = count_rows(conn, table)
            if existing:
                sys.exit(f"PostgreSQL table {table} is not empty ({existing} rows) - "
                         "refusing to mix with migrated data; drop and recreate the database")
            log(f"Copying {table}...")
            dangling = {"user_id": "users", "server_id": "mcp_servers"} \
                if table == "audit_log_entries" else None
            copied = copy_table(conn, args.sqlite, table, log, dangling_fk_columns=dangling)
            fix_sequence(conn, table)
            total_copied += copied
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    log("Verifying row counts...")
    mismatches = []
    for table in TABLE_ORDER:
        src = sqlite_count(args.sqlite, table)
        dst = count_rows(conn, table)
        if src != dst:
            mismatches.append(f"{table}: sqlite={src} postgres={dst}")
    if mismatches:
        conn.rollback()
        sys.exit("Row count mismatch: " + "; ".join(mismatches))

    subprocess.run(["cp", args.env_file, backup], check=True)
    env["SQLALCHEMY_DATABASE_URI"] = pg_uri
    write_env_file(args.env_file, env)
    log(f"env file updated (backup: {backup})")
    log(f"All tables verified, {total_copied} rows migrated. PostgreSQL is now "
        f"the live database - start mcprack.")


if __name__ == "__main__":
    main()
