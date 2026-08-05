"""Console entry point: `python -m mcprack` / the `mcprack` console script.

With no arguments, or arguments starting with "-", runs the Flask dev
server (dev/manual use only — production runs via gunicorn, see
wsgi.py / debian/mcprack.service):

    mcprack --host 0.0.0.0 --port 8913

Otherwise forwards to the Flask management CLI (see app.py/cli.py),
equivalent to `flask --app mcprack.app:create_app <command>`:

    mcprack user list
    mcprack create-admin
    mcprack db upgrade
"""

import sys

from flask.cli import FlaskGroup

from .app import create_app


def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("-"):
        args = ["run", *args]
    FlaskGroup(create_app=create_app).main(args=args, prog_name="mcprack")


if __name__ == "__main__":
    main()
