# Docker deployment (public demo instance)

Runs mcprack from the same `.deb` package published on `repo.vitexsoftware.com`,
inside a container instead of a host-level systemd service. Intended for a
public-facing **demo** instance (`DEMO_MODE=true`) that sits behind an existing
reverse proxy on the same host, so a native `mcprack.service` install on that
host can be dedicated to a real, credentialed instance instead.

`network_mode: host` is deliberate: it lets the container reach a database
already listening on `localhost` (e.g. an existing MySQL demo DB) without any
port mapping or data migration, and keeps `gunicorn`'s own `--bind
127.0.0.1:8913` from colliding with a native `mcprack.service` on 8912 on the
same host.

## Setup

1. Provide an `env` file here with mcprack's usual `/etc/mcprack/env`
   variables (see main `README.md` / `debian/README.Debian`) — for a demo
   instance this normally means `DEMO_MODE=true` and no real Vaultwarden
   credentials.
2. `docker compose build && docker compose up -d`
3. Point the host's existing reverse proxy (Apache/nginx) at
   `http://localhost:8913/` instead of the native `mcprack.service` port.

`env` is intentionally not committed (host/secret specific) — see `.gitignore` in this directory.
