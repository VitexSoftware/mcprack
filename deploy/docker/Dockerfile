FROM debian:trixie-slim

# Requires vitexsoftware.gpg (the repo.vitexsoftware.com signing key) to be
# present in the build context — see README.md in this directory.
COPY vitexsoftware.gpg /usr/share/keyrings/vitexsoftware.gpg
RUN printf 'Types: deb\nURIs: https://repo.vitexsoftware.com/\nSuites: trixie\nComponents: main backports games\nSigned-By: /usr/share/keyrings/vitexsoftware.gpg\n' \
        > /etc/apt/sources.list.d/vitexsoftware.sources \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        mcprack \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8913

ENTRYPOINT ["gunicorn", \
    "--bind", "127.0.0.1:8913", \
    "--workers", "4", \
    "--worker-class", "sync", \
    "--worker-tmp-dir", "/dev/shm", \
    "--timeout", "30", \
    "--chdir", "/usr/lib/mcprack", \
    "wsgi:application"]
