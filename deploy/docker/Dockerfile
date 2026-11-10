FROM vitexsoftware/debian:trixie

# The base image's dpkg config excludes /usr/share/locale/* to save space,
# which silently strips mcprack's own cs/sk .mo translation catalogs on
# install (session-based locale switching then has nothing to load - the
# locale cookie gets set but the UI text never changes). Drop that exclusion
# rule before installing so mcprack's translations actually land on disk.
RUN sed -i '\#path-exclude /usr/share/locale/\*#d' /etc/dpkg/dpkg.cfg.d/docker

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        adduser \
        mcprack \
        python3-pymysql \
    && apt-get clean 

EXPOSE 8913

# Do not run the application - and every MCP server it spawns - as root. The
# mcprack package creates this user and owns /var/lib/mcprack
# (docs/AUDIT-2026-11.md C-03).
USER mcprack

ENTRYPOINT ["gunicorn", \
    "--bind", "127.0.0.1:8913", \
    "--workers", "4", \
    "--worker-class", "sync", \
    "--worker-tmp-dir", "/dev/shm", \
    "--timeout", "30", \
    "--chdir", "/usr/lib/mcprack", \
    "wsgi:application"]
