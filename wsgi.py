from werkzeug.middleware.proxy_fix import ProxyFix

from mcprack.app import create_app

application = create_app()

# Trust one hop of X-Forwarded-For/-Proto/-Host from the Apache reverse
# proxy in front of gunicorn, so url_for(..., _external=True) (e.g. the
# proxy/mcp URLs handed out to MCP clients) generates https:// URLs instead
# of http:// - the Apache<->gunicorn hop itself is plain HTTP. x_for=1 also
# makes flask.request.remote_addr (and therefore audit.py's source_ip)
# reflect the real client IP instead of the proxy's own - this requires the
# reverse proxy to actually set X-Forwarded-For (see debian/apache-mcprack.conf)
# and gunicorn's bind address to be unreachable from anywhere except that
# proxy, since ProxyFix trusts this one hop unconditionally.
application.wsgi_app = ProxyFix(application.wsgi_app, x_for=1, x_proto=1, x_host=1)

# WSGI entry point for production servers (gunicorn, uWSGI, etc.)
# Do not call application.run() here - it enables debug mode.
# Use gunicorn or other WSGI application servers for production.
