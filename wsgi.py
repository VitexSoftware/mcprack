from werkzeug.middleware.proxy_fix import ProxyFix

from app import create_app

application = create_app()

# Trust one hop of X-Forwarded-Proto/-Host from the Apache reverse proxy in
# front of gunicorn, so url_for(..., _external=True) (e.g. the proxy/mcp
# URLs handed out to MCP clients) generates https:// URLs instead of http://
# - the Apache<->gunicorn hop itself is plain HTTP.
application.wsgi_app = ProxyFix(application.wsgi_app, x_proto=1, x_host=1)

# WSGI entry point for production servers (gunicorn, uWSGI, etc.)
# Do not call application.run() here - it enables debug mode.
# Use gunicorn or other WSGI application servers for production.
