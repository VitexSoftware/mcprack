from app import create_app

application = create_app()

# WSGI entry point for production servers (gunicorn, uWSGI, etc.)
# Do not call application.run() here - it enables debug mode.
# Use gunicorn or other WSGI application servers for production.
