#!/usr/bin/env python3
"""Test to verify that url_for() detects HTTPS from X-Forwarded-Proto header"""

import sys
import json
sys.path.insert(0, '/home/vitex/Projects/VitexSoftware/mcprack')

from mcprack.app import create_app
from mcprack.extensions import db
from mcprack.models import User, McpServer, UserServerSelection

# Create app with test config
app = create_app()
app.config['TESTING'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

with app.app_context():
    db.create_all()
    
    # Create test user and server
    user = User(username='testuser', auth_type='local')
    user.set_password('pw')
    db.session.add(user)
    db.session.flush()
    
    # Add a stdio server that will get a proxy URL
    server = McpServer(
        name='testserver',
        label='Test Server',
        transport='stdio',
        command='echo test',
        enabled=True
    )
    db.session.add(server)
    db.session.flush()
    
    # User selects the server
    selection = UserServerSelection(user_id=user.id, server_id=server.id)
    db.session.add(selection)
    db.session.commit()

# Test 1: HTTP request (no X-Forwarded-Proto)
print("\n=== Test 1: HTTP request (no X-Forwarded-Proto) ===")
with app.test_client() as client:
    # Login
    client.post('/login', data={'username': 'testuser', 'password': 'pw'})
    
    # Get copilot config
    resp = client.get('/view/copilot')
    print(f"Status: {resp.status_code}")
    if resp.status_code == 200:
        body = resp.data.decode()
        # Find the URL in the HTML
        if 'config_json' in body:
            import re
            match = re.search(r'"url": "([^"]*proxy/mcp[^"]*)"', body)
            if match:
                url = match.group(1)
                print(f"Proxy URL scheme: {url.split('://')[0] if '://' in url else 'unknown'}")
                print(f"Full URL: {url}")

# Test 2: HTTPS request (with X-Forwarded-Proto: https)
print("\n=== Test 2: HTTPS request (with X-Forwarded-Proto: https) ===")
with app.test_client() as client:
    # Login
    client.post('/login', data={'username': 'testuser', 'password': 'pw'})
    
    # Get copilot config with HTTPS header
    resp = client.get('/view/copilot', headers={'X-Forwarded-Proto': 'https'})
    print(f"Status: {resp.status_code}")
    if resp.status_code == 200:
        body = resp.data.decode()
        # Find the URL in the HTML
        if 'config_json' in body:
            import re
            match = re.search(r'"url": "([^"]*proxy/mcp[^"]*)"', body)
            if match:
                url = match.group(1)
                print(f"Proxy URL scheme: {url.split('://')[0] if '://' in url else 'unknown'}")
                print(f"Full URL: {url}")

# Test 3: Check with ProxyFix middleware (like production)
print("\n=== Test 3: With ProxyFix middleware ===")
from werkzeug.middleware.proxy_fix import ProxyFix

app2 = create_app()
app2.config['TESTING'] = True
app2.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
# Apply ProxyFix like in wsgi.py
app2.wsgi_app = ProxyFix(app2.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

with app2.app_context():
    db.create_all()
    
    # Create test user and server
    user = User(username='testuser2', auth_type='local')
    user.set_password('pw')
    db.session.add(user)
    db.session.flush()
    
    # Add a stdio server that will get a proxy URL
    server = McpServer(
        name='testserver2',
        label='Test Server 2',
        transport='stdio',
        command='echo test',
        enabled=True
    )
    db.session.add(server)
    db.session.flush()
    
    # User selects the server
    selection = UserServerSelection(user_id=user.id, server_id=server.id)
    db.session.add(selection)
    db.session.commit()

with app2.test_client() as client:
    # Login
    client.post('/login', data={'username': 'testuser2', 'password': 'pw'})
    
    # Get copilot config with HTTPS header
    resp = client.get(
        '/view/copilot',
        headers={'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'example.com'}
    )
    print(f"Status: {resp.status_code}")
    if resp.status_code == 200:
        body = resp.data.decode()
        # Find the URL in the HTML
        if 'config_json' in body:
            import re
            match = re.search(r'"url": "([^"]*proxy/mcp[^"]*)"', body)
            if match:
                url = match.group(1)
                print(f"Proxy URL scheme: {url.split('://')[0] if '://' in url else 'unknown'}")
                print(f"Full URL: {url}")

print("\n=== Done ===")
