#!/usr/bin/env python3
"""Test to verify that url_for() detects HTTPS from X-Forwarded-Proto header"""

import sys
import os
import json
sys.path.insert(0, '/home/vitex/Projects/VitexSoftware/mcprack')

# Set SECRET_KEY before importing app
os.environ['SECRET_KEY'] = 'test-secret-key-for-development-purposes-only-64-chars-min'

from mcprack.app import create_app
from mcprack.extensions import db
from mcprack.models import User, McpServer, UserServerSelection
from werkzeug.middleware.proxy_fix import ProxyFix

# Set DATABASE_URL before creating app
import tempfile
db_fd, db_path = tempfile.mkstemp()
os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'

# Create app with test config
app = create_app()
app.config['TESTING'] = True

# Apply ProxyFix middleware to simulate HAProxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

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
        try:
            data = json.loads(resp.data)
            if 'servers' in data and 'testserver' in data['servers']:
                url = data['servers']['testserver'].get('url', 'NO URL')
                print(f"URL scheme: {url.split('://')[0] if '://' in url else 'INVALID'}")
                print(f"Full URL: {url}")
            else:
                print("No testserver in response")
                print(f"Response: {data}")
        except:
            print(f"Response: {resp.data}")

# Test 2: HTTPS request with X-Forwarded-Proto header
print("\n=== Test 2: HTTPS request with X-Forwarded-Proto: https ===")
with app.test_client() as client:
    # Login
    client.post('/login', data={'username': 'testuser', 'password': 'pw'})
    
    # Get copilot config with X-Forwarded-Proto header
    resp = client.get('/view/copilot', headers={'X-Forwarded-Proto': 'https'})
    print(f"Status: {resp.status_code}")
    if resp.status_code == 200:
        try:
            data = json.loads(resp.data)
            if 'servers' in data and 'testserver' in data['servers']:
                url = data['servers']['testserver'].get('url', 'NO URL')
                scheme = url.split('://')[0] if '://' in url else 'INVALID'
                print(f"URL scheme: {scheme}")
                print(f"Full URL: {url}")
                
                # Verify scheme is https
                if scheme == 'https':
                    print("✅ PASS: URL scheme is https as expected")
                else:
                    print(f"❌ FAIL: URL scheme is {scheme}, expected https")
            else:
                print("No testserver in response")
                print(f"Response: {data}")
        except Exception as e:
            print(f"Error parsing response: {e}")
            print(f"Response: {resp.data}")

# Test 3: Request with X-Forwarded-Host
print("\n=== Test 3: HTTPS request with X-Forwarded-Host: mcprack-dev.spojenet.cz ===")
with app.test_client() as client:
    # Login
    client.post('/login', data={'username': 'testuser', 'password': 'pw'})
    
    # Get copilot config with full HAProxy headers
    resp = client.get('/view/copilot', headers={
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'mcprack-dev.spojenet.cz',
        'X-Forwarded-For': '192.168.1.1'
    })
    print(f"Status: {resp.status_code}")
    if resp.status_code == 200:
        try:
            data = json.loads(resp.data)
            if 'servers' in data and 'testserver' in data['servers']:
                url = data['servers']['testserver'].get('url', 'NO URL')
                print(f"Full URL: {url}")
                
                # Check host
                if 'mcprack-dev.spojenet.cz' in url:
                    print("✅ PASS: Correct host in URL")
                else:
                    print(f"⚠️  WARNING: Host may not be mcprack-dev.spojenet.cz")
            else:
                print("No testserver in response")
        except Exception as e:
            print(f"Error parsing response: {e}")

print("\n=== Test Summary ===")
print("If Test 2 shows https scheme, ProxyFix is working correctly.")
print("If Test 3 shows correct host, X-Forwarded-Host is working correctly.")
