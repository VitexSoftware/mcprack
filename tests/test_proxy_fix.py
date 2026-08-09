#!/usr/bin/env python3
"""Simple test to verify ProxyFix detects HTTPS correctly"""

import sys
from unittest.mock import Mock
sys.path.insert(0, '/home/vitex/Projects/VitexSoftware/mcprack')

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.test import EnvironBuilder
from flask import Flask, request, url_for

def test_proxy_fix_https_detection():
    """Test that ProxyFix correctly detects HTTPS from X-Forwarded-Proto"""
    
    # Create a minimal Flask app
    app = Flask(__name__)
    app.secret_key = 'test-key'
    
    # Add a simple route
    @app.route('/test')
    def test_route():
        return {
            'scheme': request.scheme,
            'is_secure': request.is_secure,
            'host': request.host,
            'url_for': url_for('test_route', _external=True)
        }
    
    # Apply ProxyFix exactly like mcprack does in wsgi.py
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    print("\n=== Testing ProxyFix HTTPS Detection ===\n")
    
    # Test 1: Plain HTTP (no X-Forwarded headers)
    print("Test 1: Plain HTTP request (no X-Forwarded-Proto)")
    with app.test_client() as client:
        response = client.get('/test')
        data = response.get_json()
        print(f"  scheme: {data['scheme']}")
        print(f"  is_secure: {data['is_secure']}")
        print(f"  url_for result: {data['url_for']}")
        assert data['scheme'] == 'http', f"Expected scheme 'http', got '{data['scheme']}'"
        assert data['is_secure'] is False
        assert 'http://' in data['url_for']
        print("  ✅ PASS: Plain HTTP detected correctly\n")
    
    # Test 2: HTTPS with X-Forwarded-Proto header
    print("Test 2: HTTPS request with X-Forwarded-Proto: https")
    with app.test_client() as client:
        response = client.get('/test', headers={'X-Forwarded-Proto': 'https'})
        data = response.get_json()
        print(f"  scheme: {data['scheme']}")
        print(f"  is_secure: {data['is_secure']}")
        print(f"  url_for result: {data['url_for']}")
        assert data['scheme'] == 'https', f"Expected scheme 'https', got '{data['scheme']}'"
        assert data['is_secure'] is True, "Expected is_secure=True"
        assert 'https://' in data['url_for'], f"Expected https:// in URL, got {data['url_for']}"
        print("  ✅ PASS: HTTPS detected correctly from X-Forwarded-Proto\n")
    
    # Test 3: HTTPS with all HAProxy headers
    print("Test 3: HTTPS with full HAProxy headers")
    with app.test_client() as client:
        response = client.get('/test', headers={
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Host': 'mcprack-dev.spojenet.cz',
            'X-Forwarded-For': '192.168.1.1'
        })
        data = response.get_json()
        print(f"  scheme: {data['scheme']}")
        print(f"  host: {data['host']}")
        print(f"  url_for result: {data['url_for']}")
        assert data['scheme'] == 'https'
        assert 'mcprack-dev.spojenet.cz' in data['url_for'], f"Expected mcprack-dev.spojenet.cz in URL, got {data['url_for']}"
        print("  ✅ PASS: Full HAProxy headers processed correctly\n")
    
    print("\n=== Summary ===")
    print("✅ All ProxyFix tests PASSED!")
    print("\nConclusion:")
    print("- ProxyFix is working correctly with X-Forwarded-Proto")
    print("- request.is_secure changes based on X-Forwarded-Proto header")
    print("- url_for() correctly uses HTTPS scheme when is_secure=True")
    print("\nThis means:")
    print("- The wsgi.py ProxyFix configuration is correct")
    print("- HAProxy headers should reach Flask correctly")
    print("- url_for() in catalog.py should generate correct HTTPS URLs")
    print("\nIf production is still returning HTTP URLs, the issue may be:")
    print("1. Debug logs show X-Forwarded-Proto is NOT being set by HAProxy")
    print("2. ProxyFix middleware is not applied (check wsgi.py)")
    print("3. app.wsgi_app is not the right object (check wsgi.py line 1-30)")

if __name__ == '__main__':
    test_proxy_fix_https_detection()
