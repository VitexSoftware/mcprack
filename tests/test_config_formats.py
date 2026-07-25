from config_formats import render_claude_config, render_copilot_config

STDIO_SERVER = {
    "name": "webdriver",
    "transport": "stdio",
    "command": "/usr/bin/selenium-webdriver-mcp",
    "args": ["--headless"],
    "url": None,
    "auth_header_name": None,
    "auth_env_key": None,
    "env": {"SOME_VAR": "value"},
}

HTTP_SERVER = {
    "name": "jenkins",
    "transport": "http",
    "command": None,
    "args": [],
    "url": "https://jenkins.proxy.spojenet.cz/mcp-server/mcp",
    "auth_header_name": "Authorization",
    "auth_env_key": "AUTH_TOKEN",
    "env": {"AUTH_TOKEN": "secret-token"},
}


def test_claude_stdio_shape():
    result = render_claude_config([STDIO_SERVER])
    assert result == {
        "mcpServers": {
            "webdriver": {
                "type": "stdio",
                "command": "/usr/bin/selenium-webdriver-mcp",
                "args": ["--headless"],
                "env": {"SOME_VAR": "value"},
            }
        }
    }


def test_claude_http_shape():
    result = render_claude_config([HTTP_SERVER])
    assert result == {
        "mcpServers": {
            "jenkins": {
                "type": "http",
                "url": "https://jenkins.proxy.spojenet.cz/mcp-server/mcp",
                "headers": {"Authorization": "secret-token"},
            }
        }
    }
    # no stdio fields leaked into an http entry
    entry = result["mcpServers"]["jenkins"]
    assert "command" not in entry
    assert "args" not in entry


def test_copilot_stdio_shape_has_no_type_field():
    result = render_copilot_config([STDIO_SERVER])
    entry = result["servers"]["webdriver"]
    assert "type" not in entry
    assert entry["command"] == "/usr/bin/selenium-webdriver-mcp"
    assert entry["args"] == ["--headless"]
    assert entry["env"] == {"SOME_VAR": "value"}


def test_copilot_http_shape_requires_type():
    result = render_copilot_config([HTTP_SERVER])
    entry = result["servers"]["jenkins"]
    assert entry["type"] == "http"
    assert entry["url"] == "https://jenkins.proxy.spojenet.cz/mcp-server/mcp"
    assert entry["headers"] == {"Authorization": "secret-token"}


def test_mixed_selection_no_cross_contamination():
    result = render_claude_config([STDIO_SERVER, HTTP_SERVER])
    assert set(result["mcpServers"].keys()) == {"webdriver", "jenkins"}
    assert "url" not in result["mcpServers"]["webdriver"]
    assert "command" not in result["mcpServers"]["jenkins"]


def test_http_entry_without_auth_key_omits_headers():
    server = dict(HTTP_SERVER, env={})
    result = render_claude_config([server])
    assert "headers" not in result["mcpServers"]["jenkins"]


def test_stdio_server_with_url_renders_as_network_entry_not_local_spawn():
    """A stdio-implemented server proxied onto the network (e.g. via
    mcp_rack) must be handed to remote users as a network endpoint, never
    as a 'run this locally' command — url always wins over transport."""
    proxied_stdio = {
        "name": "zabbix-mcp-server",
        "transport": "stdio",
        "command": "/usr/bin/zabbix-mcp-server",
        "args": [],
        "url": "http://mcphost.spojenet.cz:3100/mcp/",
        "auth_header_name": "Authorization",
        "auth_env_key": "AUTH_TOKEN",
        "env": {"AUTH_TOKEN": "proxy-token"},
    }

    claude_result = render_claude_config([proxied_stdio])
    entry = claude_result["mcpServers"]["zabbix-mcp-server"]
    assert entry["type"] == "http"
    assert entry["url"] == "http://mcphost.spojenet.cz:3100/mcp/"
    assert entry["headers"] == {"Authorization": "proxy-token"}
    assert "command" not in entry
    assert "args" not in entry

    copilot_result = render_copilot_config([proxied_stdio])
    copilot_entry = copilot_result["servers"]["zabbix-mcp-server"]
    assert copilot_entry["type"] == "http"
    assert copilot_entry["url"] == "http://mcphost.spojenet.cz:3100/mcp/"


def test_stdio_server_without_url_still_renders_as_local_spawn():
    result = render_claude_config([STDIO_SERVER])
    entry = result["mcpServers"]["webdriver"]
    assert entry["type"] == "stdio"
    assert entry["command"] == "/usr/bin/selenium-webdriver-mcp"


def test_proxy_host_converts_stdio_to_http():
    """When proxy_host is set, stdio servers without a url become network entries."""
    mastodon = {
        "name": "mastodon",
        "transport": "stdio",
        "command": "/usr/bin/mastodon-mcp",
        "args": [],
        "url": None,
        "auth_header_name": None,
        "auth_env_key": None,
        "env": {"MASTODON_INSTANCE": "f.cz"},
    }
    
    # Without proxy: stdio entry
    local_result = render_copilot_config([mastodon], proxy_host=None)
    local_entry = local_result["servers"]["mastodon"]
    assert "type" not in local_entry
    assert local_entry["command"] == "/usr/bin/mastodon-mcp"
    
    # With proxy: http entry
    proxy_result = render_copilot_config([mastodon], proxy_host="10.11.182.99", proxy_port=3100)
    proxy_entry = proxy_result["servers"]["mastodon"]
    assert proxy_entry["type"] == "http"
    assert proxy_entry["url"] == "http://10.11.182.99:3100/mcp/"
    assert "command" not in proxy_entry


def test_proxy_host_does_not_override_explicit_urls():
    """Servers that already have a url should keep it, not be replaced by proxy_url."""
    jenkins = {
        "name": "jenkins",
        "transport": "http",
        "command": None,
        "args": [],
        "url": "https://jenkins.proxy.spojenet.cz/mcp-server/mcp",
        "auth_header_name": None,
        "auth_env_key": None,
        "env": {},
    }
    
    result = render_copilot_config([jenkins], proxy_host="10.11.182.99", proxy_port=3100)
    entry = result["servers"]["jenkins"]
    # Should keep its original URL, not be replaced
    assert entry["url"] == "https://jenkins.proxy.spojenet.cz/mcp-server/mcp"


def test_proxy_port_customization():
    """proxy_port parameter should be used in the generated URL."""
    server = {
        "name": "test",
        "transport": "stdio",
        "command": "test-cmd",
        "args": [],
        "url": None,
        "auth_header_name": None,
        "auth_env_key": None,
        "env": {},
    }
    
    result = render_copilot_config([server], proxy_host="10.11.182.99", proxy_port=3200)
    entry = result["servers"]["test"]
    assert entry["type"] == "http"
    assert entry["url"] == "http://10.11.182.99:3200/mcp/"
