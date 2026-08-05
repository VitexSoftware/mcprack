import json
from types import SimpleNamespace
from unittest.mock import patch

from mcprack import detection

LIST_UNITS_OUTPUT = (
    "mcp-rack-zabbix-mcp-server.service loaded active running MCP Rack - Zabbix MCP Server Proxy\n"
    "mcp-rack-warden-mcp.service loaded active running MCP Rack - Vaultwarden MCP Proxy\n"
)

ZABBIX_UNIT_TEXT = """[Unit]
Description=MCP Rack - Zabbix MCP Server Proxy
After=network.target
Requires=network.target

[Service]
Type=simple
User=mcp-rack
Group=mcp-rack
WorkingDirectory=/opt/mcp-rack

EnvironmentFile=/etc/default/mcp-rack

ExecStart=/opt/mcp-rack/bin/mcp-rack-run \\
  zabbix-mcp-server \\
  3100 \\
  0.0.0.0 \\
  /etc/mcp-rack/zabbix-mcp-server/mcp.json

Restart=on-failure
RestartSec=5
TimeoutStopSec=30

SyslogIdentifier=mcp-rack-zabbix-mcp-server

[Install]
WantedBy=multi-user.target
"""

WARDEN_UNIT_TEXT = ZABBIX_UNIT_TEXT.replace("Zabbix MCP Server", "Vaultwarden MCP").replace(
    "zabbix-mcp-server", "warden-mcp"
).replace("3100", "3106")


def _proc(stdout="", returncode=0):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr="")


def test_detect_mcp_rack_proxies_parses_units():
    def fake_run(args, **kwargs):
        if args[:2] == ["systemctl", "list-units"]:
            return _proc(stdout=LIST_UNITS_OUTPUT)
        if args[:2] == ["systemctl", "cat"]:
            unit = args[2]
            if "zabbix" in unit:
                return _proc(stdout=ZABBIX_UNIT_TEXT)
            if "warden" in unit:
                return _proc(stdout=WARDEN_UNIT_TEXT)
        return _proc(returncode=1)

    with patch("mcprack.detection.subprocess.run", side_effect=fake_run):
        with patch("mcprack.detection.socket.getfqdn", return_value="mcphost.spojenet.cz"):
            entries = detection.detect_mcp_rack_proxies()

    by_name = {e["name"]: e for e in entries}
    assert set(by_name) == {"zabbix-mcp-server", "warden-mcp"}
    assert by_name["zabbix-mcp-server"]["transport"] == "http"
    assert by_name["zabbix-mcp-server"]["url"] == "http://mcphost.spojenet.cz:3100/mcp"
    assert by_name["zabbix-mcp-server"]["label"] == "Zabbix MCP Server"
    assert by_name["warden-mcp"]["url"] == "http://mcphost.spojenet.cz:3106/mcp"


def test_detect_mcp_rack_proxies_empty_when_systemctl_missing():
    with patch("mcprack.detection.subprocess.run", side_effect=FileNotFoundError):
        entries = detection.detect_mcp_rack_proxies()
    assert entries == []


def test_detect_local_stdio_binaries_finds_known_tools_on_path():
    def fake_which(binary):
        return "/usr/bin/warden-mcp" if binary == "warden-mcp" else None

    with patch("mcprack.detection.shutil.which", side_effect=fake_which):
        entries = detection.detect_local_stdio_binaries()

    assert len(entries) == 1
    assert entries[0]["name"] == "warden-mcp"
    assert entries[0]["transport"] == "stdio"
    assert entries[0]["command"] == "/usr/bin/warden-mcp"
    assert entries[0]["args"] == ["--stdio"]


def test_detect_local_stdio_binaries_skips_already_named():
    with patch("mcprack.detection.shutil.which", return_value="/usr/bin/warden-mcp"):
        entries = detection.detect_local_stdio_binaries(already_named={"warden-mcp"})
    assert all(e["name"] != "warden-mcp" for e in entries)


def test_detect_local_stdio_binaries_skips_already_known_command_path():
    """Same binary, different catalog name (e.g. Claude config calls it
    'mastodon' while the fallback registry key is 'mastodon-mcp') should
    still be deduplicated — by resolved path, not just by name."""
    with patch("mcprack.detection.shutil.which", return_value="/usr/bin/mastodon-mcp"):
        entries = detection.detect_local_stdio_binaries(already_commands={"/usr/bin/mastodon-mcp"})
    assert all(e["name"] != "mastodon-mcp" for e in entries)


def test_detect_local_mcp_servers_combines_all_sources_without_duplicates():
    with patch("mcprack.detection.detect_from_claude_config", return_value=[]), \
         patch(
             "mcprack.detection.detect_mcp_rack_proxies",
             return_value=[{"name": "warden-mcp", "label": "x", "transport": "http", "url": "http://h:1/mcp", "category": "mcp-rack"}],
         ), \
         patch("mcprack.detection.shutil.which", return_value="/usr/bin/warden-mcp"):
        entries = detection.detect_local_mcp_servers()

    names = [e["name"] for e in entries]
    assert names.count("warden-mcp") == 1
    assert entries[0]["transport"] == "http"


def test_detect_local_mcp_servers_claude_config_entries_take_priority():
    claude_entry = {"name": "webdriver", "label": "webdriver", "transport": "stdio", "command": "/real/path", "args": [], "category": "claude-config"}
    with patch("mcprack.detection.detect_from_claude_config", return_value=[claude_entry]), \
         patch("mcprack.detection.detect_mcp_rack_proxies", return_value=[]), \
         patch("mcprack.detection.shutil.which", return_value="/wrong/guessed/path"):
        entries = detection.detect_local_mcp_servers()

    by_name = {e["name"]: e for e in entries}
    assert by_name["webdriver"]["command"] == "/real/path"


def test_detect_from_claude_config_parses_stdio_and_http_entries(tmp_path):
    config_path = tmp_path / "claude.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "webdriver": {"type": "stdio", "command": "mcp-server-webdriver", "args": []},
                    "zabbix-mcp-server": {
                        "type": "stdio",
                        "command": "uv",
                        "args": ["run", "--directory", "/checkout", "zabbix-mcp"],
                        "env": {"READ_ONLY": "false"},
                    },
                    "Jenkins": {
                        "type": "http",
                        "url": "https://jenkins.example.test/mcp",
                        "headers": {"Authorization": "Basic totally-secret-do-not-leak"},
                    },
                    "redmine-vitex": {"type": "http", "url": "http://127.0.0.1:3040/mcp"},
                }
            }
        )
    )

    entries = detection.detect_from_claude_config(path=str(config_path))
    by_name = {e["name"]: e for e in entries}

    assert set(by_name) == {"webdriver", "zabbix-mcp-server", "Jenkins", "redmine-vitex"}

    assert by_name["webdriver"]["transport"] == "stdio"
    assert by_name["webdriver"]["command"] == "mcp-server-webdriver"

    assert by_name["zabbix-mcp-server"]["command"] == "uv"
    assert by_name["zabbix-mcp-server"]["args"] == ["run", "--directory", "/checkout", "zabbix-mcp"]
    assert by_name["zabbix-mcp-server"]["env_var_names"] == ["READ_ONLY"]

    jenkins = by_name["Jenkins"]
    assert jenkins["transport"] == "http"
    assert jenkins["url"] == "https://jenkins.example.test/mcp"
    assert jenkins["auth_header_name"] == "Authorization"
    assert jenkins["auth_env_key"] == "AUTH_TOKEN"
    # the real secret header value must never appear anywhere in the entry
    dumped = json.dumps(jenkins)
    assert "totally-secret-do-not-leak" not in dumped

    assert by_name["redmine-vitex"]["transport"] == "http"
    assert "auth_header_name" not in by_name["redmine-vitex"]


def test_detect_from_claude_config_missing_file_returns_empty():
    assert detection.detect_from_claude_config(path="/nonexistent/path.json") == []


def test_detect_from_claude_config_malformed_json_returns_empty(tmp_path):
    bad = tmp_path / "claude.json"
    bad.write_text("{not valid json")
    assert detection.detect_from_claude_config(path=str(bad)) == []


def test_detect_from_claude_config_ignores_entries_without_command_or_url(tmp_path):
    config_path = tmp_path / "claude.json"
    config_path.write_text(json.dumps({"mcpServers": {"weird": {"type": "stdio"}}}))
    assert detection.detect_from_claude_config(path=str(config_path)) == []


def test_reachable_host_resolves_wildcard_bind_addresses():
    with patch("mcprack.detection.socket.getfqdn", return_value="myhost.example.cz"):
        assert detection._reachable_host("0.0.0.0") == "myhost.example.cz"
        assert detection._reachable_host("127.0.0.1") == "myhost.example.cz"
    assert detection._reachable_host("10.11.56.226") == "10.11.56.226"
