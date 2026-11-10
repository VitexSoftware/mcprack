"""What a *user* may put into the environment of an MCP server process.

mcprack starts a stdio MCP server for each user and hands it an environment
that is the admin's configuration with the user's personal overrides layered
on top. Without a policy those overrides are an arbitrary-environment
primitive: variables such as ``NODE_OPTIONS``, ``LD_PRELOAD``,
``PYTHONPATH`` or ``PATH`` change *what code runs*, ``UV_INDEX_URL`` /
``NPM_CONFIG_REGISTRY`` change *where packages come from*, and the proxy and
CA-bundle variables put a third party between the server and its API
(docs/AUDIT-2026-11.md A-02).

The policy has three parts:

* a name must be an ordinary identifier;
* names in the process-altering families below are refused;
* values must be plain single-line strings of sane length.

Keys the **admin** declared on the server (plain config, secret names,
required keys, the auth key) are exempt from the denylist: the admin chose
them. In DEMO_MODE a user may additionally only set keys the server declares.
"""

import re

from flask import current_app

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

MAX_VALUE_LENGTH = 8192
MAX_KEYS = 100

# Exact names (compared upper-cased).
_DENIED_EXACT = frozenset(
    {
        # lookup / shell behaviour
        "PATH", "HOME", "SHELL", "USER", "LOGNAME", "IFS", "ENV", "BASH_ENV", "CDPATH", "GLOBIGNORE",
        "PS4", "PROMPT_COMMAND", "LOCPATH", "NLSPATH", "HOSTALIASES", "RES_OPTIONS", "TMPDIR", "TMP", "TEMP",
        "VIRTUAL_ENV", "CONDA_PREFIX",
        # trust store and proxying: puts a third party between the server and its API
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY", "WS_PROXY", "WSS_PROXY",
        # other runtimes
        "CLASSPATH", "PERL5OPT", "PERL5LIB", "PERLLIB", "RUBYOPT", "RUBYLIB", "PHPRC", "PHP_INI_SCAN_DIR",
        "GOPROXY", "GOFLAGS", "GOPATH", "GOROOT", "GOSUMDB", "GONOSUMDB", "GOPRIVATE",
        "KUBECONFIG",
        "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EXEC_PATH", "GIT_DIR", "GIT_WORK_TREE",
        "GIT_PROXY_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR", "GIT_TEMPLATE_DIR",
    }
)

# Whole families (compared upper-cased).
_DENIED_PREFIXES = (
    "LD_",  # dynamic linker: LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, ...
    "DYLD_",
    "MALLOC_",
    "GCONV",
    "PYTHON",  # PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONWARNINGS, ...
    "NODE_",  # NODE_OPTIONS, NODE_PATH, NODE_EXTRA_CA_CERTS, ...
    "NPM_",  # npm_config_registry etc. (case-insensitive)
    "YARN_",
    "PNPM_",
    "UV_",  # UV_INDEX_URL, UV_DEFAULT_INDEX, UV_PYTHON, ...
    "PIP_",
    "PIPX_",
    "CARGO_",
    "RUSTUP_",
    "GIT_CONFIG",
    "DOCKER_",
    "XDG_",
    "FASTMCP_",
    "JAVA_",
    "_JAVA_",
    "JDK_JAVA_",
    "DOTNET_",
    "COMPLUS_",
    "BUNDLE_",
    "GEM_",
    "COMPOSER_",
    "CGO_",
)

# Name fragments that mark a variable as "where do I connect" (A-09). Matched
# on whole underscore-separated words so API_KEY or HOSTILE are not caught.
_ENDPOINT_WORDS = frozenset(
    {"URL", "URI", "URLS", "HOST", "HOSTNAME", "HOSTS", "ENDPOINT", "INSTANCE", "SERVER", "BASE", "DOMAIN",
     "ADDR", "ADDRESS", "SITE", "ORIGIN", "GATEWAY"}
)
_CREDENTIAL_WORDS = frozenset(
    {"TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASS", "KEY", "PAT", "CREDENTIAL", "CREDENTIALS", "AUTH", "COOKIE"}
)


class EnvPolicyError(ValueError):
    """An override breaks the policy."""


def _is_denied(name):
    upper = name.upper()
    return upper in _DENIED_EXACT or upper.startswith(_DENIED_PREFIXES)


def check_key_name(name):
    """None when `name` is acceptable for a user-supplied variable, else a
    message the submitter can act on."""
    if not isinstance(name, str) or not _NAME_RE.match(name):
        return (
            f"'{name}' is not a valid variable name - use letters, digits and underscores, "
            "starting with a letter or underscore."
        )
    if _is_denied(name):
        return (
            f"The variable '{name}' is not allowed: it changes how the server process is started or "
            "where it connects. Ask an administrator to set it on the server instead."
        )
    return None


def check_value(name, value):
    """None when `value` is a plain single-line string of reasonable size."""
    if not isinstance(value, str):
        return f"The value for '{name}' must be a string."
    if len(value) > MAX_VALUE_LENGTH:
        return f"The value for '{name}' is too long (limit {MAX_VALUE_LENGTH} characters)."
    if any(ch in value for ch in ("\n", "\r", "\x00")):
        return f"The value for '{name}' must be a single line without control characters."
    return None


def admin_declared_keys(server):
    """Names the admin configured on `server` themselves."""
    keys = set(getattr(server, "env_config", None) or {})
    keys.update(getattr(server, "env_var_names", None) or [])
    keys.update(getattr(server, "required_env_keys", None) or [])
    if getattr(server, "auth_env_key", None):
        keys.add(server.auth_env_key)
    return keys


def is_endpoint_key(name):
    """Whether `name` says where the server connects (``ZABBIX_URL``,
    ``MASTODON_INSTANCE``, ``API_BASE_URL``, ...). Names that look like
    credentials are never endpoints."""
    words = set(name.upper().split("_"))
    if words & _CREDENTIAL_WORDS:
        return False
    return bool(words & _ENDPOINT_WORDS)


def _known_keys(server):
    from . import catalog  # local import: catalog imports this module

    return {item["key"] for item in catalog.get_server_known_keys(server)}


def validate_override(server, values, *, demo_mode=None):
    """Problems with a submitted override `{name: value}`, as a list of
    messages (empty when it is fine)."""
    if demo_mode is None:
        demo_mode = bool(current_app.config.get("DEMO_MODE"))

    errors = []
    if len(values) > MAX_KEYS:
        errors.append(f"Too many variables (limit {MAX_KEYS}).")
    declared = admin_declared_keys(server)
    known = _known_keys(server) if demo_mode else set()

    for name, value in values.items():
        if name in declared:
            problem = check_value(name, value)
        else:
            problem = check_key_name(name) or check_value(name, value)
            if not problem and demo_mode and name not in known:
                problem = f"On this demo instance only the variables the server declares can be set; '{name}' is not one."
        if problem:
            errors.append(problem)
    return errors


def require_valid_override(server, values):
    """Raise EnvPolicyError when `values` breaks the policy - the last line
    of defence for callers that did not validate on the way in."""
    errors = validate_override(server, values)
    if errors:
        raise EnvPolicyError(" ".join(errors))


def strip_denied(server, env):
    """`env` without user-supplied variables the policy forbids. Rows stored
    before the policy existed must not reach a process; admin-declared keys
    are kept. Returns (clean_env, dropped_names)."""
    declared = admin_declared_keys(server)
    clean, dropped = {}, []
    for name, value in env.items():
        if name not in declared and check_key_name(name):
            dropped.append(name)
        else:
            clean[name] = value
    return clean, dropped
