import os


class Config:
    # Production settings by default
    DEBUG = False
    TESTING = False
    
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SQLALCHEMY_DATABASE_URI", "sqlite:////var/lib/mcprack/mcprack.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    LDAP_ENABLED = os.environ.get("LDAP_ENABLED", "false").lower() in ("true", "1", "yes")
    LDAP_SERVER = os.environ.get("LDAP_SERVER", "ldap://10.11.25.3:389")
    LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=spojent,dc=cz")
    LDAP_USER_OU = os.environ.get("LDAP_USER_OU", "ou=Users,dc=spojent,dc=cz")
    LDAP_USER_FILTER = os.environ.get("LDAP_USER_FILTER", "(sAMAccountName=%(user)s)")
    LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
    LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")

    BW_SERVER = os.environ.get("BW_SERVER", "")
    BW_CLIENTID = os.environ.get("BW_CLIENTID", "")
    BW_CLIENTSECRET = os.environ.get("BW_CLIENTSECRET", "")
    BW_PASSWORD = os.environ.get("BW_PASSWORD", "")
    BW_ITEM_PREFIX = os.environ.get("BW_ITEM_PREFIX", "MCP-")
    BW_COMMAND_TIMEOUT = float(os.environ.get("BW_COMMAND_TIMEOUT", "12"))
    BW_LOCK_TIMEOUT = float(os.environ.get("BW_LOCK_TIMEOUT", "8"))
    BITWARDENCLI_APPDATA_DIR = os.environ.get(
        "BITWARDENCLI_APPDATA_DIR", "/opt/mcprack/.bw"
    )
    BW_BIN = os.environ.get("BW_BIN", "/usr/bin/bw")
