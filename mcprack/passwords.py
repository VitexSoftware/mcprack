"""One password policy for every way a password is set.

Applied by the self-service change, the e-mail reset, the admin UI, the REST
API, the CLI and `create-admin`. Before this an admin could create an account
with an empty password and log in with it, the API accepted one character and
the minimum was eight (docs/AUDIT-2026-11.md B-03; ASVS V2.1.1 asks for 12).

Length is the main control; the list below only catches the passwords that
are long enough to pass it and still the first thing anybody tries.
"""

from flask import current_app

DEFAULT_MIN_LENGTH = 12
MAX_LENGTH = 1024

_COMMON = frozenset(
    """
    password1234 password12345 password123456 passwordpassword passw0rd1234 p@ssw0rd1234 p@ssword1234
    administrator administrator1 admin1234567 adminadmin12 adminpassword welcome12345 welcome123456 letmein12345
    changeme1234 changeme12345 changemenow1 iloveyou1234 iloveyou12345 monkey123456 dragon123456 football1234
    baseball1234 trustno1trustno1 qwertyuiop12 qwertyuiop123 qwertyuiopas qwerty123456 qwerty1234567 1qaz2wsx3edc
    zaq12wsxcde3 abcdefghijkl abc123abc123 letmeinletmein mcprack12345 mcprackmcprack vitexsoftware spojenet12345
    """.split()
)

_SEQUENCES = (
    "01234567890123456789",
    "98765432109876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiopasdfghjklzxcvbnm",
)


def _min_length():
    return int(current_app.config.get("PASSWORD_MIN_LENGTH", DEFAULT_MIN_LENGTH))


def _is_run(text):
    """All one character, or a run taken from an obvious sequence."""
    if len(set(text)) == 1:
        return True
    return any(text in sequence for sequence in _SEQUENCES)


def check_strength(password, username=None):
    """None when `password` is acceptable, else a message for whoever set it."""
    if not isinstance(password, str) or not password.strip():
        return "The password must not be empty."
    minimum = _min_length()
    if len(password) < minimum:
        return f"The password must be at least {minimum} characters long."
    if len(password) > MAX_LENGTH:
        return f"The password must be at most {MAX_LENGTH} characters long."

    lowered = password.lower()
    if lowered in _COMMON or _is_run(lowered):
        return "That password is too common or too easy to guess. Choose a longer, less predictable one."
    if username:
        name = username.strip().lower()
        if name and (lowered == name or (len(name) >= 4 and name in lowered)):
            return "The password must not contain the username."
    return None
