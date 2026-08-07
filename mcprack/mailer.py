"""Minimal outbound-mail helper, used only for password-reset links.

Deliberately stdlib-only (smtplib/email) rather than pulling in Flask-Mail —
this is the one place mcprack sends email and it needs nothing beyond
"connect, optionally STARTTLS, optionally login, send".
"""

import smtplib
from email.message import EmailMessage

from flask import current_app


def smtp_configured():
    return bool(current_app.config["SMTP_HOST"])


def send_email(to_addr, subject, body):
    """Best-effort send. Returns True on success, False on any failure
    (logged, never raised) — callers must not let a broken mail server
    reveal whether an account/email exists."""
    cfg = current_app.config
    if not cfg["SMTP_HOST"]:
        current_app.logger.warning("send_email called but SMTP_HOST is not configured")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = to_addr
    msg.set_content(body)

    try:
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10) as smtp:
            if cfg["SMTP_USE_TLS"]:
                smtp.starttls()
            if cfg["SMTP_USERNAME"]:
                smtp.login(cfg["SMTP_USERNAME"], cfg["SMTP_PASSWORD"])
            smtp.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException):
        current_app.logger.exception("Failed to send email to %s", to_addr)
        return False
