"""One authenticated, encrypted delivery path for contact and reset emails."""

import math
import os
import smtplib
import ssl
from contextlib import contextmanager

from app import app


@contextmanager
def authenticated_smtp():
    username = os.environ.get("EMAIL_USER", "").strip()
    password = os.environ.get("EMAIL_PASS", "")
    if not username or not password:
        raise RuntimeError("Set EMAIL_USER and EMAIL_PASS in the app environment.")
    try:
        timeout = float(os.environ.get("EMAIL_TIMEOUT_SECONDS", "10"))
    except ValueError:
        raise RuntimeError("EMAIL_TIMEOUT_SECONDS must be between 1 and 30.") from None
    if not math.isfinite(timeout) or not 1 <= timeout <= 30:
        raise RuntimeError("EMAIL_TIMEOUT_SECONDS must be between 1 and 30.")

    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465, timeout=timeout, context=ssl.create_default_context()
    ) as smtp:
        smtp.login(username, password)
        yield smtp, username


def deliver_email(message):
    if os.environ.get("EMAIL_SUPPRESS_SEND") == "1":
        if app.config["IS_PRODUCTION"]:
            raise RuntimeError("EMAIL_SUPPRESS_SEND must be 0 in production.")
        app.logger.info("Email delivery suppressed in this non-production environment.")
        return

    with authenticated_smtp() as (smtp, username):
        message["From"] = username
        smtp.send_message(message)
