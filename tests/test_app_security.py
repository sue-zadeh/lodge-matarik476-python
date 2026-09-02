from __future__ import annotations

from unittest.mock import patch

from flask_wtf.csrf import generate_csrf, validate_csrf

from app import app
from app.views import escape_ics_text, send_email, send_password_reset_email


def test_security_headers_and_private_static_block(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    blocked = client.get("/static/files/private.txt")
    assert blocked.status_code == 404
    blocked_profile = client.get("/static/uploads/member.jpg")
    assert blocked_profile.status_code == 404
    assert client.get("/profiles/1/image").status_code == 404


def test_contact_page_uses_the_outlook_address(client):
    response = client.get("/contact")

    assert response.status_code == 200
    assert b'mailto:lodgematariki476@outlook.com' in response.data
    assert b'info@smartpanelhomes.co.nz' not in response.data


def test_post_without_csrf_token_is_rejected(client):
    response = client.post("/login", data={"username": "someone", "password": "Password123!"})
    assert response.status_code == 400


def test_generated_csrf_token_validates_with_configured_expiry():
    """Protect browser form submissions from CSRF expiry type regressions."""

    with app.test_request_context("/login"):
        token = generate_csrf()
        validate_csrf(token)


def test_contact_email_is_delivered_to_the_configured_outlook_address(monkeypatch):
    monkeypatch.setenv("EMAIL_USER", "technical-sender@example.test")
    monkeypatch.setenv("EMAIL_PASS", "synthetic-test-secret")
    monkeypatch.delenv("EMAIL_SUPPRESS_SEND", raising=False)
    app.config["CONTACT_EMAIL"] = "lodgematariki476@outlook.com"

    with patch("app.views.smtplib.SMTP_SSL") as smtp_class:
        smtp = smtp_class.return_value.__enter__.return_value
        send_email(
            subject="New enquiry from Lodge website",
            body="Synthetic message",
            name="Test Visitor",
            email="visitor@example.test",
            phone="+64 21 000 000",
        )

    sent_message = smtp.send_message.call_args.args[0]
    assert sent_message["To"] == "lodgematariki476@outlook.com"
    assert sent_message["From"] == "technical-sender@example.test"
    assert sent_message["Reply-To"] == "visitor@example.test"
    smtp.login.assert_called_once_with(
        "technical-sender@example.test", "synthetic-test-secret"
    )


def test_password_reset_email_goes_only_to_the_member(monkeypatch):
    monkeypatch.setenv("EMAIL_USER", "technical-sender@example.test")
    monkeypatch.setenv("EMAIL_PASS", "synthetic-test-secret")
    monkeypatch.delenv("EMAIL_SUPPRESS_SEND", raising=False)

    with patch("app.views.smtplib.SMTP") as smtp_class:
        smtp = smtp_class.return_value.__enter__.return_value
        send_password_reset_email(
            "member@example.test",
            "https://example.test/reset-password/synthetic-token",
        )

    sent_message = smtp.send_message.call_args.args[0]
    assert sent_message["To"] == "member@example.test"
    assert "synthetic-token" in sent_message.get_content()
    assert sent_message["To"] != app.config["CONTACT_EMAIL"]


def test_protected_page_redirects_anonymous_user(client):
    response = client.get("/admin/users")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_ics_text_cannot_inject_new_fields():
    escaped = escape_ics_text("Meeting\r\nATTENDEE:attacker@example.test,yes;no")
    assert "\r" not in escaped
    assert "\nATTENDEE" not in escaped
    assert "\\nATTENDEE" in escaped
    assert "\\," in escaped
    assert "\\;" in escaped
