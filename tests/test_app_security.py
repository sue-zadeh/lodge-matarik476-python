from __future__ import annotations

from flask_wtf.csrf import generate_csrf, validate_csrf

from app import app
from app.views import escape_ics_text


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


def test_post_without_csrf_token_is_rejected(client):
    response = client.post("/login", data={"username": "someone", "password": "Password123!"})
    assert response.status_code == 400


def test_generated_csrf_token_validates_with_configured_expiry():
    """Protect browser form submissions from CSRF expiry type regressions."""

    with app.test_request_context("/login"):
        token = generate_csrf()
        validate_csrf(token)


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
