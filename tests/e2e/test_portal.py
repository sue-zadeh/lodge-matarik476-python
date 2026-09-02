from __future__ import annotations

import os
from datetime import date, timedelta
from urllib.parse import urljoin

import pytest
from playwright.sync_api import Browser, Page, expect

from app.security import digest_reset_token
from connect import get_db


pytestmark = pytest.mark.e2e
BASE_URL = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8000")


def url(path: str) -> str:
    return urljoin(f"{BASE_URL}/", path.lstrip("/"))


def login(page: Page, username: str, password: str) -> None:
    page.goto(url("/login"))
    page.locator("form[action$='/login'] input[name='username']").fill(username)
    page.locator("form[action$='/login'] input[name='password']").fill(password)
    page.locator("form[action$='/login'] button[type='submit']").click()


def logout(page: Page) -> None:
    page.locator("form[action$='/logout'] button[type='submit']").click()
    expect(page).to_have_url(url("/login"))


def test_authentication_authorization_and_session_journey(page: Page):
    page.goto(url("/admin/users"))
    expect(page).to_have_url(url("/login"))

    login(page, "e2e_pending", "PendingPass123!")
    expect(page).to_have_url(url("/login"))
    expect(page.get_by_text("Invalid username or password.")).to_be_visible()

    login(page, "e2e_member", "MemberPass123!")
    expect(page).to_have_url(url("/member/home"))
    expect(page.get_by_text("Member", exact=True)).to_be_visible()

    page.goto(url("/admin/users"))
    expect(page).to_have_url(url("/login"))

    login(page, "e2e_admin", "AdminPass123!")
    expect(page).to_have_url(url("/admin/home"))
    expect(page.get_by_text("Admin Dashboard", exact=True)).to_be_visible()
    page.goto(url("/admin/users"))
    expect(page.get_by_text("Manage Users", exact=True)).to_be_visible()
    logout(page)


def test_public_registration_requires_admin_approval(page: Page):
    page.goto(url("/register"))
    page.locator("input[name='username']").fill("e2e_new_member")
    page.locator("input[name='first_name']").fill("New")
    page.locator("input[name='last_name']").fill("Applicant")
    page.locator("input[name='email']").fill("new-applicant@example.test")
    page.locator("input[name='phone']").fill("+64 21 123 456")
    page.locator("input[name='address']").fill("Synthetic registration address")
    page.locator("input[name='birth_date']").fill("1991-02-03")
    page.locator("input[name='password']").fill("ApplicantPass123!")
    page.locator("input[name='confirm_password']").fill("ApplicantPass123!")
    page.locator("form[action$='/register'] button[type='submit']").click()

    expect(page).to_have_url(url("/login"))
    expect(page.get_by_text("An administrator must activate the account", exact=False)).to_be_visible()

    login(page, "e2e_new_member", "ApplicantPass123!")
    expect(page).to_have_url(url("/login"))
    expect(page.get_by_text("Invalid username or password.")).to_be_visible()


def test_contact_form_uses_outlook_and_saves_a_valid_message(page: Page):
    page.goto(url("/contact"))
    email_link = page.locator("a[href='mailto:lodgematariki476@outlook.com']")
    expect(email_link).to_have_text("lodgematariki476@outlook.com")

    page.locator("input[name='name']").fill("Synthetic Visitor")
    page.locator("input[name='email']").fill("visitor@example.test")
    page.locator("input[name='phone']").fill("+64 21 000 001")
    page.locator("textarea[name='message']").fill("Synthetic contact message")
    page.locator("form#contactForm button[type='submit']").click()

    expect(page.get_by_text("your message has been sent", exact=False)).to_be_visible()

    connection = get_db()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT name, email, message FROM contact_messages WHERE email = %s",
            ("visitor@example.test",),
        )
        assert cursor.fetchone() == (
            "Synthetic Visitor",
            "visitor@example.test",
            "Synthetic contact message",
        )
    finally:
        cursor.close()
        connection.close()


def test_forgot_and_reset_password_with_real_database(page: Page):
    page.goto(url("/forgot-password"))
    page.locator("input[name='email']").fill("e2e-reset@example.test")
    page.get_by_role("button", name="Send Reset Link").click()
    expect(page.get_by_text("If this email is registered", exact=False)).to_be_visible()

    reset_token = "synthetic-known-reset-token"
    connection = get_db()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT password_reset_token,
                   password_reset_token_expiry > NOW()
            FROM users
            WHERE username = 'e2e_reset'
            """
        )
        stored_digest, is_unexpired = cursor.fetchone()
        assert stored_digest is not None
        assert len(stored_digest) == 64
        assert is_unexpired is True

        cursor.execute(
            """
            UPDATE users
            SET password_reset_token = %s,
                password_reset_token_expiry = NOW() + INTERVAL '1 hour'
            WHERE username = 'e2e_reset'
            """,
            (digest_reset_token(reset_token),),
        )
        connection.commit()
    finally:
        cursor.close()
        connection.close()

    page.goto(url(f"/reset-password/{reset_token}"))
    page.locator("input[name='new_password']").fill("ResetAfter456!")
    page.locator("input[name='confirm_password']").fill("ResetAfter456!")
    page.get_by_role("button", name="Reset Password").click()

    expect(page).to_have_url(url("/login"))
    expect(page.get_by_text("reset successfully", exact=False)).to_be_visible()
    login(page, "e2e_reset", "ResetAfter456!")
    expect(page).to_have_url(url("/member/home"))


def test_member_file_and_event_boundaries(page: Page):
    login(page, "e2e_member", "MemberPass123!")
    expect(page).to_have_url(url("/member/home"))

    page.goto(url("/member/files"))
    expect(page.get_by_text("Members E2E Document", exact=True)).to_be_visible()
    expect(page.get_by_text("Private Admin E2E Document", exact=True)).to_have_count(0)

    members_link = page.locator("tr", has_text="Members E2E Document").locator("a[href*='/download']")
    members_href = members_link.get_attribute("href")
    assert members_href
    allowed = page.context.request.get(url(members_href))
    assert allowed.status == 200
    assert "attachment" in allowed.headers["content-disposition"]

    denied = page.context.request.get(url("/files/2/download"))
    assert denied.status == 404

    page.goto(url("/member/calendar"))
    expect(page.get_by_text("Members E2E Event", exact=True)).to_be_visible()
    expect(page.get_by_text("Private Admin E2E Event", exact=True)).to_have_count(0)
    assert page.context.request.get(url("/member/events/2/ics")).status == 404
    assert page.context.request.get(url("/member/events/2/google")).status == 404


def test_admin_event_file_workflows_and_output_escaping(page: Page, tmp_path):
    login(page, "e2e_admin", "AdminPass123!")
    expect(page).to_have_url(url("/admin/home"))

    page.goto(url("/admin/events"))
    create_form = page.locator("form").filter(has=page.locator("input[name='title']")).first
    create_form.locator("input[name='title']").fill("E2E Created Event")
    create_form.locator("input[name='location']").fill("Test Hall")
    create_form.locator("input[name='event_date']").fill((date.today() + timedelta(days=21)).isoformat())
    create_form.locator("input[name='start_time']").fill("18:00")
    create_form.locator("textarea[name='description']").fill("<img src=x onerror=window.__xssTriggered=1>")
    create_form.locator("button").filter(has_text="Create Event").click()

    expect(page.get_by_text("Event created.")).to_be_visible()
    expect(page.get_by_text("E2E Created Event", exact=True)).to_be_visible()
    assert page.evaluate("window.__xssTriggered") is None

    evidence_file = tmp_path / "e2e-minutes.txt"
    evidence_file.write_text("Synthetic Lodge minutes\n")
    page.goto(url("/admin/files"))
    upload_form = page.locator("form[enctype='multipart/form-data']")
    upload_form.locator("input[name='subject']").fill("E2E Uploaded Minutes")
    upload_form.locator("textarea[name='description']").fill("Synthetic test document")
    upload_form.locator("input[name='file']").set_input_files(str(evidence_file))
    upload_form.locator("button[type='submit']").click()

    expect(page.get_by_text("File uploaded successfully.")).to_be_visible()
    expect(page.get_by_text("E2E Uploaded Minutes", exact=True)).to_be_visible()


def test_csrf_headers_and_legacy_static_file_block(page: Page):
    response = page.context.request.get(url("/"))
    assert response.status == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

    no_csrf = page.context.request.post(
        url("/login"),
        form={"username": "e2e_admin", "password": "AdminPass123!"},
    )
    assert no_csrf.status == 400
    assert page.context.request.get(url("/static/files/admin-evidence.txt")).status == 404
    assert page.context.request.get(url("/static/uploads/member.jpg")).status == 404


def test_deactivated_account_loses_existing_session_immediately(browser: Browser):
    member_context = browser.new_context()
    admin_context = browser.new_context()
    member_page = member_context.new_page()
    admin_page = admin_context.new_page()
    try:
        login(member_page, "e2e_revocable", "RevocablePass123!")
        expect(member_page).to_have_url(url("/member/home"))

        login(admin_page, "e2e_admin", "AdminPass123!")
        admin_page.goto(url("/admin/users"))
        user_card = admin_page.locator(".card", has_text="e2e_revocable")
        admin_page.once("dialog", lambda dialog: dialog.accept())
        user_card.get_by_role("button", name="Deactivate").click()
        expect(admin_page.get_by_text("User status updated.")).to_be_visible()

        member_page.goto(url("/member/files"))
        expect(member_page).to_have_url(url("/login"))
        expect(member_page.get_by_text("session is no longer active", exact=False)).to_be_visible()
    finally:
        member_context.close()
        admin_context.close()
