from __future__ import annotations

import os
import re
from datetime import date, timedelta
from urllib.parse import urljoin

import pytest
from playwright.sync_api import Browser, Page, expect

from app.security import PASSWORD_REQUIREMENTS, digest_reset_token
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

    page.goto(url("/change_password"))
    expect(page.get_by_text(PASSWORD_REQUIREMENTS, exact=True)).to_be_visible()
    current = page.locator("#old_password")
    assert current.get_attribute("minlength") is None
    page.get_by_role("button", name="Show current password", exact=True).click()
    expect(current).to_have_attribute("type", "text")
    expect(page.locator("#new_password")).to_have_attribute("type", "password")
    page.get_by_role("button", name="Hide current password", exact=True).press("Enter")
    expect(current).to_have_attribute("type", "password")

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
    expect(page.get_by_text(PASSWORD_REQUIREMENTS, exact=True)).to_be_visible()
    password = page.locator("#password")
    confirmation = page.locator("#confirm_password")
    expect(password).to_have_attribute("minlength", "12")
    expect(password).to_have_attribute("aria-describedby", re.compile("password-help"))
    expect(confirmation).to_have_attribute("autocomplete", "new-password")
    page.get_by_role("button", name="Show password", exact=True).click()
    expect(password).to_have_attribute("type", "text")
    expect(confirmation).to_have_attribute("type", "password")
    page.get_by_role("button", name="Hide password", exact=True).press("Enter")
    expect(password).to_have_attribute("type", "password")
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


def test_contact_message_limit_and_counter(page: Page):
    page.goto(url("/contact"))
    message = page.get_by_role("textbox", name="Message", exact=True)
    expect(page.get_by_text("Maximum 500 characters.", exact=True)).to_be_visible()
    expect(page.locator("#messageCount")).to_have_text("0 / 500")
    expect(message).to_have_value("")
    message.fill("a" * 499)
    expect(page.locator("#messageCount")).to_have_text("499 / 500")
    message.press("b")
    message.press("c")
    expect(message).to_have_value("a" * 499 + "b")
    expect(page.locator("#messageCount")).to_have_text("500 / 500")
    message.fill("")
    expect(page.locator("#messageCount")).to_have_text("0 / 500")


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
    expect(page.get_by_text(PASSWORD_REQUIREMENTS, exact=True)).to_be_visible()
    password = page.locator("#new_password")
    confirmation = page.locator("#confirm_password")
    expect(password).to_have_attribute("aria-describedby", re.compile("new_password-help"))
    expect(password).to_have_attribute("minlength", "12")
    password.fill("ResetAfter456!")
    confirmation.fill("ResetAfter456!")

    show_new = page.get_by_role("button", name="Show new password", exact=True)
    show_new.click()
    expect(password).to_have_attribute("type", "text")
    expect(confirmation).to_have_attribute("type", "password")
    expect(show_new).to_have_count(0)
    hide_new = page.get_by_role("button", name="Hide new password", exact=True)
    expect(hide_new).to_have_attribute("aria-pressed", "true")
    page.get_by_role("button", name="Show confirm password", exact=True).press("Enter")
    expect(confirmation).to_have_attribute("type", "text")
    hide_new.click()
    expect(password).to_have_attribute("type", "password")
    expect(confirmation).to_have_attribute("type", "text")
    page.get_by_role("button", name="Hide confirm password", exact=True).press("Space")
    expect(confirmation).to_have_attribute("type", "password")
    expect(page).to_have_url(url(f"/reset-password/{reset_token}"))
    expect(password).to_have_value("ResetAfter456!")
    expect(confirmation).to_have_value("ResetAfter456!")
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


def test_forgot_password_rate_limit_keeps_page_and_countdown(page: Page):
    # Run after the reset journey. CI uses two workers with separate memory limits,
    # so seven submissions must exhaust the three-per-hour limit on one of them.
    page.clock.install()
    page.goto(url("/forgot-password"))
    for _ in range(7):
        page.locator("#email").fill("unknown-rate-limit@example.test")
        with page.expect_response(
            lambda response: response.request.method == "POST"
            and response.url == url("/forgot-password")
        ) as result:
            page.get_by_role("button", name="Send Reset Link").click()
        response = result.value
        if response.status == 429:
            break
        expect(page.get_by_text("If this email is registered", exact=False)).to_be_visible()
    assert response.status == 429
    wait_seconds = int(response.headers["retry-after"])
    expect(page).to_have_url(url("/forgot-password"))
    expect(page.get_by_role("navigation")).to_be_visible()
    expect(page.get_by_role("heading", name="Forgot Password", exact=True)).to_be_visible()
    expect(page.locator("#email")).to_be_visible()
    notice = page.locator("#rate-limit-notice")
    expect(notice).to_be_visible()
    expect(notice).to_contain_text("latest reset email")
    expect(notice).to_contain_text("A new request has not been sent.")

    # The warning must outlast normal flash alerts. Advancing the browser clock
    # checks the UI timer only; the server still enforces its real rate limit.
    page.clock.fast_forward(11_000)
    expect(notice).to_be_visible()
    posts = []
    page.on("request", lambda request: posts.append(request.url) if request.method == "POST" else None)
    page.clock.fast_forward(wait_seconds * 1000 + 2000)
    expect(page.locator("#rate-limit-wait")).to_have_text("You can try again now.")
    expect(notice).to_be_visible()
    expect(page).to_have_url(url("/forgot-password"))
    assert posts == []
