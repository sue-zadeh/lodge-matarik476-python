"""Regression coverage for password guidance and rejected form submissions."""

import re
from unittest.mock import MagicMock, patch

import pytest

from app.security import PASSWORD_REQUIREMENTS


def csrf_token(client, path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


@pytest.mark.parametrize(
    "path,allowed,data,initial_status",
    [
        ("/forgot-password", 3, {"email": "unregistered@example.test"}, 302),
        ("/login", 10, {"username": "unknown", "password": "SyntheticOnly123!"}, 302),
        ("/register", 5, {}, 200),
        (
            "/reset-password/synthetic-token", 5,
            {"new_password": "Short1", "confirm_password": "Short1"}, 200,
        ),
    ],
)
def test_rate_limit_preserves_form_and_gives_retry_instructions(
    client, path, allowed, data, initial_status
):
    connection = MagicMock()
    connection.cursor.return_value.fetchone.return_value = (
        {"user_id": 7} if path.startswith("/reset-password/") else None
    )
    with patch("app.views.get_db", return_value=connection) as database, patch(
        "app.views.send_password_reset_email"
    ) as send:
        data = {**data, "csrf_token": csrf_token(client, path)}
        for _ in range(allowed):
            assert client.post(path, data=data).status_code == initial_status

        database.reset_mock()
        send.reset_mock()
        response = client.post(path, data=data)
        html = response.get_data(as_text=True)

        assert response.status_code == 429
        assert 1 <= int(response.headers["Retry-After"]) <= 3602
        assert response.headers["Cache-Control"] == "no-store"
        assert "noindex" in response.headers["X-Robots-Tag"]
        assert '<nav ' in html
        assert 'id="rate-limit-notice"' in html
        assert "Please wait" in html
        assert '<form ' in html
        assert 'name="csrf_token"' in html
        assert "alert-auto-hide" not in re.search(
            r'<div id="rate-limit-notice"[^>]*>', html
        ).group(0)
        if path == "/forgot-password":
            assert "latest reset email" in html
            assert "A new request has not been sent." in html
            assert "Send Reset Link" in html
        elif path.startswith("/reset-password/"):
            assert "Your password has not been changed" in html
            assert 'name="new_password"' in html
        database.assert_not_called()
        send.assert_not_called()
        assert "SyntheticOnly123!" not in html
        assert "Short1" not in html

        # Reading the form does not consume another submission or require a redirect.
        assert client.get(path).status_code == 200


@pytest.mark.parametrize(
    "password,confirmation,error_field,error_message",
    [
        ("Short1", "Short1", "new_password", "Password must be at least 12 characters."),
        (
            "SyntheticReset123!", "DifferentReset123!",
            "confirm_password", "Passwords do not match.",
        ),
    ],
)
def test_reset_errors_are_next_to_the_field_and_do_not_change_password(
    client, password, confirmation, error_field, error_message
):
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = {"user_id": 7}
    with patch("app.views.get_db", return_value=connection):
        token = csrf_token(client, "/reset-password/synthetic-token")
        cursor.reset_mock()
        response = client.post(
            "/reset-password/synthetic-token",
            data={
                "csrf_token": token,
                "new_password": password,
                "confirm_password": confirmation,
            },
        )
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert PASSWORD_REQUIREMENTS in html
    assert f'id="{error_field}-error"' in html
    assert f'{error_field}-error"' in html
    assert 'aria-invalid="true"' in html
    assert error_message in html
    assert password not in html
    assert confirmation not in html
    assert not any(
        call.args[0].strip().upper().startswith("UPDATE")
        for call in cursor.execute.call_args_list
    )


def test_registration_short_password_has_visible_field_feedback(client):
    data = {
        "username": "synthetic_applicant",
        "first_name": "Test",
        "last_name": "Applicant",
        "email": "applicant@example.test",
        "address": "Synthetic address",
        "birth_date": "1990-01-02",
        "password": "Short1",
        "confirm_password": "Short1",
        "csrf_token": csrf_token(client, "/register"),
    }
    with patch("app.views.get_db") as database:
        response = client.post("/register", data=data)
        database.assert_not_called()
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert PASSWORD_REQUIREMENTS in html
    assert 'id="password-error"' in html
    assert "Password must be at least 12 characters." in html
    assert "Short1" not in html
