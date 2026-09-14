from datetime import datetime, timezone
from hashlib import sha256
import re
import ssl
from unittest.mock import MagicMock, patch

import psycopg2
import pytest

from app import app
from app.views import send_password_reset_email


def csrf_token(client, path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def configure_sender(monkeypatch):
    monkeypatch.setenv("EMAIL_USER", "sender@example.test")
    monkeypatch.setenv("EMAIL_PASS", "synthetic-only-password")
    monkeypatch.setenv("EMAIL_SUPPRESS_SEND", "0")
    monkeypatch.delenv("EMAIL_TIMEOUT_SECONDS", raising=False)


def test_reset_email_contains_the_committed_token_and_correct_local_port(client, monkeypatch):
    configure_sender(monkeypatch)
    monkeypatch.setenv("PUBLIC_BASE_URL", "")
    monkeypatch.delenv("WEBSITE_HOSTNAME", raising=False)
    monkeypatch.delenv("RESET_URL_SCHEME", raising=False)
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = {"user_id": 7, "email": "member@example.test"}

    with patch("app.views.get_db", return_value=connection), patch("app.mail.smtplib.SMTP_SSL") as smtp_class:
        smtp = smtp_class.return_value.__enter__.return_value

        def inspect_delivery(message):
            connection.commit.assert_called_once()
            connection.close.assert_called_once()
            assert message["To"] == "member@example.test"
            link = re.search(r"http://localhost:5000/reset-password/(\S+)", message.get_content())
            assert link is not None
            token = link.group(1)
            parameters = cursor.execute.call_args_list[1].args[1]
            assert parameters[0] == sha256(token.encode()).hexdigest()
            assert parameters[0] != token
            assert parameters[1] > datetime.now(timezone.utc)

        smtp.send_message.side_effect = inspect_delivery
        response = client.post(
            "/forgot-password", base_url="http://localhost:5000",
            data={"email": "member@example.test", "csrf_token": csrf_token(client, "/forgot-password")},
        )
        assert response.status_code == 302
        smtp.send_message.assert_called_once()
        smtp.login.assert_called_once_with("sender@example.test", "synthetic-only-password")
        assert smtp_class.call_args.args == ("smtp.gmail.com", 465)
        assert smtp_class.call_args.kwargs["timeout"] == 10
        context = smtp_class.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("failure", ["database", "smtp"])
def test_reset_failure_is_generic_and_logs_do_not_expose_secrets(client, monkeypatch, caplog, failure):
    configure_sender(monkeypatch)
    connection = MagicMock()
    connection.cursor.return_value.fetchone.return_value = {"user_id": 7, "email": "member@example.test"}
    with patch("app.views.get_db", return_value=connection) as database, patch("app.mail.smtplib.SMTP_SSL") as smtp:
        if failure == "database":
            database.side_effect = psycopg2.errors.UndefinedColumn("private-diagnostic-secret")
        else:
            smtp.side_effect = TimeoutError("private-diagnostic-secret")
        response = client.post(
            "/forgot-password", follow_redirects=True,
            data={"email": "member@example.test", "csrf_token": csrf_token(client, "/forgot-password")},
        )
    assert response.status_code == 200
    assert b"If this email is registered and active" in response.data
    assert "mail-check" in caplog.text
    assert "private-diagnostic-secret" not in caplog.text
    assert "member@example.test" not in caplog.text
    assert "synthetic-only-password" not in caplog.text


def test_unknown_or_inactive_email_does_not_send_mail(client):
    connection = MagicMock()
    connection.cursor.return_value.fetchone.return_value = None
    with patch("app.views.get_db", return_value=connection), patch("app.views.send_password_reset_email") as send:
        response = client.post(
            "/forgot-password", follow_redirects=True,
            data={"email": "unknown@example.test", "csrf_token": csrf_token(client, "/forgot-password")},
        )
    assert b"If this email is registered and active" in response.data
    send.assert_not_called()
    assert "is_active" in connection.cursor.return_value.execute.call_args.args[0]


@pytest.mark.parametrize("length, accepted", [(499, True), (500, True), (501, False)])
def test_contact_message_limit_is_enforced_before_database_and_email(client, length, accepted):
    with patch("app.views.getCursor", return_value=(MagicMock(), MagicMock())) as database, patch("app.views.send_email") as send:
        response = client.post(
            "/contact", follow_redirects=True,
            data={"name": "Test Visitor", "email": "visitor@example.test", "message": "a" * length,
                  "csrf_token": csrf_token(client, "/contact")},
        )
    assert response.status_code == 200
    assert database.called is accepted
    assert send.called is accepted
    if not accepted:
        assert b"Message must be 500 characters or less." in response.data


def test_missing_sender_credentials_fail_without_network_access(monkeypatch):
    monkeypatch.setenv("EMAIL_SUPPRESS_SEND", "0")
    monkeypatch.delenv("EMAIL_PASS", raising=False)
    with patch("app.mail.smtplib.SMTP_SSL") as smtp, pytest.raises(RuntimeError, match="EMAIL_USER and EMAIL_PASS"):
        send_password_reset_email("member@example.test", "https://example.test/reset-password/test")
    smtp.assert_not_called()


def test_production_cannot_silently_suppress_email(monkeypatch):
    monkeypatch.setenv("EMAIL_SUPPRESS_SEND", "1")
    monkeypatch.setitem(app.config, "IS_PRODUCTION", True)
    with pytest.raises(RuntimeError, match="must be 0"):
        send_password_reset_email("member@example.test", "https://example.test/reset-password/test")


def test_mail_check_reports_missing_columns_without_exposing_credentials(monkeypatch):
    configure_sender(monkeypatch)
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchall.return_value = []
    with patch("app.diagnostics.get_db", return_value=connection), patch("app.mail.smtplib.SMTP_SSL") as smtp:
        result = app.test_cli_runner().invoke(args=["mail-check"])
    assert result.exit_code == 1
    assert "20260902_add_password_reset_columns.sql" in result.output
    assert "synthetic-only-password" not in result.output
    assert "sender@example.test" not in result.output
    smtp.assert_not_called()
