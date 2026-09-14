"""Read-only checks for email configuration and password-reset columns."""

import os

import click

from app.mail import authenticated_smtp
from connect import get_db


def register_diagnostics(app):
    @app.cli.command("mail-check")
    @click.option("--check-smtp", is_flag=True, help="Check SMTP login without sending an email.")
    def mail_check(check_smtp):
        problems = []
        for variable in ("EMAIL_USER", "EMAIL_PASS"):
            present = bool(os.environ.get(variable, "").strip())
            click.echo(f"{variable}: {'set' if present else 'MISSING'}")
            if not present:
                problems.append(f"Set {variable} in the environment used to run Flask.")

        suppressed = os.environ.get("EMAIL_SUPPRESS_SEND") == "1"
        click.echo(f"Email delivery: {'DISABLED' if suppressed else 'enabled'}")
        if suppressed:
            problems.append("Set EMAIL_SUPPRESS_SEND=0 to deliver real emails.")
        click.echo("SMTP connection: smtp.gmail.com:465 with verified TLS")
        if not os.environ.get("PUBLIC_BASE_URL", "").strip():
            click.echo("PUBLIC_BASE_URL: unset; reset links use the Azure hostname or local request URL.")
        else:
            click.echo("PUBLIC_BASE_URL: set; check that its domain and port match the app you are testing.")

        try:
            connection = get_db()
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """SELECT column_name FROM information_schema.columns
                           WHERE table_schema = current_schema() AND table_name = 'users'
                             AND column_name IN ('password_reset_token', 'password_reset_token_expiry')"""
                    )
                    columns = {row[0] for row in cursor.fetchall()}
            finally:
                connection.close()
            required = {"password_reset_token", "password_reset_token_expiry"}
            if columns == required:
                click.echo("Password-reset database columns: OK")
            else:
                problems.append("Apply migrations/20260902_add_password_reset_columns.sql to this database.")
                click.echo("Missing reset columns: " + ", ".join(sorted(required - columns)))
        except Exception as error:
            problems.append(f"Database connection/schema check failed ({type(error).__name__}). Check DB host, port and credentials.")

        if check_smtp and not suppressed:
            try:
                with authenticated_smtp():
                    click.echo("SMTP login: OK. No email was sent.")
            except Exception as error:
                problems.append(f"SMTP login failed ({type(error).__name__}). Check the Gmail sender credential and outbound port 465.")

        if problems:
            raise click.ClickException("\n".join(problems))
        click.echo("Checks passed. Reset emails go only to the email saved on an active member account.")
