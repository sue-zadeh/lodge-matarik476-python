"""Interactively create the first active administrator without default credentials."""

from __future__ import annotations

from datetime import datetime
from getpass import getpass

from app.security import hash_password, password_validation_error
from connect import get_db


def required(prompt: str) -> str:
    value = input(prompt).strip()
    if not value:
        raise SystemExit(f"{prompt.rstrip(': ')} is required.")
    return value


def main() -> None:
    username = required("Username: ")
    if not 5 <= len(username) <= 80:
        raise SystemExit("Username must be between 5 and 80 characters.")
    first_name = required("First name: ")
    last_name = required("Last name: ")
    email = required("Email: ")
    address = required("Address: ")
    birth_date = required("Birth date (YYYY-MM-DD): ")
    try:
        datetime.strptime(birth_date, "%Y-%m-%d")
    except ValueError as error:
        raise SystemExit("Birth date must be a real date in YYYY-MM-DD format.") from error

    password = getpass("Password: ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    if error := password_validation_error(password):
        raise SystemExit(error)

    connection = get_db()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO users (
                username, first_name, last_name, email, password,
                address, birth_date, role, is_active
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'admin', TRUE)
            """,
            (username, first_name, last_name, email, hash_password(password), address, birth_date),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()

    print(f"Active administrator '{username}' created.")


if __name__ == "__main__":
    main()

