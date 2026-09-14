"""Create deterministic synthetic records for the Playwright suite."""

from __future__ import annotations

import os
from datetime import date, timedelta

from app.security import hash_password
from connect import get_db


ACCOUNTS = (
    ("e2e_admin", "E2E", "Admin", "e2e-admin@example.test", "AdminPass123!", "admin", True),
    ("e2e_member", "E2E", "Member", "e2e-member@example.test", "MemberPass123!", "member", True),
    ("e2e_pending", "E2E", "Pending", "e2e-pending@example.test", "PendingPass123!", "member", False),
    ("e2e_revocable", "E2E", "Revocable", "e2e-revocable@example.test", "RevocablePass123!", "member", True),
    ("e2e_reset", "E2E", "Reset", "e2e-reset@example.test", "ResetBefore123!", "member", True),
)


def main() -> None:
    protected_folder = os.environ["FILE_UPLOAD_FOLDER"]
    os.makedirs(protected_folder, exist_ok=True)

    connection = get_db()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "TRUNCATE event_reads, file_reads, events, files, contact_messages, "
            "admin_messages, users RESTART IDENTITY CASCADE"
        )
        for username, first, last, email, password, role, active in ACCOUNTS:
            cursor.execute(
                """
                INSERT INTO users (
                    username, first_name, last_name, email, password, phone,
                    address, birth_date, role, is_active
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    username,
                    first,
                    last,
                    email,
                    hash_password(password),
                    "+64 21 000 000",
                    "Synthetic E2E address",
                    date(1990, 1, 1),
                    role,
                    active,
                ),
            )

        cursor.execute("SELECT user_id FROM users WHERE username = 'e2e_admin'")
        admin_id = cursor.fetchone()[0]
        future_date = date.today() + timedelta(days=14)
        cursor.execute(
            """
            INSERT INTO events (
                title, description, event_date, start_time, location,
                is_admin_only, created_by
            ) VALUES
                ('Members E2E Event', 'Visible to members', %s, '18:30', 'Auckland', FALSE, %s),
                ('Private Admin E2E Event', 'Admins only', %s, '19:30', 'Private room', TRUE, %s)
            """,
            (future_date, admin_id, future_date, admin_id),
        )

        test_files = (
            ("Members E2E Document", "member-evidence.txt", False, b"member evidence\n"),
            ("Private Admin E2E Document", "admin-evidence.txt", True, b"admin evidence\n"),
        )
        for subject, filename, admin_only, content in test_files:
            with open(os.path.join(protected_folder, filename), "wb") as target:
                target.write(content)
            cursor.execute(
                """
                INSERT INTO files (subject, description, filename, uploaded_by, is_admin_only)
                VALUES (%s, 'Synthetic Playwright evidence', %s, %s, %s)
                """,
                (subject, filename, admin_id, admin_only),
            )

        connection.commit()
    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    main()
