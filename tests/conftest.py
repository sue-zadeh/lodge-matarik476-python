from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-that-is-long-enough")
os.environ.setdefault("SESSION_COOKIE_SECURE", "0")

import pytest

from app import app


@pytest.fixture()
def client(tmp_path):
    app.config.update(
        TESTING=True,
        FILE_UPLOAD_FOLDER=str(tmp_path / "protected"),
        UPLOAD_FOLDER=str(tmp_path / "uploads"),
    )
    return app.test_client()

