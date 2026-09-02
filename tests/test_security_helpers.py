from __future__ import annotations

import io
import zipfile

import pytest
from PIL import Image
from werkzeug.datastructures import FileStorage

from app.security import (
    create_reset_token,
    digest_reset_token,
    hash_password,
    is_modern_password_hash,
    password_validation_error,
    remove_managed_file,
    save_profile_image,
    save_protected_document,
    verify_legacy_password,
    verify_modern_password,
)


def upload(name: str, content: bytes) -> FileStorage:
    return FileStorage(stream=io.BytesIO(content), filename=name)


def test_password_hashes_are_salted_and_verifiable():
    first = hash_password("StrongPassword123!")
    second = hash_password("StrongPassword123!")

    assert first != second
    assert is_modern_password_hash(first)
    assert verify_modern_password(first, "StrongPassword123!")
    assert not verify_modern_password(first, "wrong-password")


def test_legacy_password_is_verified_only_for_migration():
    legacy_hash = "a971f9009755b0987811c0fffb46e5ab6745ffaf10cfb4c80ae0e659d25c6004"
    assert verify_legacy_password(legacy_hash, "Admin123!", "1234abcd")
    assert not verify_legacy_password(legacy_hash, "wrong-password", "1234abcd")


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("Short1A", "at least"),
        ("alllowercase123", "uppercase"),
        ("ALLUPPERCASE123", "lowercase"),
        ("NoNumbersHere!", "number"),
    ],
)
def test_password_policy(password, expected):
    assert expected in password_validation_error(password)


def test_reset_tokens_are_random_and_only_digest_is_stored():
    first_token, first_digest = create_reset_token()
    second_token, second_digest = create_reset_token()

    assert first_token != second_token
    assert first_digest != second_digest
    assert digest_reset_token(first_token) == first_digest
    assert first_token != first_digest


def test_profile_image_is_content_checked_and_randomly_named(tmp_path):
    data = io.BytesIO()
    Image.new("RGB", (8, 8), color="navy").save(data, format="PNG")

    filename = save_profile_image(upload("avatar.jpg", data.getvalue()), str(tmp_path))

    assert filename.endswith(".png")
    assert (tmp_path / filename).is_file()


def test_profile_image_rejects_fake_image(tmp_path):
    with pytest.raises(ValueError, match="valid JPG"):
        save_profile_image(upload("avatar.png", b"<script>alert(1)</script>"), str(tmp_path))


def test_document_rejects_extension_spoofing(tmp_path):
    with pytest.raises(ValueError, match="does not match"):
        save_protected_document(upload("minutes.pdf", b"not a pdf"), str(tmp_path))


def test_document_accepts_valid_utf8_text(tmp_path):
    filename = save_protected_document(upload("minutes.txt", b"Lodge minutes\n"), str(tmp_path))

    assert filename.endswith(".txt")
    assert (tmp_path / filename).read_text() == "Lodge minutes\n"


def test_office_archive_must_match_declared_type(tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("[Content_Types].xml", "content")
        archive.writestr("word/document.xml", "document")

    filename = save_protected_document(upload("minutes.docx", data.getvalue()), str(tmp_path))
    assert (tmp_path / filename).is_file()


def test_managed_file_removal_cannot_escape_upload_directory(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    inside = protected / "inside.txt"
    outside = tmp_path / "outside.txt"
    inside.write_text("inside")
    outside.write_text("outside")

    remove_managed_file(str(protected), "../outside.txt")
    assert outside.is_file()

    remove_managed_file(str(protected), "inside.txt")
    assert not inside.exists()
