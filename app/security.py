"""Security helpers shared by authentication and upload routes."""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import secrets
import warnings
import zipfile
from pathlib import Path

from PIL import Image, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


PASSWORD_MIN_LENGTH = 12
PROFILE_IMAGE_MAX_BYTES = 5 * 1024 * 1024
DOCUMENT_MAX_BYTES = 10 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = 25_000_000

IMAGE_FORMAT_EXTENSIONS = {
    "JPEG": ".jpg",
    "PNG": ".png",
    "GIF": ".gif",
}
DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
}


def hash_password(password: str) -> str:
    """Create a modern, per-password salted hash."""

    return generate_password_hash(password, method="scrypt")


def verify_modern_password(stored_hash: str, password: str) -> bool:
    if not stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return False
    try:
        return check_password_hash(stored_hash, password)
    except (TypeError, ValueError):
        return False


def is_modern_password_hash(stored_hash: str) -> bool:
    return stored_hash.startswith(("scrypt:", "pbkdf2:"))


def verify_legacy_password(stored_hash: str, password: str, salt: str) -> bool:
    """Verify the old single-round SHA-256 format only for one-time migration."""

    candidate = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(stored_hash, candidate)


def password_validation_error(password: str) -> str | None:
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if not any(character.isupper() for character in password):
        return "Password must include an uppercase letter."
    if not any(character.islower() for character in password):
        return "Password must include a lowercase letter."
    if not any(character.isdigit() for character in password):
        return "Password must include a number."
    return None


def create_reset_token() -> tuple[str, str]:
    """Return a public one-time token and only the digest stored in the DB."""

    token = secrets.token_urlsafe(32)
    return token, digest_reset_token(token)


def digest_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _read_limited(upload, maximum_bytes: int) -> bytes:
    data = upload.stream.read(maximum_bytes + 1)
    upload.stream.seek(0)
    if not data:
        raise ValueError("The selected file is empty.")
    if len(data) > maximum_bytes:
        raise ValueError(f"The selected file is larger than {maximum_bytes // (1024 * 1024)} MB.")
    return data


def save_profile_image(upload, destination: str) -> str:
    data = _read_limited(upload, PROFILE_IMAGE_MAX_BYTES)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                image.verify()
                image_format = image.format
    except (Image.DecompressionBombError, Image.DecompressionBombWarning, UnidentifiedImageError, OSError) as exc:
        raise ValueError("Please upload a valid JPG, PNG, or GIF image.") from exc

    extension = IMAGE_FORMAT_EXTENSIONS.get(image_format or "")
    if not extension:
        raise ValueError("Please upload a valid JPG, PNG, or GIF image.")

    filename = f"{secrets.token_hex(16)}{extension}"
    os.makedirs(destination, exist_ok=True)
    with open(os.path.join(destination, filename), "xb") as target:
        target.write(data)
    return filename


def _valid_office_archive(extension: str, data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
    except (zipfile.BadZipFile, OSError):
        return False

    required_prefix = {
        ".docx": "word/",
        ".xlsx": "xl/",
        ".pptx": "ppt/",
    }[extension]
    return "[Content_Types].xml" in names and any(name.startswith(required_prefix) for name in names)


def _document_content_is_valid(extension: str, data: bytes) -> bool:
    if extension == ".pdf":
        return data.startswith(b"%PDF-")
    if extension in {".png", ".jpg", ".jpeg"}:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(data)) as image:
                    image.verify()
                    expected = "PNG" if extension == ".png" else "JPEG"
                    return image.format == expected
        except (Image.DecompressionBombError, Image.DecompressionBombWarning, UnidentifiedImageError, OSError):
            return False
    if extension in {".docx", ".xlsx", ".pptx"}:
        return _valid_office_archive(extension, data)
    if extension in {".doc", ".xls", ".ppt"}:
        return data.startswith(bytes.fromhex("D0CF11E0A1B11AE1"))
    if extension == ".txt":
        try:
            data.decode("utf-8")
            return b"\x00" not in data
        except UnicodeDecodeError:
            return False
    return False


def save_protected_document(upload, destination: str) -> str:
    original_name = secure_filename(upload.filename or "")
    extension = Path(original_name).suffix.lower()
    if extension not in DOCUMENT_EXTENSIONS:
        raise ValueError("This file type is not allowed.")

    data = _read_limited(upload, DOCUMENT_MAX_BYTES)
    if not _document_content_is_valid(extension, data):
        raise ValueError("The file content does not match its extension.")

    filename = f"{secrets.token_hex(16)}{extension}"
    os.makedirs(destination, exist_ok=True)
    with open(os.path.join(destination, filename), "xb") as target:
        target.write(data)
    return filename


def remove_managed_file(directory: str, filename: str | None) -> None:
    """Remove only a direct child of a configured upload directory."""

    if not filename or os.path.basename(filename) != filename:
        return
    path = os.path.join(directory, filename)
    if os.path.isfile(path):
        os.remove(path)
