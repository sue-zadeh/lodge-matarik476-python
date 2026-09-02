import os
import secrets
from datetime import timedelta

from flask import Flask, abort, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

environment = os.environ.get("APP_ENV", "development").strip().lower()
is_production = environment == "production" or bool(os.environ.get("WEBSITE_HOSTNAME"))
proxy_count = int(os.environ.get("TRUSTED_PROXY_COUNT", "1" if is_production else "0"))
if proxy_count:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=proxy_count,
        x_proto=proxy_count,
        x_host=proxy_count,
    )
secret_key = os.environ.get("SECRET_KEY")
if is_production and (not secret_key or len(secret_key) < 32):
    raise RuntimeError("SECRET_KEY must be set to at least 32 characters in production.")
app.config["SECRET_KEY"] = secret_key or secrets.token_hex(32)

def _configured_path(variable: str, default_path: str) -> str:
    configured = os.environ.get(variable, default_path)
    return configured if os.path.isabs(configured) else os.path.abspath(configured)


app.config.update(
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_production or os.environ.get("SESSION_COOKIE_SECURE") == "1",
    # Flask-WTF passes this value to itsdangerous as a number of seconds.
    # Using a timedelta breaks valid POSTs with newer itsdangerous releases.
    WTF_CSRF_TIME_LIMIT=2 * 60 * 60,
    UPLOAD_FOLDER=_configured_path(
        "UPLOAD_FOLDER", os.path.join(app.instance_path, "protected_profiles")
    ),
    FILE_UPLOAD_FOLDER=_configured_path(
        "FILE_UPLOAD_FOLDER", os.path.join(app.instance_path, "protected_files")
    ),
)

trusted_hosts = [host.strip() for host in os.environ.get("TRUSTED_HOSTS", "").split(",") if host.strip()]
if trusted_hosts:
    app.config["TRUSTED_HOSTS"] = trusted_hosts

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["FILE_UPLOAD_FOLDER"], exist_ok=True)

csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    headers_enabled=True,
)


@app.before_request
def block_legacy_public_file_directory():
    """Prevent Flask's static handler from bypassing protected download checks."""

    if request.path.startswith(("/static/files/", "/static/uploads/")):
        abort(404)


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://use.fontawesome.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "font-src 'self' data: https://use.fontawesome.com; "
        "connect-src 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint and request.endpoint not in {"static", "home", "about", "our_story"}:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    return "The form expired or was invalid. Please go back, refresh the page, and try again.", 400


@app.errorhandler(413)
def handle_file_too_large(_error):
    return "The uploaded file is too large. The maximum request size is 10 MB.", 413

# import routes so they register on the app
from app import views
