# connect.py
import os
import psycopg2
from urllib.parse import urlparse

def get_db():
    """
    Railway: use DATABASE_URL (recommended)
    Local/Docker: fallback to DB_* vars
    """

    database_url = os.environ.get("DATABASE_URL")

    # --- 1) Railway / Production ---
    if database_url:
        # DATABASE_URL might be internal or public.
        # If it's public proxy (shuttle.proxy.rlwy.net) you may need SSL.
        parsed = urlparse(database_url)

        host = parsed.hostname
        port = parsed.port or 5432
        user = parsed.username
        password = parsed.password
        dbname = parsed.path.lstrip("/")

        # SSL only needed for PUBLIC proxy URL typically
        # internal host: postgres.railway.internal usually does not need sslmode=require
        use_ssl = ("shuttle.proxy.rlwy.net" in (host or "")) or ("proxy.rlwy.net" in (host or ""))

        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=dbname,
            sslmode="require" if use_ssl else "prefer"
        )
        return conn

    # --- 2) Local fallback (Docker/Dev) ---
    db_name = os.environ.get("DB_NAME", "lodge")
    db_user = os.environ.get("DB_USER", "postgres")
    db_password = os.environ.get("DB_PASSWORD", "postgres")
    db_host = os.environ.get("DB_HOST", "localhost")
    db_port = int(os.environ.get("DB_PORT", "5433"))  # your docker port

    conn = psycopg2.connect(
        host=db_host,
        port=db_port,
        user=db_user,
        password=db_password,
        dbname=db_name
    )
    return conn
