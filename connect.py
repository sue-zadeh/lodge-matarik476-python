# connect.py
import os
import psycopg2
from urllib.parse import urlparse


def get_db():
    """
    Priority:
    1. DATABASE_URL -> for Railway / Azure / production if provided
    2. DB_* variables -> for local Docker / local development
    """

    database_url = os.environ.get("DATABASE_URL")

    # 1) Production / Railway / cloud style connection
    if database_url:
        parsed = urlparse(database_url)

        dbname = parsed.path.lstrip("/")
        user = parsed.username
        password = parsed.password
        host = parsed.hostname
        port = parsed.port or 5432

        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port,
            sslmode="require"
        )
        return conn

    # 2) Local Docker / local development fallback
    db_name = os.environ.get("DB_NAME", "lodge")
    db_user = os.environ.get("DB_USER", "postgres")
    db_password = os.environ.get("DB_PASSWORD", "postgres")
    db_host = os.environ.get("DB_HOST", "localhost")
    db_port = int(os.environ.get("DB_PORT", "5432"))

    conn = psycopg2.connect(
        dbname=db_name,
        user=db_user,
        password=db_password,
        host=db_host,
        port=db_port
    )
    return conn