import os
import psycopg2
from urllib.parse import urlparse

def get_db():
    """
    Local dev:
      uses DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

    Railway:
      uses DATABASE_URL automatically (Railway provides it)
    """

    database_url = os.environ.get("DATABASE_URL")

    # ---- Railway / Production ----
    if database_url:
        # DATABASE_URL example:
        # postgres://user:pass@host:port/dbname
        result = urlparse(database_url)

        return psycopg2.connect(
            dbname=result.path[1:],   # remove leading "/"
            user=result.username,
            password=result.password,
            host=result.hostname,
            port=result.port,
            sslmode="require"         # important for Railway
        )

    # ---- Local Development ----
    host = os.environ.get("DB_HOST", "localhost")
    port = int(os.environ.get("DB_PORT", "5433"))  # your docker mapped port
    dbname = os.environ.get("DB_NAME", "lodge")
    user = os.environ.get("DB_USER", "postgres")
    password = os.environ.get("DB_PASSWORD", "postgres")

    return psycopg2.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password
    )
