# connect.py (at root level)
import os
import psycopg2

def get_db():
    # First, check if we're on Railway (has DATABASE_URL)
    database_url = os.getenv("DATABASE_URL")
    
    if database_url:
        # Production mode (Railway)
        print("Using Railway DATABASE_URL")
        try:
            conn = psycopg2.connect(database_url)
            conn.autocommit = False  # Recommended for transactions
            print("Database connection successful (Railway)!")
            return conn
        except Exception as e:
            print("Railway DB connection failed:", str(e))
            raise

    # Fallback to local development (use separate vars from .env)
    print("Using local PostgreSQL (development mode)")
    db_name = os.getenv("DB_NAME", "lodge")
    db_user = os.getenv("DB_USER", "postgrees")
    db_password = os.getenv("DB_PASSWORD", "postgrees")
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5433")

    try:
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port
        )
        conn.autocommit = False
        print("Database connection successful (local)!")
        return conn
    except Exception as e:
        print("Local DB connection failed:", str(e))
        raise
      
