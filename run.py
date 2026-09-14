# run.py (at root)
# from flask import Flask  # if needed
import os

# Only load .env locally (Railway doesn't need it)
if os.getenv("RAILWAY_ENVIRONMENT") is None:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

# Import your app
from app import app  # this is Flask app

if __name__ == "__main__":
    app.run()
