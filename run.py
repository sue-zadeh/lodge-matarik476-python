# run.py (at root)
# from flask import Flask  # if needed
import os

# Only load .env locally (Railway doesn't need it)
if os.getenv("RAILWAY_ENVIRONMENT") is None:
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("Loaded .env locally")
    except ImportError:
        print("dotenv not installed - skipping (normal in production)")

# Import your app
from app import app  # Assuming this is your Flask app

if __name__ == "__main__":
    app.run(debug=True, port=5002)