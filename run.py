import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "app", ".env"))

from app import app

if __name__ == "__main__":
    app.run(debug=True, port=5002)
