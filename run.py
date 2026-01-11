
from dotenv import load_dotenv
from app import app

if __name__ == "__main__":
    app.run(debug=True, port=5002)
