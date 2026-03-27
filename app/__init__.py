# app/__init__.py
import os
from flask import Flask

app = Flask(__name__)

app.secret_key =  os.environ.get("SECRET_KEY", "dev-secret-key")

# config
app.config["UPLOAD_FOLDER"] = os.environ.get("UPLOAD_FOLDER", "static/uploads")
app.config["FILE_UPLOAD_FOLDER"] = os.environ.get("FILE_UPLOAD_FOLDER", "static/files")

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["FILE_UPLOAD_FOLDER"], exist_ok=True)


# import routes so they register on the app
from app import views
# from app import event
# from app import contact_email
# from app import admins_dashboard
