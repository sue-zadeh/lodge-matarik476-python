# app/__init__.py
from flask import Flask

app = Flask(__name__)

# config
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['FILE_UPLOAD_FOLDER'] = 'static/files'      

app.secret_key = '2232b1ec1b426bc383f1ec071979d87dd91e7b2e8467a5e0620e714ee1affdc5'

# import routes so they register on the app
from app import views
# from app import event
# from app import contact_email
# from app import admins_dashboard
