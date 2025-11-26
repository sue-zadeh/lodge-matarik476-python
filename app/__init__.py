from flask import Flask

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'static/uploads'

app.secret_key = 'e2e62cdb171271f0b12e5043f9f84208eba1f05c8658704e'

 # ----Import all common routes 
from app import views
from app import users_views
from app import community
# from app import auth
# from app import database
# from app import admins_views
# from app import members_views



if __name__ == '__main__':
    app.run(debug=True, port=5002)
 
    
