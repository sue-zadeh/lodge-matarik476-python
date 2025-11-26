import os
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
import mysql.connector
from flask_hashing import Hashing
import logging
from mysql.connector import connect, Error
from datetime import datetime
from app import app
import app.connect as connect


app.secret_key = 'e2e62cdb171271f0b12e5043f9f84208eba1f05c8658704e'
PASSWORD_SALT = '1234abcd'

hashing = Hashing(app)
logging.basicConfig(level=logging.DEBUG)

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db_connection = None

def getCursor(dictionary=False, buffered=False):
    global db_connection

    try:
        if db_connection is None or not db_connection.is_connected():
            db_connection = mysql.connector.connect(
                user=connect.dbuser,
                password=connect.dbpass,
                host=connect.dbhost,
                database=connect.dbname,
                auth_plugin='mysql_native_password',
                autocommit=True
            )
            print("Connection successful")

        cursor = db_connection.cursor(dictionary=dictionary, buffered=buffered)
        return cursor, db_connection

    except mysql.connector.Error as e:
        print("Error while connecting to MySQL", e)
        return None, None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def save_profile_photo(photo):
    if photo and allowed_file(photo.filename):
        filename = secure_filename(photo.filename)
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(photo_path)
        return filename
    return None  # Return None if no photo is uploaded or the file is invalid


# ------ members, moderators, admins
def redirect_based_on_role(html_file):
     if "member" in session:
         return redirect(url_for("community"))
     elif "moderator" in session:
        return redirect(url_for("community"))
     elif "admin" in session:
        return redirect(url_for("community"))
     else:
         return render_template(html_file)
    
def render_login_or_register(registered, toLogin, msg, username):
    if toLogin:
        return render_template('login.html', msg=msg, toLogin=toLogin, registered=registered, username=username) 
    else:
        return render_template("register.html", msg=msg, toLogin=toLogin)
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
#-- home page
@app.route("/")
def home():
    return render_template("index.html")

# @app.route('/uploads/<filename>')

     #------register form-------#
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        birth_date = request.form['birth_date']
        location = request.form['location']
        file = request.files['profile_image']
        profile_image = None

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))

        cursor, conn = getCursor()
        if not cursor or not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('register'))

        try:
            birth_date_obj = datetime.strptime(birth_date, '%Y-%m-%d')
            birth_date = birth_date_obj.strftime('%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD', 'error')
            return redirect(url_for('register'))

        # Check if location contains only letters, spaces, and commas
        if not re.match(r'^[A-Za-z\s,]+$', location):
            flash('Location must contain only letters, spaces, and commas.', 'error')
            return redirect(url_for('register'))

        # Save the file if it exists and is allowed
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_image = filename  # Save the filename to profile_image
        else:
            flash('File not allowed', 'error')
            return redirect(url_for('register'))

        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        account = cursor.fetchone()

        if account:
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))

        # Hash the password
        password = hashing.hash_value(password, '1234abcd')

        # Insert the new user into the database
        cursor.execute("""
            INSERT INTO users (username, first_name, last_name, email, password, birth_date, location, profile_image)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (username, first_name, last_name, email, password, birth_date, location, profile_image))
        conn.commit()

        flash('Registration successful. Please login now.', 'success')
        return redirect(url_for('login'))

    return render_template("register.html")

  
   #----- login------#
  
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor, conn = getCursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
# Check if user exists and password is correct
        if user and hashing.check_value(user['password'], password, PASSWORD_SALT):
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('community'))

        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

    return render_template("login.html")
#----logout---#

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))
  
    #------------profile----------#
@app.route('/profile', methods=['GET'])
def profile():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('Please log in to view the profile page.', 'info')
        return redirect(url_for('login'))
    
    # Fetch user data after ensuring the user is logged in
    cursor, conn = getCursor(dictionary=True)
    if cursor is None or conn is None:
        return "Database connection error", 500

    try:
        # Fetch the user information
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
        user = cursor.fetchone()

        # Fetch user messages
        cursor.execute("SELECT * FROM messages WHERE user_id = %s ORDER BY created_at DESC", (session['user_id'],))
        messages = cursor.fetchall()

        # Check if user data exists and handle date formatting
        if user and 'birth_date' in user:
            try:
                # Format birth_date if it's a datetime.date object
                user['birth_date'] = user['birth_date'].strftime('%d/%m/%Y')
            except AttributeError:
                flash('Error formatting date. Date format is incorrect.', 'error')

    finally:
        cursor.close()
        if conn.is_connected():
            conn.close()

    # Check if user data exists before rendering the profile page
    if user:
        return render_template("profile-user.html", user=user, messages=messages)
    else:
        return "User not found", 404

      
#---- Edit Profile view-----#

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('You must be logged in to edit your profile.', 'error')
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)

    if request.method == 'POST':
        email = request.form.get('email')
        location = request.form.get('location')
        birth_date = request.form.get('birth_date')
        file = request.files.get('profile_image')
        # Default image if none is uploaded
        profile_image = session.get('profile_image', 'default.png') 

        if file and allowed_file(file.filename):
           filename = secure_filename(file.filename)
           file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))


        # Update user information in the database
        cursor.execute("""
            UPDATE users SET email = %s, location = %s, birth_date = %s, profile_image = %s WHERE user_id = %s
        """, (email, location, birth_date, profile_image, session['user_id']))
        conn.commit()
        flash('Profile updated successfully!', 'success')
      # Redirect to the profile page
        return redirect(url_for('profile')) 

    # For GET request, load user information to populate form
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
    user = cursor.fetchone()
    return render_template("edit_profile.html", user=user)  

  
  #----delete profile----#
  
@app.route('/delete_profile', methods=['POST'])
def delete_profile():
    if 'user_id' in session:
        cursor, conn = getCursor()
        cursor.execute("DELETE FROM users WHERE user_id = %s", (session['user_id'],))
        conn.commit()
        cursor.close()
        conn.close()
        session.clear()  # Clear the session after deleting the account
        flash('Your account has been deleted successfully.', 'success')
      # Redirect to the home page or login page
        return redirect(url_for('home'))  
    else:
        flash('You must be logged in to delete your account.', 'danger')
        return redirect(url_for('login'))


# Change Password view
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    app.logger.debug('Session: %s', session)
    if 'username' in session:
        if request.method == 'POST':
            app.logger.debug('Form Data: %s', request.form)
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Check if new password and confirm password match
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
              # Redirect back to change password page
                return redirect(url_for('change_password'))  
            
            cursor, conn = getCursor(dictionary=True)
            if not cursor:
                flash('Database connection error.', 'error')
              # Redirect back if database error happens
                return redirect(url_for('change_password'))  
            
            # Check if old password is correct
            cursor.execute("SELECT password FROM users WHERE username = %s", (session['username'],))
            user = cursor.fetchone()

            if user and hashing.check_value(user['password'], old_password, PASSWORD_SALT):
                # If the old password is correct, update the password
                hashed_password = hashing.hash_value(new_password, PASSWORD_SALT)
                cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, session['username']))
                conn.commit()
                flash('Password changed successfully!', 'success')
                cursor.close()
              # Redirect to profile after successful password change
                return redirect(url_for('profile'))  
            else:
                flash('Old password is incorrect or user not found.', 'error')
                cursor.close()
              # Redirect back to change password page if old password is wrong
                return redirect(url_for('change_password'))  
        
        return render_template('password.html')
    
    app.logger.debug('Redirecting to login because of missing session')
    flash('You must be logged in to change your password.', 'error')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
