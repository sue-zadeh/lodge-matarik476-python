import os
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_hashing import Hashing
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime
from app import app
from app.connect import get_db  # our PostgreSQL connection

PASSWORD_SALT = '1234abcd'

hashing = Hashing(app)
logging.basicConfig(level=logging.DEBUG)

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# ---------- DB helper ----------

def getCursor(dictionary: bool = False):
    """
    Returns (cursor, connection).
    If dictionary=True -> rows as dicts (for column names).
    """
    conn = get_db()

    if dictionary:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        cursor = conn.cursor()

    return cursor, conn


# ---------- File helpers ----------

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


def save_profile_photo(photo):
    if photo and allowed_file(photo.filename):
        filename = secure_filename(photo.filename)
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(photo_path)
        return filename
    return None


# ---------- Role helper ----------

def redirect_based_on_role(html_file):
    if "member" in session:
        return redirect(url_for("community"))
    elif "admin" in session:
        return redirect(url_for("community"))
    else:
        return render_template(html_file)


def render_login_or_register(registered, toLogin, msg, username):
    if toLogin:
        return render_template('login.html', msg=msg, toLogin=toLogin,
                               registered=registered, username=username)
    else:
        return render_template("register.html", msg=msg, toLogin=toLogin)


def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ---------- Routes ----------

@app.route("/")
def home():
    return render_template("index.html")


# ------ register form ------- #
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
        phone = request.form.get('phone', '')
        role = request.form.get('role', 'member')
        file = request.files['profile_image']
        profile_image = None

        # ---- basic validations ----

        # Passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))

        # Username length
        if len(username) < 5:
            flash('Username must be at least 5 characters long.', 'error')
            return redirect(url_for('register'))

        # Simple email check
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email format.', 'error')
            return redirect(url_for('register'))

        # Phone: only digits, + and space
        if phone and not re.match(r'^[0-9+ ]*$', phone):
            flash('Phone must contain digits and + only.', 'error')
            return redirect(url_for('register'))

        # Password strength
        if (len(password) < 8 or
            not re.search(r'[A-Z]', password) or
            not re.search(r'[a-z]', password) or
            not re.search(r'[0-9]', password)):
            flash('Password must be at least 8 characters and include upper, lower and number.', 'error')
            return redirect(url_for('register'))

        # Parse date
        try:
            birth_date_obj = datetime.strptime(birth_date, '%Y-%m-%d')
            birth_date = birth_date_obj.strftime('%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD', 'error')
            return redirect(url_for('register'))

        # Location only letters, spaces, commas
        # if not re.match(r'^[A-Za-z\s,]+$', location):
        #     flash('Location must contain only letters, spaces, and commas.', 'error')
        #     return redirect(url_for('register'))

        # Save profile image
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_image = filename
            session['profile_image'] = filename   
        else:
            flash('File not allowed', 'error')
            return redirect(url_for('register'))

        cursor, conn = getCursor()
        if not cursor or not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('register'))

        # Check if username already exists
        cursor.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        account = cursor.fetchone()

        if account:
            flash('Username already exists!', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('register'))

        # Hash the password
        password_hash = hashing.hash_value(password, PASSWORD_SALT)

        # Insert the new user
        cursor.execute(
            """
            INSERT INTO users (
                username, first_name, last_name,
                email, password, phone,
                birth_date, profile_image, role
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (username, first_name, last_name,
             email, password_hash, phone,
             birth_date, profile_image, role)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash('Registration successful. Please login now.', 'success')
        return redirect(url_for('login'))

    return render_template("register.html")


# ----- login ------ #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Read form data
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Get DB cursor (dictionary=True => RealDictCursor)
        cursor, conn = getCursor(dictionary=True)

        # Column names must match your table: user_id + password
        cursor.execute(
            """
            SELECT user_id, username, password, role
            FROM users
            WHERE username = %s AND is_active = TRUE
            """,
            (username,)
        )
        user = cursor.fetchone()

        # We can close the cursor/connection now
        cursor.close()
        conn.close()

        # Check password using the same salt you used on register
        if user and hashing.check_value(user['password'], password, PASSWORD_SALT):
            session.clear()
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']   # 'member' or 'admin'

            flash(f'Welcome, {user["username"]}!', 'success')
            return redirect(url_for('home'))  # go to home page

        # If we reach here, login failed
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

    # GET -> show form
    return render_template("login.html")



# ---- logout ---- #
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# ------------ profile ---------- #
@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to view the profile page.', 'info')
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
        user = cursor.fetchone()

        # (Optional) messages table – comment out if not created yet
        # cursor.execute("SELECT * FROM messages WHERE user_id = %s ORDER BY created_at DESC", (session['user_id'],))
        # messages = cursor.fetchall()
        messages = []

        if user and 'birth_date' in user and user['birth_date']:
            try:
                user['birth_date'] = user['birth_date'].strftime('%d/%m/%Y')
            except AttributeError:
                flash('Error formatting date.', 'error')

    finally:
        cursor.close()
        conn.close()

    if user:
        return render_template("profile-members.html", user=user, messages=messages)
    else:
        return "User not found", 404


# ---- Edit Profile ---- #
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('You must be logged in to edit your profile.', 'error')
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)

    if request.method == 'POST':
        username    = request.form.get('username', '').strip()
        first_name  = request.form.get('first_name', '').strip()
        last_name   = request.form.get('last_name', '').strip()
        email       = request.form.get('email', '').strip()
        phone       = request.form.get('phone', '').strip()
        birth_date  = request.form.get('birth_date')       # 'YYYY-MM-DD' from <input type="date">
        file        = request.files.get('profile_image')
        profile_image = session.get('profile_image', 'default.png')

        # handle photo
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_image = filename

        # (optional) simple username-length check
        if len(username) < 5:
            flash('Username must be at least 5 characters.', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('edit_profile'))

        # update user
        cursor.execute(
            """
            UPDATE users
            SET username      = %s,
                first_name    = %s,
                last_name     = %s,
                email         = %s,
                phone         = %s,
                birth_date    = %s,
                profile_image = %s
            WHERE user_id = %s
            """,
            (username, first_name, last_name, email, phone,
             birth_date, profile_image, session['user_id'])
        )
        conn.commit()
        cursor.close()
        conn.close()

        # also update session values if username changed
        session['username'] = username

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # ---------- GET: load current data ----------
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    # for <input type="date"> we need YYYY-MM-DD
    if user and user.get('birth_date'):
        try:
            user['birth_date'] = user['birth_date'].strftime('%Y-%m-%d')
        except AttributeError:
            pass

    return render_template("edit-profile.html", user=user)


# ---- Delete profile ---- #
@app.route('/delete_profile', methods=['POST'])
def delete_profile():
    if 'user_id' in session:
        cursor, conn = getCursor()
        cursor.execute("DELETE FROM users WHERE user_id = %s", (session['user_id'],))
        conn.commit()
        cursor.close()
        conn.close()
        session.clear()
        flash('Your account has been deleted successfully.', 'success')
        return redirect(url_for('home'))
    else:
        flash('You must be logged in to delete your account.', 'danger')
        return redirect(url_for('login'))


# ---- Change password ---- #
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    app.logger.debug('Session: %s', session)
    if 'username' in session:
        if request.method == 'POST':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return redirect(url_for('change_password'))

            cursor, conn = getCursor(dictionary=True)

            cursor.execute("SELECT password FROM users WHERE username = %s", (session['username'],))
            user = cursor.fetchone()

            if user and hashing.check_value(user['password'], old_password, PASSWORD_SALT):
                hashed_password = hashing.hash_value(new_password, PASSWORD_SALT)
                cursor.execute(
                    "UPDATE users SET password = %s WHERE username = %s",
                    (hashed_password, session['username'])
                )
                conn.commit()
                cursor.close()
                conn.close()
                flash('Password changed successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                cursor.close()
                conn.close()
                flash('Old password is incorrect or user not found.', 'error')
                return redirect(url_for('change_password'))

        return render_template('password.html')

    app.logger.debug('Redirecting to login because of missing session')
    flash('You must be logged in to change your password.', 'error')
    return redirect(url_for('login'))
