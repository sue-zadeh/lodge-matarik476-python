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
from datetime import timedelta

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

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




def render_login_or_register(registered, toLogin, msg, username):
    if toLogin:
        return render_template('login.html', msg=msg, toLogin=toLogin,
                               registered=registered, username=username)
    else:
        return render_template("register.html", msg=msg, toLogin=toLogin)


def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ---------- Routes ----------
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

@app.route("/")
def home():
    role = session.get('role')

    if role == 'admin':
        return redirect(url_for('admin_home'))
    elif role == 'member':
        return redirect(url_for('member_home'))

    # Not logged in → public landing page
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

        # ---- role logic ----#
        
        # default
        role = 'member'

        # only current admins can set role via form
        if session.get('role') == 'admin':
            role_from_form = request.form.get('role', 'member')
            if role_from_form in ['admin', 'member']:
                role = role_from_form

        file = request.files['profile_image']
        profile_image = None

        # ---- basic validations ----
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))

        if len(username) < 5:
            flash('Username must be at least 5 characters long.', 'error')
            return redirect(url_for('register'))

        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email format.', 'error')
            return redirect(url_for('register'))

        if phone and not re.match(r'^[0-9+ ]*$', phone):
            flash('Phone must contain digits and + only.', 'error')
            return redirect(url_for('register'))

        if (len(password) < 8 or
            not re.search(r'[A-Z]', password) or
            not re.search(r'[a-z]', password) or
            not re.search(r'[0-9]', password)):
            flash('Password must be at least 8 characters and include upper, lower and number.', 'error')
            return redirect(url_for('register'))

        try:
            birth_date_obj = datetime.strptime(birth_date, '%Y-%m-%d')
            birth_date = birth_date_obj.strftime('%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD', 'error')
            return redirect(url_for('register'))

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

        cursor.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        account = cursor.fetchone()

        if account:
            flash('Username already exists!', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('register'))

        password_hash = hashing.hash_value(password, PASSWORD_SALT)

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

#-------------- Login -------------#

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        cursor, conn = getCursor(dictionary=True)
        cursor.execute("""
            SELECT user_id, username, password, role
            FROM users
            WHERE username = %s AND is_active = TRUE
        """, (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and hashing.check_value(user['password'], password, PASSWORD_SALT):
            session.permanent = True   # ← needed for timeout
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']

            flash(f'Welcome, {user["username"]}!', 'success')

            # Role-based homepage
            if user['role'] == 'admin':
                return redirect(url_for('admin_home'))
            elif user['role'] == 'member':
                return redirect(url_for('member_home'))
            else:
                return redirect(url_for('home'))

        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

    return render_template("login.html")


# ------ Routes for home_members and home_admins ------ #

@app.route('/member/home')
def member_home():
    # only members can see this page
    if session.get('role') != 'member':
        return redirect(url_for('login'))

    user = None
    whats_next = None
    user_id = session.get('user_id')

    if user_id:
        cursor, conn = getCursor(dictionary=True)

        # ---- get current user ----
        cursor.execute(
            """
            SELECT user_id, username, first_name, last_name, profile_image, role
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )
        user = cursor.fetchone()

        # ---- get latest "what's next" message (if any) ----
        cursor.execute(
            """
            SELECT content
            FROM whats_next
            ORDER BY created_at DESC
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        if row:
            whats_next = row['content']

        cursor.close()
        conn.close()

    return render_template('home_member.html', user=user, whats_next=whats_next)

#-----Admin Home ------#

@app.route('/admin/home')
def admin_home():
    # only admins can see this page
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    user = None
    latest_note = ""   # default if there is no message yet
    user_id = session.get('user_id')

    if user_id:
        cursor, conn = getCursor(dictionary=True)

        # Get admin user info
        cursor.execute(
            """
            SELECT user_id, username, first_name, last_name, profile_image, role
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )
        user = cursor.fetchone()

        # Get last "what's next" message
        cursor.execute(
            """
            SELECT content
            FROM whats_next
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        if row:
            latest_note = row["content"]

        cursor.close()
        conn.close()

    return render_template('home_admin.html', user=user, latest_note=latest_note)

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

    # Always load current user first
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        flash('User not found.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # names must match your form fields
        username    = request.form.get('username')
        first_name  = request.form.get('fname')
        last_name   = request.form.get('lname')
        email       = request.form.get('email')
        phone       = request.form.get('phone')
        birth_date  = request.form.get('birth_date')   # yyyy-mm-dd from input[type=date]

        file = request.files.get('profile_image')

        # default: keep existing image
        profile_image = user.get('profile_image')

        # if a new file uploaded, save and replace
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_image = filename

        cursor.execute("""
            UPDATE users
            SET username = %s,
                first_name = %s,
                last_name = %s,
                email = %s,
                phone = %s,
                birth_date = %s,
                profile_image = %s
            WHERE user_id = %s
        """, (
            username,
            first_name,
            last_name,
            email,
            phone,
            birth_date,
            profile_image,
            session['user_id']
        ))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # GET: prepare data for the form
    if user.get('birth_date'):
        try:
            user['birth_date'] = user['birth_date'].strftime('%Y-%m-%d')
        except AttributeError:
            pass

    cursor.close()
    conn.close()
    return render_template("edit-profile.html", user=user)


#------- Change Picture in the Profile --------------------#
@app.route('/update_profile_image', methods=['POST'])
def update_profile_image():
    if 'user_id' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))

    file = request.files.get('profile_image')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        cursor, conn = getCursor()
        cursor.execute(
            "UPDATE users SET profile_image = %s WHERE user_id = %s",
            (filename, session['user_id'])
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash('Profile photo updated.', 'success')

    return redirect(url_for('profile'))


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
  
# =========================================================
# ADMIN – whats_next
# =========================================================

@app.route('/admin/whats_next', methods=['POST'])
def admin_whats_next():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    text = request.form.get('whats_next', '').strip()

    if not text:
        flash('Message cannot be empty.', 'warning')
        return redirect(url_for('admin_home'))

    cursor, conn = getCursor()
    cursor.execute(
        "INSERT INTO whats_next (content) VALUES (%s)",
        (text,)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("What's Happening Next message updated.", 'success')
    return redirect(url_for('admin_home'))
# =========================================================
# ADMIN – MANAGE USERS (members + admins)
# =========================================================

@app.route('/admin/users', methods=['GET', 'POST'])
def admin_manage_users():
    # only admins can see this page
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    search_term = ""
    users = []
    message = ""

    cursor, conn = getCursor(dictionary=True)

    try:
        if request.method == 'POST':
            search_term = request.form.get('search', '').strip()

        base_sql = """
            SELECT
                user_id,
                username,
                first_name,
                last_name,
                email,
                phone,
                birth_date,
                profile_image,
                role,
                is_active
            FROM users
        """

        params = []

        if search_term:
            base_sql += """
                WHERE
                    first_name ILIKE %s
                    OR last_name ILIKE %s
                    OR username ILIKE %s
                    OR email ILIKE %s
            """
            like = f"%{search_term}%"
            params = [like, like, like, like]

        base_sql += " ORDER BY role DESC, first_name, last_name"

        cursor.execute(base_sql, params)
        users = cursor.fetchall()

        if search_term and not users:
            message = f"Sorry, there are no results for '{search_term}'."

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "admin_manage_users.html",
        users=users,
        search_term=search_term,
        message=message
    )


# ---------------------------------------------------------
# Change role (admin <-> member)
# ---------------------------------------------------------

@app.route('/admin/users/<int:user_id>/change_role', methods=['POST'])
def admin_change_role(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    new_role = request.form.get('role')
    if new_role not in ['admin', 'member']:
        flash("Invalid role selected.", "danger")
        return redirect(url_for('admin_manage_users'))

    # Optional: don't allow an admin to change their own role
    if user_id == session.get('user_id'):
        flash("You cannot change your own role.", "warning")
        return redirect(url_for('admin_manage_users'))

    cursor, conn = getCursor()
    try:
        cursor.execute(
            "UPDATE users SET role = %s WHERE user_id = %s",
            (new_role, user_id)
        )
        conn.commit()
        flash("User role updated successfully.", "success")
    except Exception:
        conn.rollback()
        flash("Failed to update user role.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_manage_users'))


# ---------------------------------------------------------
# Toggle active / inactive
# ---------------------------------------------------------

@app.route('/admin/users/<int:user_id>/toggle_active', methods=['POST'])
def admin_toggle_active(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    # Optional: don't lock yourself out
    if user_id == session.get('user_id'):
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for('admin_manage_users'))

    cursor, conn = getCursor()
    try:
        cursor.execute(
            "UPDATE users SET is_active = NOT is_active WHERE user_id = %s",
            (user_id,)
        )
        conn.commit()
        flash("User status updated.", "success")
    except Exception:
        conn.rollback()
        flash("Failed to update user status.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_manage_users'))


# ---------------------------------------------------------
# Delete user
# ---------------------------------------------------------

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    # Optional: safety – don't let admin delete themselves
    if user_id == session.get('user_id'):
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for('admin_manage_users'))

    cursor, conn = getCursor()
    try:
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()
        flash("User removed successfully.", "success")
    except Exception:
        conn.rollback()
        flash("Failed to delete user.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_manage_users'))
