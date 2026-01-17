import os
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_hashing import Hashing
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime, date
from app import app
from connect import get_db  # our PostgreSQL connection
from datetime import timedelta
from email.message import EmailMessage
import smtplib
from urllib.parse import urlencode
import resend
import pytz
from contextlib import contextmanager

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

PASSWORD_SALT = '1234abcd'

hashing = Hashing(app)
logging.basicConfig(level=logging.DEBUG)

# profile/member photos
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# docs/files that admins send to members
FILE_UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'files')
app.config['FILE_UPLOAD_FOLDER'] = FILE_UPLOAD_FOLDER

# ---allowed file
ALLOWED_FILE_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'xls', 'xlsx',
    'ppt', 'pptx', 'txt', 'png', 'jpg', 'jpeg'
}

def allowed_file_generic(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_FILE_EXTENSIONS
  
  
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
def norm_role(role):
    """Normalize role text from DB/session (handles None, spaces, casing)."""
    return (role or "").strip().lower()

# ---------- Routes ----------
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year, 'date' : date }

@app.route("/")
def home():
    role = norm_role(session.get('role'))  # norm_role function

    if role == 'admin':
        return redirect(url_for('admin_home'))
    elif role == 'member':
        return redirect(url_for('member_home'))

    # If no valid role or not logged in → show public page
    return render_template("index.html")
    
#---------------Cursor --------------#

@contextmanager
def db_cursor(dictionary=False):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) if dictionary else conn.cursor()
    try:
        yield cur, conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

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
        address = request.form.get('address', '').strip()
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
          
        if not address:
           flash('Address is required.', 'error')
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

        # Check both username and email
        cursor.execute("""
            SELECT username, email
            FROM users
            WHERE username = %s OR email = %s
        """, (username, email))

        existing = cursor.fetchone()

        if existing:
            if existing[0] == username:
                flash('Username already exists!', 'error')
            elif existing[1] == email:
                flash('Email already registered!', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('register'))

        # only reach this if NO existing user
        password_hash = hashing.hash_value(password, PASSWORD_SALT)

        cursor.execute(
            """
            INSERT INTO users (
                username, first_name, last_name,
                email, password, phone, address,
                birth_date, profile_image, role
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (username, first_name, last_name,
             email, password_hash, phone, address,
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

        try:
            with db_cursor(dictionary=True) as (cursor, conn):
                cursor.execute("""
                    SELECT user_id, username, password, role
                    FROM users
                    WHERE username = %s AND COALESCE(is_active, TRUE) = TRUE
                    LIMIT 1
                """, (username,))
                user = cursor.fetchone()

        except Exception as e:
            app.logger.exception("Login DB error")
            flash('Database error. Please try again.', 'danger')
            return redirect(url_for('login'))

        if user and hashing.check_value(user['password'], password, PASSWORD_SALT):
            role = norm_role(user.get('role'))

            session.permanent = True
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = role

            flash(f'Welcome, {user["username"]}!', 'success')

            if role == 'admin':
                return redirect(url_for('admin_home'))
            if role == 'member':
                return redirect(url_for('member_home'))
            return redirect(url_for('home'))

        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

    return render_template("login.html")




# ------ Routes for home_members and home_admins ------ #

@app.route('/member/home')
def member_home():
    if norm_role(session.get('role')) != 'member':
        return redirect(url_for('login'))

    user_id = session.get('user_id')

    try:
        with db_cursor(dictionary=True) as (cursor, conn):

            cursor.execute("""
                SELECT user_id, username, first_name, last_name, profile_image, role
                FROM users
                WHERE user_id = %s
            """, (user_id,))
            user = cursor.fetchone()

            cursor.execute("""
                SELECT f.file_id, f.subject, f.created_at
                FROM files f
                LEFT JOIN file_reads fr
                  ON fr.file_id = f.file_id AND fr.user_id = %s
                WHERE fr.user_id IS NULL
                  AND f.is_admin_only = FALSE
                ORDER BY f.created_at DESC
                LIMIT 5
            """, (user_id,))
            new_files = cursor.fetchall()
            new_files_count = len(new_files)

            cursor.execute("""
                SELECT note
                FROM admin_messages
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            """)
            whats_next = cursor.fetchone()

            active_event = get_active_event(cursor)

            event_is_new = False
            if active_event:
                cursor.execute("""
                    SELECT 1
                    FROM event_reads
                    WHERE event_id = %s AND user_id = %s
                    LIMIT 1
                """, (active_event["event_id"], user_id))
                seen = cursor.fetchone()
                event_is_new = (seen is None)

    except Exception:
        app.logger.exception("member_home error")
        flash("Sorry, member home failed to load (DB error).", "danger")
        return redirect(url_for('home'))

    return render_template(
        'home_member.html',
        user=user,
        active_event=active_event,
        event_is_new=event_is_new,
        new_files=new_files,
        new_files_count=new_files_count,
        whats_next=whats_next
    )

# ----- Admin Home ------ #

@app.route('/admin/home')
def admin_home():
    if norm_role(session.get('role')) != 'admin':
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    user = None
    latest_note = ""
    contact_messages = []

    try:
        with db_cursor(dictionary=True) as (cursor, conn):

            cursor.execute("""
                SELECT user_id, username, first_name, last_name, profile_image, role
                FROM users
                WHERE user_id = %s
            """, (user_id,))
            user = cursor.fetchone()

            cursor.execute("""
                SELECT note
                FROM admin_messages
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            if row:
                latest_note = row["note"]

            cursor.execute("""
                SELECT id, name, email, phone, message, created_at
                FROM contact_messages
                ORDER BY created_at DESC
                LIMIT 5
            """)
            contact_messages = cursor.fetchall()

    except Exception:
        app.logger.exception("admin_home error")
        flash("Sorry, admin home failed to load (DB error).", "danger")
        return redirect(url_for('home'))

    return render_template(
        'home_admin.html',
        user=user,
        latest_note=latest_note,
        contact_messages=contact_messages,
    )
    
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
    # must be logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor, conn = getCursor(dictionary=True)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        birth_date = request.form.get('birth_date', None)

        # --- check duplicates (other users) ---
        cursor.execute(
            """
            SELECT user_id, username, email
            FROM users
            WHERE (username = %s OR email = %s)
              AND user_id <> %s
            """,
            (username, email, user_id)
        )
        existing = cursor.fetchone()

        if existing:
            # someone else already has this username/email
            if existing['username'] == username:
                flash('Username already exists. Please choose another one.', 'error')
            elif existing['email'] == email:
                flash('Email already registered. Please use a different email.', 'error')

            cursor.close()
            conn.close()
            return redirect(url_for('edit_profile'))
            if not address:
                flash('Address is required.', 'error')
                cursor.close()
                conn.close()
                return redirect(url_for('edit_profile'))


        # --- handle optional profile image (if you have this in your form) ---
        file = request.files.get('profile_image')
        profile_image = None
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_image = filename
            else:
                flash('File not allowed.', 'error')
                cursor.close()
                conn.close()
                return redirect(url_for('edit_profile'))

        # --- finally update the record ---
        cursor.execute(
            """
            UPDATE users
            SET username = %s,
                first_name = %s,
                last_name  = %s,
                email      = %s,
                phone      = %s,
                address    = %s,
                birth_date = %s,
                profile_image = COALESCE(%s, profile_image)
            WHERE user_id = %s
            """,
            (username, first_name, last_name,
             email, phone, address, birth_date, profile_image, user_id)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash('Profile updated successfully.', 'success')
        return redirect(url_for('member_home'))  # or wherever you send them

    # GET: load current user data
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('edit-profile.html', user=user)


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
        "INSERT INTO admin_messages (note) VALUES (%s)",
        (text,)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Message sent to members' home page.", 'success')
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
                address,
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
  
  
  
# ---------- Admin files page ---------- #


@app.route('/admin/files', methods=['GET', 'POST'])
def admin_files():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    edit_id = request.args.get('edit_id', type=int)
    cursor, conn = getCursor(dictionary=True)

    message = None

    if request.method == 'POST':
        file_id = request.form.get('file_id')
        subject = request.form.get('subject', '').strip()
        description = request.form.get('description', '').strip()
        is_admin_only = 'is_admin_only' in request.form

        if not subject:
            flash('Subject is required.', 'error')
            cursor.close(); conn.close()
            return redirect(url_for('admin_files'))

        filename_on_disk = None
        upload = request.files.get('file')

        # Only require file when creating new (not editing)
        if not file_id and (not upload or not upload.filename):
            flash('Please choose a file to upload.', 'error')
            cursor.close(); conn.close()
            return redirect(url_for('admin_files'))

        if upload and upload.filename:
            if not allowed_file_generic(upload.filename):
                flash('File type not allowed.', 'error')
                cursor.close(); conn.close()
                return redirect(url_for('admin_files'))

            safe_name = secure_filename(upload.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename_on_disk = f"{timestamp}_{safe_name}"
            upload.save(os.path.join(app.config['FILE_UPLOAD_FOLDER'], filename_on_disk))

        try:
            if file_id:  # UPDATE
                cursor.execute("""
                    UPDATE files
                    SET subject = %s,
                        description = %s,
                        is_admin_only = %s,
                        filename = COALESCE(%s, filename)
                    WHERE file_id = %s
                """, (subject, description, is_admin_only, filename_on_disk, file_id))
                message = "File updated successfully."
            else:  # CREATE
                cursor.execute("""
                    INSERT INTO files (subject, description, filename, uploader_id, is_admin_only)
                    VALUES (%s, %s, %s, %s, %s)
                """, (subject, description, filename_on_disk, session['user_id'], is_admin_only))
                message = "File uploaded successfully."

            conn.commit()
            flash(message, 'success')
        except Exception as e:
            conn.rollback()
            app.logger.exception("File save error")
            flash("Failed to save file. Check logs.", 'danger')

    # GET: list files
    try:
        cursor.execute("""
            SELECT f.file_id, f.subject, f.description, f.filename, f.created_at,
                   f.is_admin_only, u.username AS uploader
            FROM files f
            JOIN users u ON f.uploader_id = u.user_id
            ORDER BY f.created_at DESC
        """)
        files = cursor.fetchall()

        file_to_edit = None
        if edit_id:
            cursor.execute("""
                SELECT file_id, subject, description, filename, created_at, is_admin_only
                FROM files WHERE file_id = %s
            """, (edit_id,))
            file_to_edit = cursor.fetchone()
    except Exception as e:
        app.logger.exception("Files list error")
        flash("Failed to load files list.", 'danger')
        files = []

    cursor.close()
    conn.close()

    return render_template('admin_files.html', files=files, file_to_edit=file_to_edit)  
  
  #=====================================#
  
# ========= file/audience ================#

@app.route('/admin/files/<int:file_id>/audience', methods=['POST'])
def update_file_audience(file_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    audience = request.form.get('audience', 'public')  # public/admin
    is_admin_only = True if audience == 'admin' else False

    cursor, conn = getCursor()
    cursor.execute(
        "UPDATE files SET is_admin_only = %s WHERE file_id = %s",
        (is_admin_only, file_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash('Audience updated.', 'success')
    return redirect(url_for('admin_files'))


#------------ Delete file -----------#

@app.route('/admin/files/<int:file_id>/delete', methods=['POST'])
def delete_file(file_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    cursor, conn = getCursor()
    cursor.execute("DELETE FROM files WHERE file_id = %s", (file_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash('File deleted.', 'success')
    return redirect(url_for('admin_files'))
  
# ------------ Member/Files page -------#
@app.route('/member/files')
def member_files():
    if norm_role(session.get('role')) != 'member':
        return redirect(url_for('login'))

    user_id = session['user_id']

    try:
        with db_cursor(dictionary=True) as (cursor, conn):

            cursor.execute("""
                SELECT f.file_id,
                       f.subject,
                       f.description,
                       f.filename,
                       f.created_at,
                       u.username AS uploader
                FROM files f
                JOIN users u ON f.uploader_id = u.user_id
                WHERE f.is_admin_only = FALSE
                ORDER BY f.created_at DESC
            """)
            files = cursor.fetchall()

            for f in files:
                cursor.execute("""
                    INSERT INTO file_reads (user_id, file_id)
                    VALUES (%s, %s)
                    ON CONFLICT (user_id, file_id) DO NOTHING
                """, (user_id, f['file_id']))

    except Exception:
        app.logger.exception("member_files error")
        flash("Sorry, files failed to load.", "danger")
        return redirect(url_for('member_home'))

    return render_template('member_files.html', files=files)

#========== EVENTS ======================#

#===== Admin manage events page =======#

@app.route('/admin/events', methods=['GET', 'POST'])
def admin_events():
    if norm_role(session.get('role')) != 'admin':
        return redirect(url_for('login'))

    admin_id = session.get('user_id')
    if not admin_id:
        flash("Session expired. Please login again.", "danger")
        return redirect(url_for("login"))

    try:
        with db_cursor(dictionary=True) as (cursor, conn):

            if request.method == 'POST':
                title = request.form.get('title', '').strip()
                description = request.form.get('description', '').strip()

                event_date = request.form.get('event_date', '').strip()
                start_time = request.form.get('start_time', '').strip()
                end_time = request.form.get('end_time', '').strip()
                location = request.form.get('location', '').strip()

                audience = request.form.get('audience', 'members')
                is_admin_only = True if audience == 'admin' else False
                is_pinned = True if request.form.get('is_pinned') else False

                if not title or not event_date or not start_time:
                    flash('Please fill in Title, Date, and Start time.', 'error')
                    return redirect(url_for('admin_events'))

                if end_time == '':
                    end_time = None

                if is_pinned:
                    cursor.execute("UPDATE events SET is_pinned = FALSE WHERE is_pinned = TRUE")

                cursor.execute("""
                    INSERT INTO events (
                        title, description, event_date, start_time, end_time,
                        location, is_pinned, is_admin_only, created_by
                    )
                    VALUES (
                        %s, %s, %s::date, %s::time, %s::time,
                        %s, %s, %s, %s
                    )
                """, (
                    title, description, event_date, start_time, end_time,
                    location, is_pinned, is_admin_only, admin_id
                ))

                flash('Event created.', 'success')
                return redirect(url_for('admin_events'))

            cursor.execute("""
                SELECT e.*, u.username AS created_by_name
                FROM events e
                LEFT JOIN users u ON u.user_id = e.created_by
                ORDER BY e.is_pinned DESC, e.event_date DESC, e.start_time DESC
            """)
            events = cursor.fetchall()

    except Exception:
        app.logger.exception("admin_events error")
        flash("Event failed to save. Check Railway logs for the exact DB error.", "danger")
        return redirect(url_for('admin_events'))

    return render_template('admin_events.html', events=events, today=date.today().isoformat())
)

        
#=========change audience/admin + save to calendar + edit/delete ========#   
    
# Admin download .ics for ANY event (admin-only or member events)
@app.route('/admin/events/<int:event_id>/ics')
def admin_event_ics(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)
    cursor.execute("SELECT * FROM events WHERE event_id = %s LIMIT 1", (event_id,))
    e = cursor.fetchone()
    cursor.close()
    conn.close()

    if not e:
        return "Event not found", 404

    dt_start = f"{e['event_date'].strftime('%Y%m%d')}T{str(e['start_time']).replace(':','')[:4]}00"
    dt_end = dt_start
    if e.get('end_time'):
        dt_end = f"{e['event_date'].strftime('%Y%m%d')}T{str(e['end_time']).replace(':','')[:4]}00"

    title = (e.get('title') or 'Lodge Event').replace('\n', ' ')
    desc = (e.get('description') or '').replace('\n', '\\n')
    location = (e.get('location') or '').replace('\n', ' ')

    ics = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Lodge Matariki 476//EN
BEGIN:VEVENT
UID:event-{e['event_id']}@lodge
DTSTART:{dt_start}
DTEND:{dt_end}
SUMMARY:{title}
DESCRIPTION:{desc}
LOCATION:{location}
END:VEVENT
END:VCALENDAR
"""
    return (ics, 200, {
        "Content-Type": "text/calendar; charset=utf-8",
        "Content-Disposition": f"attachment; filename=event_{e['event_id']}.ics"
    })


# Change audience (Admin only / Members & Admins)
@app.route('/admin/events/<int:event_id>/audience', methods=['POST'])
def admin_update_event_audience(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    audience = request.form.get('audience', 'members')
    is_admin_only = True if audience == 'admin' else False

    cursor, conn = getCursor(dictionary=True)

    # update audience
    cursor.execute("""
        UPDATE events
        SET is_admin_only = %s,
            updated_at = NOW()
        WHERE event_id = %s
    """, (is_admin_only, event_id))
    conn.commit()

    # If it becomes visible to members, make it "NEW" again for members
    if not is_admin_only:
        cursor.execute("DELETE FROM event_reads WHERE event_id = %s", (event_id,))
        conn.commit()

    cursor.close()
    conn.close()

    flash('Audience updated.', 'success')
    return redirect(url_for('admin_events'))


# Edit event (simple: same page, per-row form)
@app.route('/admin/events/<int:event_id>/edit', methods=['POST'])
def admin_edit_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    event_date = request.form.get('event_date', '').strip()
    start_time = request.form.get('start_time', '').strip()
    end_time = request.form.get('end_time', '').strip()
    location = request.form.get('location', '').strip()

    if end_time == '':
        end_time = None

    if not title or not event_date or not start_time:
        flash('Title, Date, and Start time are required.', 'error')
        return redirect(url_for('admin_events'))

    cursor, conn = getCursor(dictionary=True)

    cursor.execute("""
        UPDATE events
        SET title=%s,
            description=%s,
            event_date=%s::date,
            start_time=%s::time,
            end_time=%s::time,
            location=%s,
            updated_at=NOW()
        WHERE event_id=%s
    """, (title, description, event_date, start_time, end_time, location, event_id))
    conn.commit()

    # Event changed => members should see NEW again (only matters for member-visible events)
    cursor.execute("DELETE FROM event_reads WHERE event_id = %s", (event_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash('Event updated.', 'success')
    return redirect(url_for('admin_events'))


# Delete event
@app.route('/admin/events/<int:event_id>/delete', methods=['POST'])
def admin_delete_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)
    cursor.execute("DELETE FROM events WHERE event_id = %s", (event_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Event deleted.', 'success')
    return redirect(url_for('admin_events'))


#---- 2- Admin pin/unpin event -----#

@app.route('/admin/events/<int:event_id>/pin', methods=['POST'])
def admin_pin_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)

    # unpin all, pin selected
    cursor.execute("UPDATE events SET is_pinned = FALSE WHERE is_pinned = TRUE")
    cursor.execute("UPDATE events SET is_pinned = TRUE, updated_at = NOW() WHERE event_id = %s", (event_id,))
    conn.commit()

    # important: event updated => members should see NEW badge again
    cursor.execute("DELETE FROM event_reads WHERE event_id = %s", (event_id,))
    conn.commit()

    cursor.close(); conn.close()
    flash('Event pinned to top.', 'success')
    return redirect(url_for('admin_events'))

 #---- get “active event for member home” ---#
 
def get_active_event(cursor):
    cursor.execute("""
        SELECT *
        FROM events
        WHERE is_pinned = TRUE
          AND COALESCE(is_admin_only, FALSE) = FALSE
          AND (event_date > CURRENT_DATE OR event_date = CURRENT_DATE)
        ORDER BY event_date ASC, start_time ASC
        LIMIT 1
    """)
    pinned = cursor.fetchone()
    if pinned:
        return pinned

    cursor.execute("""
        SELECT *
        FROM events
        WHERE COALESCE(is_admin_only, FALSE) = FALSE
          AND (
               event_date > CURRENT_DATE
               OR (event_date = CURRENT_DATE AND start_time >= CURRENT_TIME)
          )
        ORDER BY event_date ASC, start_time ASC
        LIMIT 1
    """)
    return cursor.fetchone()
  
  #-- Member: mark event as seen ----#
  
@app.route('/member/events/<int:event_id>/seen', methods=['POST'])
def mark_event_seen(event_id):
    if session.get('role') != 'member':
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor, conn = getCursor(dictionary=True)

    cursor.execute("""
        INSERT INTO event_reads (event_id, user_id)
        VALUES (%s, %s)
        ON CONFLICT (event_id, user_id) DO NOTHING
    """, (event_id, user_id))
    conn.commit()

    cursor.close()
    conn.close()
    return ("", 204)
  
#============= MEMBER / CALENDER =========#4955

@app.route('/member/calendar')
def member_calendar():
    if session.get('role') != 'member':
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor, conn = getCursor(dictionary=True)

    # Members only see shared events
    cursor.execute("""
        SELECT *
        FROM events
        WHERE is_admin_only = FALSE
        ORDER BY event_date DESC, start_time DESC
        LIMIT 50
    """)
    events = cursor.fetchall()

    today = date.today()

    # Add status
    for e in events:
        # event_date is usually date already; if it's string, you can parse it
        e_date = e['event_date']
        e['is_expired'] = (e_date < today)

    cursor.close()
    conn.close()

    return render_template('member_calendar.html', events=events)

#========= members can save event - download .ics =========#
@app.route('/member/events/<int:event_id>/ics')
def member_event_ics(event_id):
    if session.get('role') != 'member':
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)
    cursor.execute("""
        SELECT *
        FROM events
        WHERE event_id = %s AND is_admin_only = FALSE
        LIMIT 1
    """, (event_id,))
    e = cursor.fetchone()
    cursor.close()
    conn.close()

    if not e:
        return "Event not found", 404

    # Build basic ICS (no extra libraries)
    # Format: YYYYMMDDTHHMMSSZ (we’ll treat as local time without Z to keep simple)
    dt_start = f"{e['event_date'].strftime('%Y%m%d')}T{str(e['start_time']).replace(':','')[:4]}00"
    dt_end = dt_start
    if e.get('end_time'):
        dt_end = f"{e['event_date'].strftime('%Y%m%d')}T{str(e['end_time']).replace(':','')[:4]}00"

    title = (e.get('title') or 'Lodge Event').replace('\n', ' ')
    desc = (e.get('description') or '').replace('\n', '\\n')
    location = (e.get('location') or '').replace('\n', ' ')

    ics = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Lodge Matariki 476//EN
BEGIN:VEVENT
UID:event-{e['event_id']}@lodge
DTSTART:{dt_start}
DTEND:{dt_end}
SUMMARY:{title}
DESCRIPTION:{desc}
LOCATION:{location}
END:VEVENT
END:VCALENDAR
"""

    return (ics, 200, {
        "Content-Type": "text/calendar; charset=utf-8",
        "Content-Disposition": f"attachment; filename=event_{e['event_id']}.ics"
    })


#==== open Google Calendar ====#

@app.route('/member/events/<int:event_id>/google')
def member_event_google(event_id):
    if session.get('role') not in ('member', 'admin'):
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)
    cursor.execute("""
        SELECT *
        FROM events
        WHERE event_id = %s
        LIMIT 1
    """, (event_id,))
    e = cursor.fetchone()
    cursor.close()
    conn.close()

    if not e:
        return "Event not found", 404

    # Google wants YYYYMMDDTHHMMSS format (no timezone here -> treated as local)
    start = f"{e['event_date'].strftime('%Y%m%d')}T{str(e['start_time'])[:5].replace(':','')}00"
    end = start
    if e.get('end_time'):
        end = f"{e['event_date'].strftime('%Y%m%d')}T{str(e['end_time'])[:5].replace(':','')}00"

    params = {
        "action": "TEMPLATE",
        "text": e.get("title") or "Lodge Event",
        "details": e.get("description") or "",
        "location": e.get("location") or "",
        "dates": f"{start}/{end}",
    }
    return redirect("https://calendar.google.com/calendar/render?" + urlencode(params))


  # ---------- Contact us ------ #

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        message = request.form.get('message', '').strip()

        if not name or not email or not message:
            flash('Please fill in your name, email, and message.', 'error')
            return redirect(url_for('contact'))

        # -------- Save to DB -------- #
        try:
            cursor, conn = getCursor()
            print("DB cursor opened, executing INSERT...")  # Debug
            cursor.execute(
                """
                INSERT INTO contact_messages (name, email, phone, message)
                VALUES (%s, %s, %s, %s)
                """,
                (name, email, phone, message)
            )
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            # If DB fails we still try to send email, but you could log e
            flash('Sorry, there was a problem saving your message.', 'error')
            return redirect(url_for('contact'))

        # -------- Prepare email body -------- #
        body = (
            f"New enquiry from Lodge website\n\n"
            f"Name: {name}\n"
            f"Email: {email}\n"
            f"Phone: {phone}\n\n"
            f"Message:\n{message}\n"
        )

        # -------- Send email -------- #
        try:
            send_email(
            subject="New enquiry from Lodge website",
            body=message,
            name=name,
            email=email,
            phone=phone
            )

            flash('Thank you – your message has been sent.', 'success')
        except Exception as e:
            print("EMAIL ERROR:", repr(e))
            # You can log(e) if you want
            flash('Your message was saved, but there was a problem sending email.', 'error')

        return redirect(url_for('contact'))

    return render_template('contact.html')
  
  # ------------ Send Email ------ #

# def send_email(subject, body):
#     msg = EmailMessage()
#     msg["Subject"] = subject

#     # Use your existing .env keys
#     smtp_user = os.environ.get("EMAIL_USER")
#     smtp_pass = os.environ.get("EMAIL_PASS")

#     if not smtp_user or not smtp_pass:
#         raise Exception("Missing EMAIL_USER / EMAIL_PASS in environment")

#     # where to send (you can send to yourself)
#     to_addr = os.environ.get("EMAIL_TO", smtp_user)

#     msg["From"] = smtp_user
#     msg["To"] = to_addr
#     msg.set_content(body)

#     with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
#         smtp.login(smtp_user, smtp_pass)
#         smtp.send_message(msg)


   # pip install pytz (optional but recommended)


def send_email(subject, body, name, email, phone):
    api_key = os.getenv("RESEND_API_KEY")
    if not api_key:
        raise Exception("Missing RESEND_API_KEY in environment variables!")

    resend.api_key = api_key

    # Recipient – use EMAIL_TO from env, fallback to your Gmail
    to_addr = os.getenv("EMAIL_TO", "lodge417.form@gmail.com")

    # NZ time
    nz_time = datetime.now(pytz.timezone("Pacific/Auckland")).strftime("%d %b %Y at %I:%M %p NZDT")

    # Nice email body
    email_text = f"""Hi Lodge Matariki 476,

You have received a new enquiry from the website:

Name:     {name}
Email:    {email}
Phone:    {phone if phone else 'Not provided'}

Message:
{body}

Received: {nz_time}

---
This message was sent via Resend.com
"""

    try:
        resend.Emails.send({
            "from": "onboarding@resend.dev",  # Safe for testing
            "to": [to_addr],
            "subject": subject,
            "text": email_text,
        })
        print("Email sent successfully to", to_addr)
        return True
    except Exception as e:
        print("RESEND EMAIL FAILED:", str(e))
        raise  # Re-raise so contact route can catch it
      
 #===== minimal health-check route =====#     
@app.route('/health')
def health():
    return "OK", 200
  
  
    #==================== temporary route =======#
  
# @app.route("/debug/db")
# def debug_db():
#     cursor, conn = getCursor(dictionary=True)
#     cursor.execute("SELECT current_database() AS db, inet_server_addr() AS host, inet_server_port() AS port;")
#     row = cursor.fetchone()
#     cursor.close()
#     conn.close()
#     return row

  