import os
import re
from flask import abort, render_template, request, redirect, url_for, session, flash, send_from_directory
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime, date, timedelta, timezone
from app import app, limiter
from app.security import (
    create_reset_token,
    digest_reset_token,
    hash_password,
    is_modern_password_hash,
    password_validation_error,
    remove_managed_file,
    save_profile_image,
    save_protected_document,
    verify_legacy_password,
    verify_modern_password,
)
from connect import get_db  # our PostgreSQL connection
from email.message import EmailMessage
import smtplib
from urllib.parse import urlencode
import pytz
from contextlib import contextmanager

# Kept only to verify old records once; successful login immediately rehashes with scrypt.
LEGACY_PASSWORD_SALT = '1234abcd'  # nosec B105

logging.basicConfig(level=logging.INFO)
  
  
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

# ---------- Role helper ----------

def render_login_or_register(registered, toLogin, msg, username):
    if toLogin:
        return render_template('login.html', msg=msg, toLogin=toLogin,
                               registered=registered, username=username)
    else:
        return render_template("register.html", msg=msg, toLogin=toLogin)


def norm_role(role):
    """Normalize role text from DB/session (handles None, spaces, casing)."""
    return (role or "").strip().lower()


def escape_ics_text(value):
    """Escape user-managed text before placing it in an iCalendar field."""

    return (value or "").replace("\\", "\\\\").replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n").replace(";", "\\;").replace(",", "\\,")


def password_matches(stored_hash, password):
    """Support legacy accounts while all new/changed passwords use scrypt."""

    if is_modern_password_hash(stored_hash):
        return verify_modern_password(stored_hash, password)
    return verify_legacy_password(stored_hash, password, LEGACY_PASSWORD_SALT)

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


@app.before_request
def refresh_authenticated_identity():
    """Fail closed when an account is deactivated or its role has changed."""

    user_id = session.get('user_id')
    if not user_id or request.endpoint in {'static', 'health'}:
        return None

    try:
        with db_cursor(dictionary=True) as (cursor, _connection):
            cursor.execute(
                """SELECT username, role
                   FROM users
                   WHERE user_id = %s AND COALESCE(is_active, TRUE) = TRUE
                   LIMIT 1""",
                (user_id,)
            )
            current_user = cursor.fetchone()
    except Exception:
        app.logger.exception("Session identity refresh failed")
        session.clear()
        if request.endpoint not in {'home', 'about', 'our_story', 'contact', 'login', 'register', 'forgot_password', 'reset_password'}:
            return "Authentication is temporarily unavailable.", 503
        return None

    if not current_user:
        session.clear()
        if request.endpoint not in {'home', 'about', 'our_story', 'contact', 'login', 'register', 'forgot_password', 'reset_password'}:
            flash('Your session is no longer active. Please contact an administrator.', 'warning')
            return redirect(url_for('login'))
        return None

    session['username'] = current_user['username']
    session['role'] = norm_role(current_user['role'])
    return None
#========================about us =============#

@app.route('/about', methods=['GET'])
def about():
  return render_template("aboutus.html")
#========================================

@app.route('/our_story', methods=['GET'])
def our_story():
  return render_template("ourstory.html")

# ------ register form ------- #

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    form = {
        'username': '',
        'first_name': '',
        'last_name': '',
        'email': '',
        'address': '',
        'birth_date': '',
        'phone': '',
        'role': 'member'
    }
    errors = {}

    if request.method == 'POST':
        form['username'] = request.form.get('username', '').strip()
        form['first_name'] = request.form.get('first_name', '').strip()
        form['last_name'] = request.form.get('last_name', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        form['email'] = request.form.get('email', '').strip()
        form['address'] = request.form.get('address', '').strip()
        form['birth_date'] = request.form.get('birth_date', '').strip()
        form['phone'] = request.form.get('phone', '').strip()

        role = 'member'
        if session.get('role') == 'admin':
            role_from_form = request.form.get('role', 'member')
            if role_from_form in ['admin', 'member']:
                role = role_from_form
        form['role'] = role

        file = request.files.get('profile_image')
        profile_image = None

        # ---- validations ----
        if password != confirm_password:
            errors['confirm_password'] = 'Passwords do not match.'

        if len(form['username']) < 5 or len(form['username']) > 80:
            errors['username'] = 'Username must be at least 5 characters long.'

        if not form['first_name'] or len(form['first_name']) > 80:
            errors['first_name'] = 'First name is required.'

        if not form['last_name'] or len(form['last_name']) > 80:
            errors['last_name'] = 'Last name is required.'

        if len(form['email']) > 190 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', form['email']):
            errors['email'] = 'Invalid email format.'

        if len(form['phone']) > 40 or (form['phone'] and not re.fullmatch(r'[0-9+ ]*', form['phone'])):
            errors['phone'] = 'Phone must contain digits and + only.'

        password_error = password_validation_error(password)
        if password_error:
            errors['password'] = password_error

        if not form['address'] or len(form['address']) > 255:
            errors['address'] = 'Address is required.'

        # strict YYYY-MM-DD only
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', form['birth_date']):
            errors['birth_date'] = 'Birth date must be in YYYY-MM-DD format.'
        else:
            try:
                birth_date_obj = datetime.strptime(form['birth_date'], '%Y-%m-%d')
                birth_date = birth_date_obj.strftime('%Y-%m-%d')
            except ValueError:
                errors['birth_date'] = 'Invalid date. Use real year, month, and day.'
                birth_date = None

        if errors:
            return render_template("register.html", form=form, errors=errors)

        if file and file.filename:
            try:
                profile_image = save_profile_image(file, app.config['UPLOAD_FOLDER'])
            except ValueError as error:
                errors['profile_image'] = str(error)
                return render_template("register.html", form=form, errors=errors)

        cursor, conn = getCursor()
        if not cursor or not conn:
            errors['general'] = 'Database connection error.'
            return render_template("register.html", form=form, errors=errors)

            # Check if username already exists
        cursor.execute(
            """
             SELECT 1
             FROM users
             WHERE LOWER(username) = LOWER(%s)
             """,
             (form['username'],)
            )

        username_exists = cursor.fetchone()

        if username_exists:
            cursor.close()
            conn.close()
            remove_managed_file(app.config['UPLOAD_FOLDER'], profile_image)

            errors['username'] = 'Username already exists.'

            return render_template(
                 "register.html",
                 form=form,
                 errors=errors
             )


        # Check if email already exists
        cursor.execute(
              """
              SELECT 1
              FROM users
              WHERE LOWER(email) = LOWER(%s)
              """,
              (form['email'],)
          )      
        email_exists = cursor.fetchone()

        if email_exists:
               cursor.close()
               conn.close()
               remove_managed_file(app.config['UPLOAD_FOLDER'], profile_image)
          
               errors['email'] = 'Email already exists.'
          
               return render_template(
                  "register.html",
                  form=form,
                  errors=errors
              )
 
        password_hash = hash_password(password)
        is_active = norm_role(session.get('role')) == 'admin'

        cursor.execute(
            """
            INSERT INTO users (
                username, first_name, last_name,
                email, password, phone, address,
                birth_date, profile_image, role, is_active
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                form['username'],
                form['first_name'],
                form['last_name'],
                form['email'],
                password_hash,
                form['phone'],
                form['address'],
                birth_date,
                profile_image,
                form['role'],
                is_active
            )
        )

        conn.commit()
        cursor.close()
        conn.close()

        if is_active:
            flash('Registration successful. The account is active.', 'success')
        else:
            flash('Registration received. An administrator must activate the account before login.', 'success')
        return redirect(url_for('login'))

    return render_template("register.html", form=form, errors=errors)

#-------------- Login -------------#

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute; 30 per hour", methods=["POST"])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        try:
            with db_cursor(dictionary=True) as (cursor, conn):
                cursor.execute("""
                    SELECT user_id, username, password, role
                    FROM users
                    WHERE LOWER(username) = LOWER(%s) AND COALESCE(is_active, TRUE) = TRUE
                    LIMIT 1
                """, (username,))
                user = cursor.fetchone()

                if user and password_matches(user['password'], password):
                    if not is_modern_password_hash(user['password']):
                        cursor.execute(
                            "UPDATE users SET password = %s, updated_at = NOW() WHERE user_id = %s",
                            (hash_password(password), user['user_id'])
                        )
                else:
                    user = None

        except Exception:
            app.logger.exception("Login DB error")
            flash('Login is temporarily unavailable. Please try again.', 'danger')
            return redirect(url_for('login'))

        if user:
            role = norm_role(user.get('role'))

            session.clear()
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

# ---------------- Forgot Password Rout  -----------------------------#

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per hour", methods=["POST"])
def forgot_password():

    if request.method == 'POST':

        # Email typed by the user
        email = request.form.get('email', '').strip().lower()

        if not email:
            flash('Please enter your email address.', 'danger')
            return redirect(url_for('forgot_password'))

        try:
            with db_cursor(dictionary=True) as (cursor, conn):

                # IMPORTANT:
                # We only search the email stored in the member profile.
                cursor.execute("""
                    SELECT user_id, email
                    FROM users
                    WHERE LOWER(email) = %s
                      AND COALESCE(is_active, TRUE) = TRUE
                    LIMIT 1
                """, (email,))

                user = cursor.fetchone()

                if user:

                    # Store only a digest so a database read cannot expose reset links.
                    token, token_digest = create_reset_token()

                    # Link valid for one hour
                    expiry = datetime.now(timezone.utc) + timedelta(hours=1)

                    cursor.execute("""
                        UPDATE users
                        SET password_reset_token = %s,
                            password_reset_token_expiry = %s
                        WHERE user_id = %s
                    """, (
                        token_digest,
                        expiry,
                        user['user_id']
                    ))

                    reset_path = url_for('reset_password', token=token)
                    public_base_url = os.environ.get('PUBLIC_BASE_URL', '').rstrip('/')
                    azure_hostname = os.environ.get('WEBSITE_HOSTNAME', '').strip()
                    if not public_base_url and azure_hostname:
                        public_base_url = f"https://{azure_hostname}"
                    reset_link = (
                        f"{public_base_url}{reset_path}"
                        if public_base_url
                        else url_for(
                            'reset_password',
                            token=token,
                            _external=True,
                            _scheme=os.environ.get("RESET_URL_SCHEME", request.scheme)
                        )
                    )

                    send_password_reset_email(
                        user['email'],
                        reset_link
                    )

        except Exception:
            app.logger.exception('Forgot password error')

        # Always show same message.
        # Do not tell people whether an email exists.
        flash(
            'If this email is registered, a password reset link has been sent.',
            'success'
        )

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


# ======================  Reset Password Rout ===================#

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per hour", methods=["POST"])
def reset_password(token):

    try:

        with db_cursor(dictionary=True) as (cursor, conn):

            cursor.execute("""
                SELECT user_id
                FROM users
                WHERE password_reset_token = %s
                  AND password_reset_token_expiry > NOW()
                  AND COALESCE(is_active, TRUE) = TRUE
                LIMIT 1
            """, (digest_reset_token(token),))

            user = cursor.fetchone()

            if not user:
                flash(
                    'This password reset link is invalid or has expired.',
                    'danger'
                )
                return redirect(url_for('forgot_password'))

            if request.method == 'POST':

                new_password = request.form.get(
                    'new_password',
                    ''
                )

                confirm_password = request.form.get(
                    'confirm_password',
                    ''
                )

                if new_password != confirm_password:
                    flash(
                        'Passwords do not match.',
                        'danger'
                    )

                    return render_template(
                        'reset_password.html'
                    )

                password_error = password_validation_error(new_password)
                if password_error:

                    flash(
                        password_error,
                        'danger'
                    )

                    return render_template(
                        'reset_password.html'
                    )

                password_hash = hash_password(new_password)

                cursor.execute("""
                    UPDATE users
                    SET password = %s,
                        password_reset_token = NULL,
                        password_reset_token_expiry = NULL
                    WHERE user_id = %s
                """, (
                    password_hash,
                    user['user_id']
                ))

                flash(
                    'Your password has been reset successfully. Please login.',
                    'success'
                )

                session.clear()

                return redirect(url_for('login'))

    except Exception:

        app.logger.exception('Reset password error')

        flash(
            'Something went wrong. Please try again.',
            'danger'
        )

        return redirect(url_for('forgot_password'))

    return render_template('reset_password.html')
  
  # ============================== Email Message For Forgot Password ===============#
  
def send_password_reset_email(to_email, reset_link):
    message = EmailMessage()

    message["Subject"] = "Reset your Lodge Matariki password"
    message["To"] = to_email

    message.set_content(
        f"""
Hello,

We received a request to reset your Lodge Matariki password.

Please use the link below to create a new password:

{reset_link}

This link will expire in 1 hour.

If you did not request a password reset, you can ignore this email.

Lodge Matariki 476
"""
    )

    if os.environ.get("EMAIL_SUPPRESS_SEND") == "1":
        app.logger.info("Password-reset email delivery suppressed in the test environment.")
        return

    smtp_user = os.environ.get("EMAIL_USER")
    smtp_pass = os.environ.get("EMAIL_PASS")

    if not smtp_user or not smtp_pass:
        raise Exception("Missing EMAIL_USER or EMAIL_PASS")

    message["From"] = smtp_user

    with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()

        smtp.login(
            smtp_user,
            smtp_pass
        )

        smtp.send_message(message)
        
        
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

@app.route('/logout', methods=['POST'])
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


@app.route('/profiles/<int:user_id>/image')
def profile_image(user_id):
    role = norm_role(session.get('role'))
    if role not in {'member', 'admin'}:
        abort(404)
    if role != 'admin' and user_id != session.get('user_id'):
        abort(404)

    cursor, conn = getCursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT profile_image FROM users WHERE user_id = %s AND is_active = TRUE",
            (user_id,)
        )
        record = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not record or not record.get('profile_image'):
        abort(404)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        record['profile_image'],
        as_attachment=False,
        conditional=True,
    )
      

# ---- Edit Profile ---- #
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor, conn = getCursor(dictionary=True)
    user = None

    try:
        # Always load user (so GET works + also safe if POST fails)
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()

        if request.method == 'POST':
            username = (request.form.get('username') or '').strip()

            # accept both template name styles
            first_name = (request.form.get('first_name') or request.form.get('fname') or '').strip()
            last_name  = (request.form.get('last_name')  or request.form.get('lname')  or '').strip()

            email = (request.form.get('email') or '').strip()

            phone = (request.form.get('phone') or '').strip()
            if phone.lower() == 'none':
                phone = ''
            phone = phone if phone else None

            address = (request.form.get('address') or '').strip()

            if not (5 <= len(username) <= 80):
                flash('Username must be between 5 and 80 characters.', 'error')
                return redirect(url_for('edit_profile'))
            if not first_name or len(first_name) > 80 or not last_name or len(last_name) > 80:
                flash('First and last name are required and must be 80 characters or less.', 'error')
                return redirect(url_for('edit_profile'))
            if len(email) > 190 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
                flash('Please enter a valid email address.', 'error')
                return redirect(url_for('edit_profile'))
            if len(address) > 255 or len(phone or '') > 40:
                flash('Address or phone is too long.', 'error')
                return redirect(url_for('edit_profile'))

            birth_date_raw = (request.form.get('birth_date') or '').strip()
            birth_date = None
            if birth_date_raw:
                try:
                    datetime.strptime(birth_date_raw, '%Y-%m-%d')
                    birth_date = birth_date_raw
                except ValueError:
                    flash('Invalid date format. Use YYYY-MM-DD', 'error')
                    return redirect(url_for('edit_profile'))

            # duplicates check
            cursor.execute("""
                SELECT user_id, username, email
                FROM users
                WHERE (LOWER(username) = LOWER(%s) OR LOWER(email) = LOWER(%s))
                  AND user_id <> %s
            """, (username, email, user_id))
            existing = cursor.fetchone()
            if existing:
                flash('Username or email already exists.', 'error')
                return redirect(url_for('edit_profile'))

            # image
            profile_image = None
            file = request.files.get('profile_image')
            if file and file.filename:
                try:
                    profile_image = save_profile_image(file, app.config['UPLOAD_FOLDER'])
                except ValueError as error:
                    flash(str(error), 'error')
                    return redirect(url_for('edit_profile'))

            cursor.execute("""
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
            """, (username, first_name, last_name, email, phone, address, birth_date, profile_image, user_id))

            conn.commit()
            if profile_image and user and user.get('profile_image') != profile_image:
                remove_managed_file(app.config['UPLOAD_FOLDER'], user.get('profile_image'))
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('profile'))

    except Exception:
        conn.rollback()
        app.logger.exception("Edit profile error")
        flash('Failed to update profile.', 'danger')
        return redirect(url_for('edit_profile'))

    finally:
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
    if file and file.filename:
        try:
            filename = save_profile_image(file, app.config['UPLOAD_FOLDER'])
        except ValueError as error:
            flash(str(error), 'error')
            return redirect(url_for('profile'))

        cursor, conn = getCursor()
        cursor.execute(
            "SELECT profile_image FROM users WHERE user_id = %s",
            (session['user_id'],)
        )
        old_record = cursor.fetchone()
        cursor.execute(
            "UPDATE users SET profile_image = %s WHERE user_id = %s",
            (filename, session['user_id'])
        )
        conn.commit()
        cursor.close()
        conn.close()

        if old_record:
            remove_managed_file(app.config['UPLOAD_FOLDER'], old_record[0])

        flash('Profile photo updated.', 'success')

    return redirect(url_for('profile'))


# ---- Delete profile ---- #
@app.route('/delete_profile', methods=['POST'])
def delete_profile():
    if 'user_id' in session:
        cursor, conn = getCursor(dictionary=True)
        cursor.execute("SELECT profile_image FROM users WHERE user_id = %s", (session['user_id'],))
        user_record = cursor.fetchone()
        cursor.execute("DELETE FROM users WHERE user_id = %s", (session['user_id'],))
        conn.commit()
        cursor.close()
        conn.close()
        if user_record:
            remove_managed_file(app.config['UPLOAD_FOLDER'], user_record.get('profile_image'))
        session.clear()
        flash('Your account has been deleted successfully.', 'success')
        return redirect(url_for('home'))
    else:
        flash('You must be logged in to delete your account.', 'danger')
        return redirect(url_for('login'))


# ---- Change password ---- #
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' in session:
        if request.method == 'POST':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return redirect(url_for('change_password'))

            password_error = password_validation_error(new_password)
            if password_error:
                flash(password_error, 'error')
                return redirect(url_for('change_password'))

            cursor, conn = getCursor(dictionary=True)

            cursor.execute("SELECT password FROM users WHERE LOWER(username) = LOWER(%s)", (session['username'],))
            user = cursor.fetchone()

            if user and password_matches(user['password'], old_password):
                hashed_password = hash_password(new_password)
                cursor.execute(
                    """UPDATE users
                       SET password = %s, password_reset_token = NULL,
                           password_reset_token_expiry = NULL, updated_at = NOW()
                       WHERE LOWER(username) = LOWER(%s)""",
                    (hashed_password, session['username'])
                )
                conn.commit()
                cursor.close()
                conn.close()
                session.clear()
                flash('Password changed successfully. Please login again.', 'success')
                return redirect(url_for('login'))
            else:
                cursor.close()
                conn.close()
                flash('Old password is incorrect or user not found.', 'error')
                return redirect(url_for('change_password'))

        return render_template('password.html')

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
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    # ✅ works for GET (?search=...) and POST (form submit)
    search_term = (request.args.get('search') or request.form.get('search') or "").strip()

    users = []
    message = ""

    cursor, conn = getCursor(dictionary=True)
    try:
        base_sql = """
            SELECT
                user_id, username, first_name, last_name,
                email, phone, address, birth_date,
                profile_image, role, is_active
            FROM users
        """
        params = []

        if search_term:
            base_sql += """
                WHERE
                    COALESCE(first_name,'') ILIKE %s
                    OR COALESCE(last_name,'') ILIKE %s
                    OR COALESCE(username,'') ILIKE %s
                    OR COALESCE(email,'') ILIKE %s
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
# ========== Change role (admin <-> member)
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
#============= Toggle active / inactive
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
#========== # Delete user
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
    profile_image = None
    try:
        cursor.execute("SELECT profile_image FROM users WHERE user_id = %s", (user_id,))
        user_record = cursor.fetchone()
        profile_image = user_record[0] if user_record else None
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()
        remove_managed_file(app.config['UPLOAD_FOLDER'], profile_image)
        flash("User removed successfully.", "success")
    except Exception:
        conn.rollback()
        flash("Failed to delete user.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_manage_users'))
  
  
 # ======================================# 
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

        if not subject or len(subject) > 255 or len(description) > 2000:
            flash('Subject is required (maximum 255 characters); notes may be up to 2000 characters.', 'error')
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
            try:
                filename_on_disk = save_protected_document(
                    upload, app.config['FILE_UPLOAD_FOLDER']
                )
            except ValueError as error:
                flash(str(error), 'error')
                cursor.close(); conn.close()
                return redirect(url_for('admin_files'))

        try:
            if file_id:  # UPDATE
                cursor.execute("SELECT filename FROM files WHERE file_id = %s", (file_id,))
                old_record = cursor.fetchone()
                if not old_record:
                    if filename_on_disk:
                        remove_managed_file(app.config['FILE_UPLOAD_FOLDER'], filename_on_disk)
                    abort(404)
                cursor.execute("""
                    UPDATE files
                    SET subject = %s,
                        description = %s,
                        is_admin_only = %s,
                        filename = COALESCE(%s, filename)
                    WHERE file_id = %s
                """, (subject, description, is_admin_only, filename_on_disk, file_id))
                old_filename = old_record['filename'] if filename_on_disk else None
                message = "File updated successfully."
            else:  # CREATE
                cursor.execute("""
                    INSERT INTO files (subject, description, filename, uploaded_by, is_admin_only)
                    VALUES (%s, %s, %s, %s, %s)
                """, (subject, description, filename_on_disk, session['user_id'], is_admin_only))
                old_filename = None
                message = "File uploaded successfully."

            conn.commit()
            if old_filename:
                remove_managed_file(app.config['FILE_UPLOAD_FOLDER'], old_filename)
            flash(message, 'success')
            return redirect(url_for('admin_files'))
        except Exception as e:
            conn.rollback()
            app.logger.exception("File save error")
            flash("Failed to save file. Check logs.", 'danger')
            return redirect(url_for('admin_files'))
    # GET: SELECT list files
    try:
        cursor.execute("""
            SELECT f.file_id, f.subject, f.description, f.filename, f.created_at,
                   f.is_admin_only, u.username AS uploader
            FROM files f
            JOIN users u ON f.uploaded_by = u.user_id
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
    if audience not in {'public', 'admin'}:
        abort(400)
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

# Serve files securely after checking both the session role and the DB audience.
@app.route('/files/<int:file_id>/download')
def download_file(file_id):
    role = norm_role(session.get('role'))
    if role not in ['member', 'admin']:
        flash('Please login to access files.', 'danger')
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT filename, is_admin_only FROM files WHERE file_id = %s LIMIT 1",
            (file_id,)
        )
        record = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not record or (record['is_admin_only'] and role != 'admin'):
        abort(404)

    return send_from_directory(
        app.config['FILE_UPLOAD_FOLDER'],
        record['filename'],
        as_attachment=True,
        download_name=record['filename'],
    )

#------------ Delete file -----------#

@app.route('/admin/files/<int:file_id>/delete', methods=['POST'])
def delete_file(file_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)
    try:
        cursor.execute("SELECT filename FROM files WHERE file_id = %s", (file_id,))
        record = cursor.fetchone()
        if not record:
            abort(404)
        cursor.execute("DELETE FROM files WHERE file_id = %s", (file_id,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    remove_managed_file(app.config['FILE_UPLOAD_FOLDER'], record['filename'])

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
                JOIN users u ON f.uploaded_by = u.user_id
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
                if audience not in {'members', 'admin'}:
                    abort(400)
                is_admin_only = True if audience == 'admin' else False
                is_pinned = True if request.form.get('is_pinned') else False

                if (not title or len(title) > 255 or len(description) > 5000
                        or len(location) > 255 or not event_date or not start_time):
                    flash('Please fill in Title, Date, and Start time.', 'error')
                    return redirect(url_for('admin_events'))

                try:
                    datetime.strptime(event_date, '%Y-%m-%d')
                    datetime.strptime(start_time, '%H:%M')
                    if end_time:
                        datetime.strptime(end_time, '%H:%M')
                except ValueError:
                    flash('Please enter a valid event date and time.', 'error')
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

    title = escape_ics_text(e.get('title') or 'Lodge Event')
    desc = escape_ics_text(e.get('description'))
    location = escape_ics_text(e.get('location'))

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
    if audience not in {'members', 'admin'}:
        abort(400)
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

    if (not title or len(title) > 255 or len(description) > 5000
            or len(location) > 255 or not event_date or not start_time):
        flash('Title, Date, and Start time are required.', 'error')
        return redirect(url_for('admin_events'))

    try:
        datetime.strptime(event_date, '%Y-%m-%d')
        datetime.strptime(start_time, '%H:%M')
        if end_time:
            datetime.strptime(end_time, '%H:%M')
    except ValueError:
        flash('Please enter a valid event date and time.', 'error')
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
        SELECT event_id, %s
        FROM events
        WHERE event_id = %s AND is_admin_only = FALSE
        ON CONFLICT (event_id, user_id) DO NOTHING
    """, (user_id, event_id))
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

    title = escape_ics_text(e.get('title') or 'Lodge Event')
    desc = escape_ics_text(e.get('description'))
    location = escape_ics_text(e.get('location'))

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
    role = norm_role(session.get('role'))
    if role not in ('member', 'admin'):
        return redirect(url_for('login'))

    cursor, conn = getCursor(dictionary=True)
    cursor.execute("""
        SELECT *
        FROM events
        WHERE event_id = %s
          AND (%s = 'admin' OR is_admin_only = FALSE)
        LIMIT 1
    """, (event_id, role))
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
@limiter.limit("5 per hour", methods=["POST"])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        message = request.form.get('message', '').strip()
        website = request.form.get('website', '').strip()

        # Hidden honeypot: return a normal-looking success without storing bot spam.
        if website:
            flash('Thank you – your message has been sent.', 'success')
            return redirect(url_for('contact'))

        if not name or not email or not message:
            flash('Please fill in your name, email, and message.', 'error')
            return redirect(url_for('contact'))
        if len(message) > 1500:
           flash('Message must be 1500 characters or less.', 'error')
           return redirect(url_for('contact'))  
        
        if len(name) > 100:
           flash('Name is too long.', 'error')
           return redirect(url_for('contact'))

        if len(email) > 190:
           flash('Email is too long.', 'error')
           return redirect(url_for('contact'))

        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or '\n' in email or '\r' in email:
           flash('Please enter a valid email address.', 'error')
           return redirect(url_for('contact'))

        if len(phone) > 20:
           flash('Phone number is too long.', 'error')
           return redirect(url_for('contact')) 

        # -------- Save to DB -------- #
        try:
            cursor, conn = getCursor()
            cursor.execute(
                """
                INSERT INTO contact_messages (name, email, phone, message)
                VALUES (%s, %s, %s, %s)
                """,
                (name, email, phone, message)
            )
            retention_days = max(1, int(os.environ.get('CONTACT_RETENTION_DAYS', '90')))
            cursor.execute(
                """DELETE FROM contact_messages
                   WHERE created_at < NOW() - (%s * INTERVAL '1 day')""",
                (retention_days,)
            )
            conn.commit()
            cursor.close()
            conn.close()
        except Exception:
            app.logger.exception("Contact message database error")
            flash('Sorry, there was a problem saving your message.', 'error')
            return redirect(url_for('contact'))

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
        except Exception:
            app.logger.exception("Contact email delivery error")
            flash('Your message was saved, but there was a problem sending email.', 'error')

        return redirect(url_for('contact'))

    return render_template('contact.html')
  
  # ------------ Send Contact Email ------ #

def send_email(subject, body, name, email, phone):
    to_addr = app.config["CONTACT_EMAIL"]

    nz_time = datetime.now(pytz.timezone("Pacific/Auckland")).strftime("%d %b %Y at %I:%M %p NZDT")

    email_text = f"""Hi Lodge Matariki 476,

You have received a new enquiry from the website:

Name: {name}
Email: {email}
Phone: {phone if phone else 'Not provided'}

Message:
{body}

Received: {nz_time}
"""

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["To"] = to_addr
    msg["Reply-To"] = email
    msg.set_content(email_text)

    if os.environ.get("EMAIL_SUPPRESS_SEND") == "1":
        app.logger.info("Contact email delivery suppressed in the test environment.")
        return

    smtp_user = os.environ.get("EMAIL_USER")
    smtp_pass = os.environ.get("EMAIL_PASS")

    if not smtp_user or not smtp_pass:
        raise Exception("Missing EMAIL_USER or EMAIL_PASS in environment variables")

    msg["From"] = smtp_user

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(smtp_user, smtp_pass)
        smtp.send_message(msg)
      
 #===== minimal health-check route =====#     
@app.route('/health')
def health():
    return "OK", 200


@app.route('/ready')
@limiter.exempt
def ready():
    try:
        with db_cursor() as (cursor, _connection):
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception:
        app.logger.exception("Readiness database check failed")
        return "NOT READY", 503
    return "READY", 200
  
  
    #==================== temporary route =======#
  
# @app.route("/debug/db")
# def debug_db():
#     cursor, conn = getCursor(dictionary=True)
#     cursor.execute("SELECT current_database() AS db, inet_server_addr() AS host, inet_server_port() AS port;")
#     row = cursor.fetchone()
#     cursor.close()
#     conn.close()
#     return row
