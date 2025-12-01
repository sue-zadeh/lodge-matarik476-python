# import os
# import re
# from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
# from werkzeug.utils import secure_filename
# from flask_hashing import Hashing
# import logging
# import psycopg2
# import psycopg2.extras
# from datetime import datetime
# from app import app
# from app.connect import get_db  # our PostgreSQL connection
# from datetime import timedelta

# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

# PASSWORD_SALT = '1234abcd'

# hashing = Hashing(app)
# logging.basicConfig(level=logging.DEBUG)

# UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



# # ---------- DB helper ----------

# def getCursor(dictionary: bool = False):
#     """
#     Returns (cursor, connection).
#     If dictionary=True -> rows as dicts (for column names).
#     """
#     conn = get_db()

#     if dictionary:
#         cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
#     else:
#         cursor = conn.cursor()

#     return cursor, conn


# # ---------- File helpers ----------

# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


# def save_profile_photo(photo):
#     if photo and allowed_file(photo.filename):
#         filename = secure_filename(photo.filename)
#         photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#         photo.save(photo_path)
#         return filename
#     return None


# # ---------- Role helper ----------

# def redirect_based_on_role(html_file):
#     if "member" in session:
#         return redirect(url_for("community"))
#     elif "admin" in session:
#         return redirect(url_for("community"))
#     else:
#         return render_template(html_file)


# def render_login_or_register(registered, toLogin, msg, username):
#     if toLogin:
#         return render_template('login.html', msg=msg, toLogin=toLogin,
#                                registered=registered, username=username)
#     else:
#         return render_template("register.html", msg=msg, toLogin=toLogin)


# def uploaded_file(filename):
#     return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# @app.route('/admin/members')
# def manage_members():
#     if session.get('role') != 'admin':
#         return redirect(url_for('login'))
#     return render_template('admin_manage_members.html')


# @app.route('/admin/settings')
# def admin_settings():
#     if session.get('role') != 'admin':
#         return redirect(url_for('login'))
#     return render_template('admin_settings.html')


# @app.route('/admin/announcements/create')
# def create_announcement():
#     if session.get('role') != 'admin':
#         return redirect(url_for('login'))
#     return render_template('admin_create_announcement.html')


# @app.route('/admin/files/upload')
# def upload_file():
#     if session.get('role') != 'admin':
#         return redirect(url_for('login'))
#     return render_template('admin_upload_file.html')
#   @app.route('/admin/whats_next', methods=['POST'])
# def admin_whats_next():
#     if session.get('role') != 'admin':
#         return redirect(url_for('login'))

#     text = request.form.get('whats_next', '').strip()

#     if not text:
#         flash('Message cannot be empty.', 'warning')
#         return redirect(url_for('admin_home'))

#     cursor, conn = getCursor()
#     cursor.execute(
#         "INSERT INTO whats_next (content) VALUES (%s)",
#         (text,)
#     )
#     conn.commit()
#     cursor.close()
#     conn.close()

#     flash('“What’s Happening Next” message updated.', 'success')
#     return redirect(url_for('admin_home'))

