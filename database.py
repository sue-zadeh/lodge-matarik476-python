# # database.py
# import mysql.connector
# import app.connect as connect

# db_connection = None

# def getCursor(dictionary=False, buffered=False):
#     global db_connection
#     try:
#         if db_connection is None or not db_connection.is_connected():
#             db_connection = mysql.connector.connect(
#                 user=connect.dbuser,
#                 password=connect.dbpass,
#                 host=connect.dbhost,
#                 database=connect.dbname,
#                 auth_plugin='mysql_native_password',
#                 autocommit=True
#             )
#             print("Connection successful")
#         cursor = db_connection.cursor(dictionary=dictionary, buffered=buffered)
#         return cursor, db_connection
#     except mysql.connector.Error as e:
#         print("Error while connecting to MySQL", e)
#         return None, None