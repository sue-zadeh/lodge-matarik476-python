from flask_hashing import Hashing

# create a Hashing helper (no need for Flask app here)
hashing = Hashing()

# 1) copy the same salt you use in your project
PASSWORD_SALT = "1234abcd"

# 2) choose the admin password you want
plain = "Admin123!"   # you can change this if you like

# 3) generate the hash
password_hash = hashing.hash_value(plain, PASSWORD_SALT)
print(password_hash)
# a971f9009755b0987811c0fffb46e5ab6745ffaf10cfb4c80ae0e659d25c6004