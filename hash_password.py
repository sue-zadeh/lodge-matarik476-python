from app import app
from flask_hashing import Hashing

PASSWORD_SALT = "1234abcd"

hashing = Hashing(app)

plain = "Admin123!"
hashed = hashing.hash_value(plain, PASSWORD_SALT)

print("HASH:", hashed)
print("CHECK:", hashing.check_value(hashed, plain, PASSWORD_SALT))  # must be True

# HASH: a971f9009755b0987811c0fffb46e5ab6745ffaf10cfb4c80ae0e659d25c6004