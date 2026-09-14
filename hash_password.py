from getpass import getpass

from app.security import hash_password


if __name__ == "__main__":
    password = getpass("Password to hash: ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    print(hash_password(password))
