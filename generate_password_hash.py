#!/usr/bin/python -tt
# Project: port_selfservice_fantasy
# Filename: generate_password_hash.py
# claudiadeluna
# PyCharm

import bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def main():
    # Generate hashes for our test users
    passwords = {"jsmith": "admin123", "awhite": "admin123", "claudia": "admin123"}

    for username, password in passwords.items():
        hashed = hash_password(password)
        print(f"Username: {username}")
        print(f"Hashed password: {hashed}\n")


# Standard call to the main() function.
if __name__ == "__main__":
    main()
