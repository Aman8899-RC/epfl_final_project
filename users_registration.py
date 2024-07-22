
from werkzeug.security import check_password_hash, generate_password_hash
from flask import session
from cs50 import SQL
db = SQL("sqlite:///finance.db")
import re

class UserRegistration:
    password_validator = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@$%#^&*]).{8,}$'

    def __init__(self, username, password, confirmation):
        self.username = username
        self.password = password
        self.confirmation = confirmation

    def is_valid_username(self):
        if not self.username:
            return False, "Please Enter Username"
        if db.execute("SELECT * FROM users WHERE username LIKE ?", self.username):
            return False, "Please Enter Unique Username"
        return True, ""

    def is_valid_password(self):
        if not self.password:
            return False, "Please Enter password"
        if not re.match(self.password_validator, self.password):
            return False, "INVALID password: it must contain capital, small letters, number, and symbol with at least 8 characters"
        if self.password != self.confirmation:
            return False, "Passwords do not match"
        return True, ""

    def register_user(self):
        hasshed_password = generate_password_hash(self.password)
        insert_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", self.username, hasshed_password)
        if insert_user is None:
            return False, "Register failed"
        
        user_id = db.execute("SELECT id FROM users WHERE username = ?", self.username)[0]["id"]
        session["user_id"] = user_id
        return True, ""