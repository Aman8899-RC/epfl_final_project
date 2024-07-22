import datetime
import os
import re
import routes
from users_registration import UserRegistration
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
# from flask_change_password import ChangePassword, ChangePasswordForm, SetPasswordForm
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from utility import apology, login_required, lookup, usd, Register

# Configure application
app = Flask(__name__)
# app.run(port=5001)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

app.add_url_rule("/", "index", routes.index, methods=["GET", "POST"])
app.add_url_rule("/buy", "buy", routes.buy, methods=["GET", "POST"])
app.add_url_rule("/history", "history", routes.history, methods=["GET"])
app.add_url_rule("/login", "login", routes.login, methods=["GET", "POST"])
app.add_url_rule("/logout", "logout", routes.logout, methods=["GET"])
app.add_url_rule("/quote", "quote", routes.quote, methods=["GET", "POST"])
app.add_url_rule("/register", "register", routes.register, methods=["GET", "POST"])
app.add_url_rule("/sell", "sell", routes.sell, methods=["GET", "POST"])
app.add_url_rule("/change_password", "change_password", routes.change_password, methods=["GET", "POST"])
app.add_url_rule("/adding_cash", "add_cash", routes.add_cash, methods=["GET", "POST"])
if __name__=="__main__":
    app.run(debug=True)