import datetime
import os
import re

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

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

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


# creating table for buy, sells, history
db.execute("CREATE TABLE IF NOT EXISTS userparchess (parchess_number INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, shares NUMERIC NOT NULL, price NUMERIC NOT NULL, total_price NUMERIC NOT NULL, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))")
db.execute("CREATE TABLE IF NOT EXISTS usersells (sell_number INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, shares NUMERIC NOT NULL, price NUMERIC NOT NULL, total_price NUMERIC NOT NULL, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))")
db.execute("CREATE TABLE IF NOT EXISTS history (transaction_id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, shares NUMERIC NOT NULL, price TEXT NOT NULL, total_price TEXT NOT NULL, status TEXT NOT NULL, time TEXT NOT NULL, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))")


def time():
    time = datetime.datetime.now()
    time_now = time.strftime("%Y-%m-%d %H:%M:%S")
    return time_now


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # if request.method == "POST":
    """Show portfolio of stocks"""

    share_info = []
    symbol_list = []
    grand_total = 0
    owne_symbol = db.execute("SELECT symbol FROM userparchess WHERE user_id =?", session["user_id"])
    for symbol in owne_symbol:

        if symbol["symbol"] not in symbol_list:
            symbol_list.append(symbol["symbol"])

    for stock_symbol in symbol_list:
        shares_stock = 0
        shares_sum = db.execute("SELECT shares FROM userparchess WHERE user_id =? AND symbol=?", session["user_id"], stock_symbol)

        for i in range(len(shares_sum)):
            shares_stock += shares_sum[i]["shares"]

        price = lookup(stock_symbol)["price"]
        grand_total += price * shares_stock

        share_information = {
            "symbol": stock_symbol,
            "numbershares": shares_stock,
            "currentsharesprice": usd(price),
            "currenttotalprice": usd(price * shares_stock)
        }

        share_info.append(share_information)

    cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"]
    grand_total += cash
    cash = usd(cash)
    grand_total = usd(grand_total)

    return render_template("index.html", share_info=share_info, cash=cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Please enter the symbol for buy")
        symbol_result = lookup(symbol)
        if symbol_result:
            price = symbol_result["price"]
        else:
            return apology("Enetred symbol doesn't exists")

        shares = request.form.get("shares")
        try:
            if not shares or int(shares) < 0:
                return apology("Please enter the shares for buy")
        except:
            return apology("invalid shares")

        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        total_price = int(shares) * price
        balance = balance[0]["cash"]
        if balance < total_price:
            return apology("You don't have enough cash")

        try:
            db.execute("UPDATE users SET cash=? WHERE id=?", balance - total_price, session["user_id"])
        except:
            return apology("Error on updating cash try again")
        # price = usd(price)
        # total_price = usd(price)
        insert_parchessing = db.execute("INSERT INTO userparchess (symbol, shares, price, total_price, user_id) VALUES (?, ?, ?, ?, ?)", symbol, int(
            shares), price, total_price, session["user_id"])
        # symbol shares price total_price status time
        date = time()
        price = usd(price)
        total_history_price = usd(total_price)
        db.execute("INSERT INTO history (symbol, shares, price, total_price, status, time, user_id) VALUES (?,?,?,?,?,?,?)",
                   symbol, int(shares), price, total_history_price, "Buy", date, session["user_id"])
        if insert_parchessing is None:
            return apology("buy shares failes try again")

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history_result = db.execute(
        "SELECT symbol, shares, price, total_price, status, time FROM history WHERE user_id=?", session["user_id"])
    if not history_result:
        return apology("There is no any transaction to display")
    # price = (history_result["price"])

    return render_template("history.html", history_result=history_result)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("please Enter a symbol")
        results = lookup(symbol)
        if results:
            price = usd(results["price"])

            return render_template("quoted.html", results=results, price=price)
        else:
            return apology("The entered symbol doesn't exist")
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        user_registration = UserRegistration(username, password, confirmation)

        is_valid, message = user_registration.is_valid_username()
        if not is_valid:
            return apology(message)

        is_valid, message = user_registration.is_valid_password()
        if not is_valid:
            return apology(message)

        is_registered, message = user_registration.register_user()
        if not is_registered:
            return apology(message)

        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        shares_total = 0
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Please enter a symbol")
        result_symbol = lookup(symbol)
        if not result_symbol:
            return apology("Please enter valid symbol")
        price = result_symbol["price"]

        shares = request.form.get("shares")
        try:
            # Check if symbol is in table userparchess
            owned_symbols = db.execute("SELECT symbol FROM userparchess WHERE user_id =? AND symbol=?", session["user_id"], symbol)

            if not owned_symbols:
                return apology("Sorry you don't have these stock yet")

            # Checking if user input shares or negative
            if not shares or int(shares) < 1:
                return apology("Please enter a valid share")

            # Checing how much the user has in table in userparchess
            owned_shares_for_symbol = db.execute(
                "SELECT shares FROM userparchess WHERE symbol=? AND user_id=?", symbol, session["user_id"])
            if not owned_shares_for_symbol:
                # user_symbol =
                return apology("No shares found")

            # counting shares user owens
            for share in owned_shares_for_symbol:
                shares_total += share["shares"]

            # Checking if user has sufficesnt shares
            if shares_total < int(shares):
                return apology("Sorry you don't have that much shares")

        except ValueError:

            return apology("Invalid shares")

        try:

            db.execute("INSERT INTO usersells (symbol, shares, price , total_price, user_id) VALUES (?,?,?,?,?)",
                       symbol, int(shares), price, (int(shares) * price), session["user_id"])
            date = time()
            # price = usd(price)
            total_history_price = (int(shares) * price)
            db.execute("INSERT INTO history (symbol, shares, price, total_price, status, time, user_id) VALUES (?,?,?,?,?,?,?)",
                       symbol, int(shares), price, total_history_price, "Sell", date, session["user_id"])

            shares = int(shares)
            for share in owned_shares_for_symbol:
                # If shares are greater than 0 to substitue from it the shares_total from the row
                if share["shares"] > shares:
                    db.execute("UPDATE userparchess SET shares=? WHERE user_id=?", (share["shares"] - shares), session["user_id"])
                    break
                else:
                    shares -= share["shares"]
                    db.execute("DELETE from userparchess WHERE shares = ?", share["shares"])

            # Updating cash in users table
            balance = db.execute("SELECT cash FROM users WHERE id = ?", (session["user_id"]))
            balance = balance[0]["cash"]
            db.execute("update users SET cash=?  WHERE id=?", (balance + (price * int(shares))), session["user_id"])

        except Exception as e:
            print(e)
            return apology(f"Selling failed {e}")

        return redirect("/")
    symbol_from_database = db.execute("SELECT symbol FROM userparchess WHERE user_id=?", session["user_id"])
    # print(symbol_from_database)
    symobl_list = []
    for char in symbol_from_database:
        symobl_list.append(char["symbol"])
    # print(symobl_list)
    return render_template("sell.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("password")
        if not password and not confirm_password:
            return apology("Please enter password and confirm it")
        if password != confirm_password:
            return apology("Please eneter same password and confirm it")
        user_password = db.execute("SELECT hash FROM users WHERE id=?", session["user_id"])[0]["hash"]
        if check_password_hash(user_password, password):
            return apology("Please enter a password that's differnt than previous password")
        try:
            # generate_password_hash
            password_validator = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@$%#^&*]).{8,}$'
            if not re.match(password_validator, password):
                return apology("INVALID password at lest it has to contain capital, smal letters, number, and symbol 8 characters ")

            hashed_password = generate_password_hash(password)
            db.execute("UPDATE users SET hash=? WHERE id=?", hashed_password, session["user_id"])
            return redirect("/")
        except Exception as e:
            print(e)
            return apology("Sorry password didn't change")

    return render_template("change_password.html")


@app.route("/adding_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":
        try:

            add_cash = int(request.form.get("add_cash"))
            if add_cash < 10:
                return apology("Minimum adding is 10$")
            balance = db.execute("SELECT cash FROM users WHERE id =?", session["user_id"])
            if not balance:
                return apology("Error occured 1231")
            db.execute("UPDATE users SET cash=? WHERE id=?", (balance[0]["cash"] + add_cash), session["user_id"])
            return redirect("/")
        except Exception as e:
            print(e)
            return apology("Error 400")

    return render_template("adding_cash.html")
