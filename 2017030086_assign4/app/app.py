from flask import Flask, flash, redirect, render_template, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session

import sqlite3 as sql
import os


FLAG = "TUC{fakeflagfortesting}"

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
limiter = Limiter(app, key_func=get_remote_address, default_limits=["500 per hour"])
Session(app)


# Login page
@app.route("/", methods=["GET"])
@limiter.exempt
def home():
    return render_template("login.html")


# LOOK HERE!
# Login request handler
@app.route("/login", methods=["POST"])
@limiter.limit("1/second", override_defaults=False)
def login():
    # grab the password from the request
    password = request.form["password"]
    # LOL no stacked queries are allowed :(
    if ";" in password:
        flash("YOU SUSSY BAKA")
        return render_template("login.html"), 403

    # Hmm... This is safe right? RIGHT?!
    query = f"SELECT * FROM users WHERE username = 'user' AND password = '{password}'"
    # Get a connection to the database
    cursor = con.cursor()
    # Execute the query
    res = cursor.execute(query)
    # If result is empty, then the password is wrong
    if res.fetchone() is None:
        flash("wrong password!")
        return render_template("login.html"), 403

    # Set the session and redirect to the dashboard
    session["logged_in"] = True
    return redirect("/dashboard")


@app.route("/dashboard", methods=["GET"])
@limiter.exempt
def dashboard():
    # Check if the user is logged in
    if not session.get("logged_in"):
        flash("LMAO NO!")
        return render_template("login.html"), 403
    return render_template("dashboard.html")


# LOOK HERE TOO!
@app.route("/search", methods=["POST"])
@limiter.limit("1/second", override_defaults=False)
def search():
    # Check if the user is logged in
    if not session.get("logged_in"):
        flash("LMAO NO!")
        return render_template("login.html"), 403
    # Get the search query
    name = request.form["item_name"]

    # LOL no stacked queries are allowed :(
    if ";" in name:
        flash("YOU SUSSY BAKA")
        return render_template("dashboard.html"), 403

    # Hmm... This looks kinda sus ngl!
    query = f"SELECT name,category,price FROM items WHERE name = '{name}'"
    # print(query)
    # Get a connection to the database
    cursor = con.cursor()
    # Execute the query
    res = cursor.execute(query)
    # Get the results
    results = res.fetchall()[0]
    # print(results)
    # Render the results
    return render_template("dashboard.html", results=results)


# admin page, maybe you'll find something here after you log in?
@app.route("/admin", methods=["GET", "POST"])
@limiter.exempt
def admin():
    if request.method == "GET":
        return render_template("admin_login.html")

    # grab the password from the request
    password = request.form["password"]

    # Nothing can be done here
    query = "SELECT * FROM users WHERE username = 'superadmin'"
    # Get a connection to the database
    cursor = con.cursor()
    # Execute the query
    res = cursor.execute(query).fetchone()
    admin_pass = res[2]
    # print(res, password)
    # If result is empty, then the password is wrong
    if password != admin_pass:
        flash("wrong password!")
        return render_template("admin_login.html"), 403
    # if the password is correct, then render the flag
    return render_template("admin_dashboard.html", flag=FLAG)


if __name__ == "__main__":
    # Connect to the database
    con = sql.connect("./db/database.db", check_same_thread=False)
    # Run the app
    debug = True if os.getenv("FLASK_DEBUG") == "TRUE" else False
    # print(debug)
    app.run(debug=debug, host="0.0.0.0", port=8081)
