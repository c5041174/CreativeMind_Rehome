"""
app.py - ReHome main Flask application

Features:
- User registration/login (password hashing)
- Post items with image upload
- Browse items, item details
- Request items
- User dashboard (manage own listings)
- Admin panel (manage users/items/requests)
- Simple access control and error handlers

Before running:
1. ensure instance/config.py exists (SECRET_KEY, UPLOAD_FOLDER, DATABASE)
2. run `python init_db.py` to create rehome.db and default admin account
3. install requirements: Flask, Werkzeug
"""

import os
from re import search
import sqlite3

from urllib.request import Request
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory,
    abort,
)
from logics.logic import *
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_cors import CORS

# error = None

# --------------------
# Configuration
# --------------------
app = Flask(__name__, instance_relative_config=True)
CORS(app)

# load instance config if present; fallback defaults
try:
    app.config.from_pyfile("instance/config.py")
except Exception:
    # fallbacks (safe defaults for development)
    app.config.update(
        {
            "SECRET_KEY": "rehome",
            "UPLOAD_FOLDER": "static/uploads",
            "DATABASE": "db/rehome.db",
            "ALLOWED_EXTENSIONS": {"png", "jpg", "jpeg", "gif"},
        }
    )

# ensure upload folder exists
os.makedirs(app.config.get("UPLOAD_FOLDER", "static/uploads"), exist_ok=True)

# convenience
SECRET_KEY = app.config.get("SECRET_KEY", "rehome")
DB_PATH = app.config.get("DATABASE", "db/rehome.db")
UPLOAD_FOLDER = app.config.get("UPLOAD_FOLDER", "static/uploads")
ALLOWED_EXT = set(app.config.get("ALLOWED_EXTENSIONS", {"png", "jpg", "jpeg", "gif"}))

siteName = "ReHome"
app.secret_key = SECRET_KEY  # Required for CSRF protection
csrf = CSRFProtect(app)  # This automatically protects all POST routes


# Set the site name in the app context
@app.context_processor
def inject_site_name():
    return dict(siteName=siteName)


# Create the csrf_token global variable
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())


# API route to check email uniqueness
@app.route("/api/email/")
def email():
    error = None

    email_valid = request.args.get("data", "").strip().lower()
    user = get_user_by_email(email_valid, DB_PATH)
    if user:
        error = f"Email {email_valid} already registered"
        return error
    return ""


# check if uploaded file is allowed
def allowed_file(filename):
    """Check file extension is allowed."""
    if not filename:
        return False
    ext = filename.rsplit(".", 1)[-1].lower()
    return "." in filename and ext in ALLOWED_EXT


# Routes


# Homepage & Item Browsing
@app.route("/search", methods=("GET", "POST"))
@app.route("/")
@app.route("/<selectitem>")
def index(selectitem=None):
    # Homepage - list available items with optional search/category filter

    conn = get_db(DB_PATH)
    items = select_all_items(DB_PATH)
    if request.method == "POST":
        search = request.form.get("search", "").strip().lower()
        if not search:
            items = select_all_items(DB_PATH)
        else:
            items = conn.execute(
                "SELECT items.*, users.name AS owner_name "
                "FROM items JOIN users ON items.user_id = users.id "
                "WHERE category like ? "
                "ORDER BY items.created_at DESC",
                ("{}%".format(search),),
            ).fetchall()
    else:
        if not selectitem:
            items = select_all_items(DB_PATH)
        else:
            # Filter by category
            items = conn.execute(
                "SELECT items.*, users.name AS owner_name "
                "FROM items JOIN users ON items.user_id = users.id "
                "WHERE category = ? AND status = 'available' "
                "ORDER BY created_at DESC",
                (selectitem,),
            ).fetchall()

    conn.close()

    return render_template("index.html", categories=categories, items=items)


# Registration
@app.route("/register/", methods=("GET", "POST"))
def register():
    # Register new user
    if request.method == "POST":
        error = None
        conn = get_db(DB_PATH)
        name = request.form.get("name", "").strip()

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("ConfirmPassword", "")
        # Validate input
        if not name or not email or not password or not confirm_password:
            error = "Please fill in all required fields."
        elif password != confirm_password:
            error = "Passwords do not match!"

        if error == None:
            # All good, proceed to register
            hashed = generate_password_hash(password)
            # Insert user into database
            try:
                register_user(name, email, hashed, conn)
                flash(category="success", message=f"Welcome {name}")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                # likely email uniqueness constraint failed
                flash("Email already registered. Try logging in.", "danger")
            finally:
                # Close the database connection
                conn.close()
        else:
            flash(category="danger", message=error)
            return redirect(url_for("register"))
    # GET request, render registration form
    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    # User login
    next_page = request.args.get("next") or url_for("index")
    if request.method == "POST":
        # Process login form
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        # Validate credentials
        user = get_user_by_email(email, DB_PATH)
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["email"] = user["email"]
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["is_admin"] = bool(user["is_admin"])
            flash("Logged in successfully.", "success")
            return redirect(next_page)
        else:
            flash("Invalid email or password.", "danger")
    # Render login form
    return render_template("login.html")


# Logout
@app.route("/logout/")
def logout():
    # User logout
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------- User Dashboard & Items ----------
@app.route("/dashboard")
@login_required
def dashboard():
    # User dashboard: manage own items and requests
    items, request_items = get_user_dashboard_items(DB_PATH)
    return render_template("dashboard.html", items=items, request_items=request_items)


# Add new item
@app.route("/add-item", methods=["GET", "POST"])
@login_required
def add_item():
    # Add new item
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip()
        condition = request.form.get("condition", "").strip()

        location = f'{request.form.get("location", "").strip()} { request.form.get("Postalcode", "").strip()}'

        image = request.files.get("image")
        image_filename = None

        if not title:
            flash("Title is required.", "danger")
            return redirect(url_for("add_item"))
        # Handle image upload
        if image and image.filename:
            if allowed_file(image.filename):
                filename = secure_filename(image.filename)
                # avoid filename collision by prefixing user id + timestamp
                import time

                prefix = f"{session.get('user_id', 'u')}_{int(time.time())}_"
                filename = prefix + filename
                save_path = os.path.join(UPLOAD_FOLDER, filename)
                image.save(save_path)
                image_filename = filename
            else:
                flash("Invalid image type. Allowed: png, jpg, jpeg, gif.", "danger")
                return redirect(url_for("add_item"))
        # Insert new item into database
        add_new_item(
            title, description, category, condition, image_filename, location, DB_PATH
        )
        flash("Item posted successfully.", "success")
        return redirect(url_for("dashboard"))
    # GET request, render add item form
    return render_template(
        "add_item.html", categories=categories, conditions=conditions
    )


# Item detail page
@app.route("/item/<int:item_id>")
def item_detail(item_id):
    # Item detail page
    item = get_item_by_id(item_id, DB_PATH)
    # Check if item exists
    if not item:
        abort(404)
    return render_template("item.html", item=item)


# Request an item
@app.route("/request-item/<int:item_id>", methods=["POST"])
@login_required
def request_item(item_id):

    message = request.form.get("message", "").strip()
    # check item exists and is available
    conn = get_db(DB_PATH)
    item = conn.execute(
        "SELECT * FROM items WHERE id = ? AND status = 'available'", (item_id,)
    ).fetchone()
    # item not found or not available
    if not item:
        conn.close()
        flash("Item not available.", "warning")
        return redirect(url_for("index"))

    # prevent owner requesting own item
    if item["user_id"] == session["user_id"]:
        conn.close()
        flash("You cannot request your own item.", "warning")
        return redirect(url_for("dashboard"))
    # insert request
    conn.execute(
        "INSERT INTO requests (item_id, requester_id, message) VALUES (?, ?, ?)",
        (item_id, session["user_id"], message),
    )
    # Update item status to 'claimed' if request is approved
    conn.commit()
    conn.close()
    flash("Request submitted. The owner will be notified.", "success")
    return redirect(url_for("dashboard"))


# ---------- Admin ----------
@app.route("/admin")
@login_required
def admin_panel():
    # Admin control panel
    if not session.get("is_admin"):
        abort(403)
    users, items, requests = admin_control_panel(DB_PATH)
    # Render admin panel
    return render_template(
        "admin_panel.html", users=users, items=items, requests=requests
    )


# Delete an item (admin)
@app.route("/admin/delete-item/<int:item_id>")
@login_required
def admin_delete_item(item_id):
    if not session.get("is_admin"):
        abort(403)
    deleteitem(item_id, DB_PATH, UPLOAD_FOLDER)
    # Redirect to admin panel
    return redirect(url_for("admin_panel"))


# Update request status (admin)
@app.route("/admin/update-request/<int:req_id>/<action>")
@login_required
def admin_update_request(req_id, action):
    # Update request status (approve/reject)
    if not session.get("is_admin"):
        abort(403)
    if action not in ("approved", "rejected"):
        abort(400)
        # Update request status in database
    conn = get_db(DB_PATH)
    conn.execute("UPDATE requests SET status = ? WHERE id = ?", (action, req_id))
    conn.commit()
    # optionally, if approved mark item status as 'claimed'
    if action == "approved":
        req = conn.execute(
            "SELECT item_id FROM requests WHERE id = ?", (req_id,)
        ).fetchone()
        # Update item status to 'claimed'
        if req:
            conn.execute(
                "UPDATE items SET status = 'claimed' WHERE id = ?", (req["item_id"],)
            )
            conn.commit()
    conn.close()
    flash("Request updated.", "success")
    # Redirect to admin panel
    return redirect(url_for("admin_panel"))


# ---------- Static uploads route ----------


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ---------- Error handlers ----------
@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def page_not_found(e):
    return render_template("errors/404.html"), 404


# Edit an item Page
@app.route("/update/<int:item_id>/", methods=("GET", "POST"))
@login_required
def update(item_id):

    # Get item data
    item = get_item_by_id(item_id, DB_PATH)

    # Check for errors
    error = None
    if item is None:  # If item not found, add error message
        error = "item not found!"
        flash(category="warning", message=error)
    elif item["user_id"] != session.get(
        "user_id"
    ):  # Check user is only accessing their own items
        error = "You do not have permission to edit this item."
        flash(category="danger", message=error)
    # If there was an error, redirect to items list
    if error:
        return redirect(url_for("/"))

    # If the request method is POST, process the form submission
    if request.method == "POST":

        # Get the input from the form

        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip()
        condition = request.form.get("condition", "").strip()

        location = f'{request.form.get("location", "").strip()} { request.form.get("Postalcode", "").strip()}'

        image = request.files.get("image")
        image_filename = None

        if not title:
            flash("Title is required.", "danger")
            return redirect(url_for("add_item"))

        if image and image.filename:
            if allowed_file(image.filename):
                filename = secure_filename(image.filename)
                # avoid filename collision by prefixing user id + timestamp
                import time

                prefix = f"{session.get('user_id', 'u')}_{int(time.time())}_"
                filename = prefix + filename
                save_path = os.path.join(UPLOAD_FOLDER, filename)

                if filename != item["image_path"]:
                    # delete old image file
                    try:
                        os.remove(os.path.join(UPLOAD_FOLDER, item["image_path"]))
                    except Exception:
                        pass
                image.save(save_path)
                image_filename = filename

            else:
                flash("Invalid image type. Allowed: png, jpg, jpeg, gif.", "danger")
                return redirect(url_for("add_item"))
        # Validate the input
        if not title:
            flash(category="danger", message="Title is required!")
            return redirect(url_for("update", item_id=item_id))

        # Use the database function to update the item
        update_item(
            title,
            description,
            category,
            condition,
            location,
            image_filename,
            item_id,
            DB_PATH,
        )

        # Flash a success message and redirect to the dashboard page
        flash(category="success", message="Updated successfully!")
        return redirect(url_for("dashboard"))

    return render_template(
        "update.html", item=item, categories=categories, conditions=conditions
    )


@app.route("/delete/<int:item_id>", methods=("GET", "POST"))
@login_required
def delete(item_id):

    # Get item data
    item = get_item_by_id(item_id, DB_PATH)
    # Check for errors
    error = None
    if request.method == "POST":
        if item is None:  # If item not found, add error message
            error = "Item not found!"
            flash(category="warning", message=error)
        if item["user_id"] != session.get(
            "user_id"
        ):  # Check user is only accessing their own items
            error = f"You do not have permission to delete this item {session.get('user_id')} ."
            flash(category="danger", message=error)

        # If there was an error, redirect to items list
        if error:
            return redirect(url_for("dashboard"))

        # Use the database function to delete the item
        deleteitem(item_id, DB_PATH, UPLOAD_FOLDER)

        return redirect(url_for("dashboard"))
    return render_template("delete_item.html", item=item)


# Cancel an item
@app.route("/cancel/<int:item_id>", methods=("GET", "POST"))
@login_required
def cancel(item_id):

    item = get_item_by_id(item_id, DB_PATH)

    # Check for errors
    error = None
    if request.method == "POST":
        if item is None:  # If requested item not found, add error message
            error = "requested Item not found!"
            flash(category="warning", message=error)
        elif item["user_id"] == session.get(
            "user_id"
        ):  # Check user is only accessing their own items
            error = "You do not have permission to cancel this requested item."
            flash(category="danger", message=error)

        # If there was an error, redirect to items list
        if error:
            return redirect(url_for("dashboard"))

        cancle_user_requested_item(DB_PATH, item_id, session.get("user_id"))

        # Flash a success message and redirect to the index page
        flash(category="success", message="requested Item canceled successfully!")
        return redirect(url_for("dashboard"))
    return render_template("cancel_item.html", item=item)


@app.route("/update_password", methods=["GET", "POST"])
def update_password():
    # Update user password
    if request.method == "POST":
        email = request.form.get("email")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        # Validate input
        if not email or not new_password or not confirm_password:
            flash(category="danger", message="All fields are required.")
            return redirect(url_for("update_password"))

        if new_password != confirm_password:
            flash(category="danger", message="Passwords do not match.")
            return redirect(url_for("update_password"))

        user = get_user_by_email(email, DB_PATH)
        if not user:
            flash(category="danger", message="User not found.")
            return redirect(url_for("update_password"))

        hashed_new_password = generate_password_hash(new_password)
        update_new_password(hashed_new_password, email, DB_PATH)

        flash(category="success", message="Password updated successfully!")
        return redirect(url_for("login"))

    return render_template("update_password.html")


# --------------------
# Run
# --------------------
if __name__ == "__main__":
    # ensure secret key available in session
    app.secret_key = app.config.get("SECRET_KEY", os.urandom(24))
    # debug True only for development — remove in production
    app.run(debug=True)
