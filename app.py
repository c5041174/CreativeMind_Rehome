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
2. run `python create_db.py` to create rehome.db and default admin account
3. install requirements: Flask, Werkzeug
"""
import os
import sqlite3
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf


# --------------------
# Configuration
# --------------------
app = Flask(__name__, instance_relative_config=True)

# load instance config if present; fallback defaults
try:
    app.config.from_pyfile('instance/config.py')
except Exception:
    # fallbacks (safe defaults for development)
    app.config.update({
        "SECRET_KEY": "rehome",
        "UPLOAD_FOLDER": "static/uploads",
        "DATABASE": "db/rehome.db",
        "ALLOWED_EXTENSIONS": {"png", "jpg", "jpeg", "gif"}
    })

# ensure upload folder exists
os.makedirs(app.config.get('UPLOAD_FOLDER', 'static/uploads'), exist_ok=True)

# convenience
SECRET_KEY =app.config.get("SECRET_KEY", "rehome")
DB_PATH = app.config.get('DATABASE', 'db/rehome.db')
UPLOAD_FOLDER = app.config.get('UPLOAD_FOLDER', 'static/uploads')
ALLOWED_EXT = set(app.config.get('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif'}))

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



# --------------------
# Helpers
# --------------------
def get_db():
    """Return a sqlite3 connection with row factory as dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def allowed_file(filename):
    """Check file extension is allowed."""
    if not filename:
        return False
    ext = filename.rsplit('.', 1)[-1].lower()
    return '.' in filename and ext in ALLOWED_EXT

def login_required(func):
    """Decorator to protect routes that need authentication."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for('login', next=request.path))
        return func(*args, **kwargs)
    return wrapper

# --------------------
# Routes
# --------------------
@app.route("/")
def index():
    """Homepage: list available items."""
    conn = get_db()
    items = conn.execute(
        "SELECT items.*, users.name AS owner_name "
        "FROM items JOIN users ON items.user_id = users.id "
        "WHERE items.status = 'available' "
        "ORDER BY items.created_at DESC"
    ).fetchall()
    conn.commit()
    conn.close()
    return render_template("index.html", items=items)
    

# ---------- Authentication ----------
@app.route("/register/", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        conn = get_db()
        error = None
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("ConfirmPassword","")
        
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if not name or not email or not password or not confirm_password:
            error = "Please fill in all required fields."
        elif password != confirm_password:
            error = 'Passwords do not match!'
        elif user :
            error = f"Email {email} already exits"
        if error is None :
            
            hashed = generate_password_hash(password)

            try:
                conn.execute(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, hashed)
                )
                conn.commit()
                flash(category='success', message=f"Welcome {name}")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Email already registered. Try logging in.", "danger")
            finally:
                conn.close()
        else:
            flash(category='danger', message=error)
            return redirect(url_for("register"))
            
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    next_page = request.args.get('next') or url_for('dashboard')
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

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

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

# ---------- User Dashboard & Items ----------
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    items = conn.execute(
        "SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", items=items)


@app.route("/add-item", methods=["GET", "POST"])
@login_required
def add_item():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip()
        condition = request.form.get("condition", "").strip()
        location = request.form.get("location", "").strip()
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
                image.save(save_path)
                image_filename = filename
            else:
                flash("Invalid image type. Allowed: png, jpg, jpeg, gif.", "danger")
                return redirect(url_for("add_item"))

        conn = get_db()
        conn.execute(
            "INSERT INTO items (user_id, title, description, category, condition, image_path, location) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session["user_id"], title, description, category, condition, image_filename, location)
        )
        conn.commit()
        conn.close()
        flash("Item posted successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_item.html")


@app.route("/item/<int:item_id>")
def item_detail(item_id):
    conn = get_db()
    item = conn.execute(
        "SELECT items.*, users.name AS owner_name, users.email AS owner_email "
        "FROM items JOIN users ON items.user_id = users.id "
        "WHERE items.id = ?",
        (item_id,)
    ).fetchone()
    conn.close()
    if not item:
        abort(404)
    return render_template("item.html", item=item)


@app.route("/request-item/<int:item_id>", methods=["POST"])
@login_required
def request_item(item_id):
    message = request.form.get("message", "").strip()
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE id = ? AND status = 'available'", (item_id,)).fetchone()
    if not item:
        conn.close()
        flash("Item not available.", "warning")
        return redirect(url_for("index"))

    # prevent owner requesting own item
    if item["user_id"] == session["user_id"]:
        conn.close()
        flash("You cannot request your own item.", "warning")
        return redirect(url_for("dashboard"))

    conn.execute(
        "INSERT INTO requests (item_id, requester_id, message) VALUES (?, ?, ?)",
        (item_id, session["user_id"], message)
    )
    conn.commit()
    conn.close()
    flash("Request submitted. The owner will be notified.", "success")
    return redirect(url_for("dashboard"))

# ---------- Admin ----------
@app.route("/admin")
@login_required
def admin_panel():
    if not session.get("is_admin"):
        abort(403)
    conn = get_db()
    users = conn.execute("SELECT id, name, email, is_admin, created_at FROM users ORDER BY created_at DESC").fetchall()
    items = conn.execute(
        "SELECT items.id, items.title, items.status, users.name AS owner_name "
        "FROM items JOIN users ON items.user_id = users.id ORDER BY items.created_at DESC"
    ).fetchall()
    requests = conn.execute(
        "SELECT requests.id, requests.status, requests.message, requests.created_at, items.title as item_title, u.name as requester_name "
        "FROM requests JOIN items ON requests.item_id = items.id JOIN users u ON requests.requester_id = u.id "
        "ORDER BY requests.created_at DESC"
    ).fetchall()
    conn.close()
    return render_template("admin_panel.html", users=users, items=items, requests=requests)


@app.route("/admin/delete-item/<int:item_id>")
@login_required
def admin_delete_item(item_id):
    if not session.get("is_admin"):
        abort(403)
    conn = get_db()
    # optionally remove image file
    item = conn.execute("SELECT image_path FROM items WHERE id = ?", (item_id,)).fetchone()
    if item and item["image_path"]:
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, item["image_path"]))
        except Exception:
            pass
    conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    flash("Item deleted.", "info")
    return redirect(url_for("admin_panel"))


@app.route("/admin/update-request/<int:req_id>/<action>")
@login_required
def admin_update_request(req_id, action):
    if not session.get("is_admin"):
        abort(403)
    if action not in ("approved", "rejected"):
        abort(400)
    conn = get_db()
    conn.execute("UPDATE requests SET status = ? WHERE id = ?", (action, req_id))
    conn.commit()
    # optionally, if approved mark item status as 'claimed'
    if action == "approved":
        req = conn.execute("SELECT item_id FROM requests WHERE id = ?", (req_id,)).fetchone()
        if req:
            conn.execute("UPDATE items SET status = 'claimed' WHERE id = ?", (req["item_id"],))
            conn.commit()
    conn.close()
    flash("Request updated.", "success")
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

# --------------------
# Run
# --------------------
if __name__ == "__main__":
    # ensure secret key available in session
    app.secret_key = app.config.get("SECRET_KEY", os.urandom(24))
    # debug True only for development — remove in production
    app.run(debug=True)
