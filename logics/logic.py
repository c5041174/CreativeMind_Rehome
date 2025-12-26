import re
import sqlite3
from flask import *
from functools import wraps
import os

#from app import update_password

# from db.init_db import DB_PATH

# list of item conditions
conditions = {
    "conditions": [
        "Brand New",
        "Like New",
        "Gently Used",
        "Good",
        "Fair",
        "Needs Repair",
        "For Parts Only",
    ]
}

# list of item categories
categories = {
    "categories": [
        "Fast foods",
        "Fresh Foods",
        "Goceries",
        "Furniture",
        "Clothing",
        "Electronics",
        "Books",
        "Toys",
        "Kitchenware",
        "Appliances",
        "Tools",
        "Sports",
        "Baby Items",
        "Pet Supplies",
        "Bags",
        "Miscellaneous",
    ]
}


# Establish connection to the SQLite database
def get_db(DB_PATH):
    """Return a sqlite3 connection with row factory as dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# add new user to the database
def register_user(name, email, hashed, conn):

    conn.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed),
    )
    conn.commit()


# Fetch all available items with optional search or category filter
def get_all_items(DB_PATH, selectitem):
    items = selectitem
    conn = get_db(DB_PATH)
    if request.method == "POST":
        Search = request.form.get("search", "").strip().lower()
        if not Search:
            items = conn.execute(
                "SELECT items.*, users.name AS owner_name "
                "FROM items JOIN users ON items.user_id = users.id "
                "WHERE items.status = 'available' "
                "ORDER BY items.created_at DESC"
            ).fetchall()
        else:
            items = conn.execute(
                "SELECT items.*, users.name AS owner_name "
                "FROM items JOIN users ON items.user_id = users.id "
                "WHERE category like ? "
                "ORDER BY items.created_at DESC",
                ("{}%".format(Search),),
            ).fetchall()
    else:
        if not items:
            items = conn.execute(
                "SELECT items.*, users.name AS owner_name "
                "FROM items JOIN users ON items.user_id = users.id "
                "WHERE items.status = 'available' "
                "ORDER BY items.created_at DESC"
            ).fetchall()

        else:
            items = conn.execute(
                "SELECT items.*, users.name AS owner_name "
                "FROM items JOIN users ON items.user_id = users.id "
                "WHERE category = ? "
                "ORDER BY items.created_at DESC",
                (selectitem,),
            ).fetchall()
    conn.commit()
    conn.close()
    return items


# Update user password
def update_password(email, new_hashed_password, DB_PATH):
    conn = get_db(DB_PATH)
    conn.execute(
        "UPDATE users SET password = ? WHERE email = ?", (new_hashed_password, email)
    )
    conn.commit()
    conn.close()


# get an item by its ID with owner details
def get_item_by_id(item_id, DB_PATH):

    conn = get_db(DB_PATH)
    item = conn.execute(
        "SELECT items.*, users.name as owner_name, users.email as owner_email"
        "FROM items JOIN users ON items.user_id = users.id "
        "WHERE items.id = ?",
        (item_id,),
    ).fetchone()
    conn.close()
    return item


# Fetch dashboard items and requests for a user
def get_user_dashboard_items(DB_PATH):
    conn = get_db(DB_PATH)
    items = conn.execute(
        "SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    request_items = conn.execute(
        "SELECT requests.id, requests.status, requests.message, requests.created_at,items.id as item_id, items.title as item_title, u.name as requester_name, u.id, items.image_path "
        "FROM requests JOIN items ON requests.item_id = items.id JOIN users u ON requests.requester_id = u.id "
        "where u.id = ? "
        "ORDER BY requests.created_at DESC",
        (session["user_id"],),
    ).fetchall()
    return items, request_items


# login required decorator
def login_required(func):
    """Decorator to protect routes that need authentication."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login", next=request.path))
        return func(*args, **kwargs)

    return wrapper


# Add new item to the database
def add_new_item(
    title, description, category, condition, image_filename, location, DB_PATH
):
    conn = get_db(DB_PATH)
    conn.execute(
        "INSERT INTO items (user_id, title, description, category, condition, image_path, location) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            session["user_id"],
            title,
            description,
            category,
            condition,
            image_filename,
            location,
        ),
    )
    conn.commit()
    conn.close()


# Get User by email
# valiate if email exists
def get_user_by_email(email, DB_PATH):
    conn = get_db(DB_PATH)
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return user


# Get an item by its ID
def get_item_by_id(item_id, DB_PATH):
    conn = get_db(DB_PATH)
    item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    conn.close()
    return item


# Update an item by its ID
def update_item(
    title, description, category, condition, location, image_path, item_id, DB_PATH
):
    conn = get_db(DB_PATH)
    conn.execute(
        "UPDATE items SET title = ?, description = ?, category = ?, condition = ?, location = ?, image_path = ? WHERE id = ?",
        (
            title,
            description,
            category,
            condition,
            location,
            image_path,
            item_id,
        ),
    )
    conn.commit()
    conn.close()

    # Delete a item by its ID


def delete_item(item_id, DB_PATH):
    conn = get_db(DB_PATH)
    conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()


# Admin control panel data fetch
def admin_control_panel(DB_PATH):
    conn = get_db(DB_PATH)
    users = conn.execute(
        "SELECT id, name, email, is_admin, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
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
    return users, items, requests


def cancle_user_requested_item(DB_PATH, item_id, requester_id):
    conn = get_db(DB_PATH)
    conn.execute(
        "DELETE FROM requests WHERE item_id = ? and requester_id = ?",
        (item_id, requester_id),
    )
    conn.commit()
    conn.close()


def deleteitem(item_id, DB_PATH, UPLOAD_FOLDER):

    conn = get_db(DB_PATH)
    # optionally remove image file
    item = conn.execute(
        "SELECT image_path FROM items WHERE id = ?", (item_id,)
    ).fetchone()
    # delete item record
    if item and item["image_path"]:
        try:

            os.remove(os.path.join(UPLOAD_FOLDER, item["image_path"]))
        except Exception:
            pass
    delete_item(item_id, DB_PATH)
    conn.commit()
    conn.close()
    flash("Item deleted.", "info")
