import sqlite3


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


def get_db(DB_PATH):
    """Return a sqlite3 connection with row factory as dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn
