import sqlite3

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
