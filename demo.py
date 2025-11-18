import sqlite3
import os

conn = sqlite3.connect("db/rehome.db")

cosur = conn.cursor()


items = cosur.execute(
        "SELECT items.*, users.name AS owner_name "
        "FROM items JOIN users ON items.user_id = users.id "
        "WHERE items.status = 'available' "
        "ORDER BY items.created_at DESC"
    ).fetchall()

print(items)

conn.commit()
conn.close()