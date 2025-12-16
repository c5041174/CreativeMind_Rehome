import sqlite3

# from werkzeug.security import generate_password_hash


conn = sqlite3.connect("db/rehome.db")

cursor = conn.cursor()

# hashed = generate_password_hash("group")


items = cursor.execute(
    "SELECT items.*, users.name AS owner_name "
    "FROM items JOIN users ON items.user_id = users.id "
    "WHERE items.status = 'available' "
    "ORDER BY items.created_at DESC "
).fetchall()

for item in items[0:4]:
    print(item[6])

conn.commit()
conn.close()
