import sqlite3

# from werkzeug.security import generate_password_hash


conn = sqlite3.connect("db/rehome.db")

cursor = conn.cursor()

# hashed = generate_password_hash("group")

items = conn.execute(
    "SELECT items.*, users.name, users.email  "
    "FROM items JOIN users ON items.user_id = users.id "
    "WHERE items.id = ?",
    (15,),
).fetchone()


print(items)

conn.commit()
conn.close()
