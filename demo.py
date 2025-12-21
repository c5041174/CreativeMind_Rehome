import sqlite3

# from werkzeug.security import generate_password_hash


conn = sqlite3.connect("db/rehome.db")

cursor = conn.cursor()

# hashed = generate_password_hash("group")


item = cursor.execute("delete FROM items WHERE id = ?", (21,)).fetchone()


print(item)

conn.commit()
conn.close()
