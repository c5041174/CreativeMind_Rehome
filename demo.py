import sqlite3

# from werkzeug.security import generate_password_hash


conn = sqlite3.connect("db/rehome.db")

cursor = conn.cursor()

# hashed = generate_password_hash("group")


conn.execute(
    "DELETE from requests WHERE item_id = 1",
).fetchone()


# print(selectitem)

conn.commit()
conn.close()
