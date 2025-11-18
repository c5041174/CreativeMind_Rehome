import sqlite3
import hashlib


conn = sqlite3.connect("db/rehome.db")

cursor = conn.cursor()

password = hashlib.sha256("admin123".encode()).hexdigest()

cursor.execute("""
INSERT INTO users (name, email, password, is_admin)
VALUES (?, ?, ?, 1)
""", ("Admin", "admin@rehome.com", password))



print("Admin account created.")

conn.commit()
conn.close()