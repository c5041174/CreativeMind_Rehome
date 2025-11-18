import sqlite3
from werkzeug.security import generate_password_hash
import os


try:
    DB_PATH = 'rehome.db'
    conn = None

    if os.path.exists(DB_PATH):
        print("Database already exists at", DB_PATH)
        
    else:
        conn = sqlite3.connect(DB_PATH) # Connect to the database
        with open('schema.sql') as f: # Open the schema file
            conn.executescript(f.read()) # Execute the schema script to create tables
            
        
    c = conn.cursor()

    c.execute('PRAGMA foreign_keys = ON;')

    # insert default admin
    admin_password = generate_password_hash('AdminPass123')
    c.execute('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)',
    ('Admin', 'admin@rehome.local', admin_password, 1))

    conn.commit()
    conn.close()
    print('Database created and admin user inserted (email: admin@rehome.local, password: AdminPass123)')
except Exception :
    print("connection error")
    