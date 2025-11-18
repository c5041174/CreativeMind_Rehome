DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS items;
DROP TABLE IF EXISTS requests;



-- Create a table to store user account information
CREATE TABLE users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL,
email TEXT NOT NULL UNIQUE,
password TEXT NOT NULL,
location TEXT,
is_admin INTEGER DEFAULT 0,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
-- Create a table to store items  information
CREATE TABLE items (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
title TEXT NOT NULL,
description TEXT,
category TEXT,
condition TEXT,
image_path TEXT,
location TEXT,
status TEXT DEFAULT 'available',
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
-- Create a table to store requests information
CREATE TABLE requests (
id INTEGER PRIMARY KEY AUTOINCREMENT,
item_id INTEGER NOT NULL,
requester_id INTEGER NOT NULL,
status TEXT DEFAULT 'pending',
message TEXT,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE
);



