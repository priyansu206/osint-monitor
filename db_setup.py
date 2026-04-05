import sqlite3

print("--- BUILDING THE RELATIONAL DATABASE ---")

conn = sqlite3.connect('osint_monitor.db')
cursor = conn.cursor()

cursor.execute('PRAGMA foreign_keys = ON')

# 1. create the users table to store user credentials and link to targets
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    )
''')
print("[+] 'users' table created.")

# 2. create the targets table to store monitored domains, their status, and link back to the user who added them
cursor.execute('''
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_name TEXT NOT NULL,
        last_checked TIMESTAMP,
        status TEXT,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')
print("[+] 'targets' table created and linked to users.")

conn.commit()
conn.close()

print("[+] Database 'osint_monitor.db' built successfully!")