import sqlite3

print("=== BUILDING THE DATABASE ===")

# 1. Connect to the database
# (If 'osint_monitor.db' doesn't exist, SQLite automatically creates it!)
conn = sqlite3.connect('osint_monitor.db')

# 2. Create a cursor (The tool that executes our SQL commands)
cursor = conn.cursor()

# 3. Write the SQL command to build our table
# We are creating a table called 'targets' with 4 specific columns
cursor.execute('''
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_name TEXT NOT NULL UNIQUE,
        last_checked TIMESTAMP,
        status TEXT
    )
''')

# Let's add your initial domains into the database right now
initial_domains = [
    ("google.com",),
    ("github.com",),
    ("expired.badssl.com",)
]

# Insert them using INSERT OR IGNORE (so it doesn't crash if they already exist)
cursor.executemany('''
    INSERT OR IGNORE INTO targets (domain_name) 
    VALUES (?)
''', initial_domains)

# 4. Save (commit) the changes and close the connection
conn.commit()
conn.close()

print("[+] Database 'osint_monitor.db' created successfully!")
print("[+] Table 'targets' initialized with default domains.")
