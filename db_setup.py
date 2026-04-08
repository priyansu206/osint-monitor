import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")

def setup_cloud_db():
    print("[*] Connecting to Supabase...")
    try:
        # Connect to the database using the URL from the environment variable. Psycopg2 can parse the URL directly, so we can just pass it in.
        conn = psycopg2.connect(DB_URL)
        cursor = conn.cursor()

        print("[*] Building Users table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')

        print("[*] Building Targets table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                domain_name VARCHAR(255) NOT NULL,
                last_checked TIMESTAMP,
                status VARCHAR(100),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        # Save the changes and close the connection.
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ SUCCESS: Cloud database matrix fully constructed!")

    except Exception as e:
        print(f"❌ ERROR: Could not connect to Supabase. Check your password and URL.")
        print(e)

if __name__ == '__main__':
    setup_cloud_db()