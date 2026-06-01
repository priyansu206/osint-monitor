import os
import psycopg2
from dotenv import load_dotenv

# Load the hidden database URL from your .env file
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

def test_supabase_connection():
    print("[*] Initiating connection to Supabase...")
    
    if not DATABASE_URL:
        print("[!] Error: DATABASE_URL not found in .env file.")
        return

    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        cursor.execute("SELECT version(), NOW();")
        db_info = cursor.fetchone()
        
        print("\n✅ SUCCESS: Connected to Supabase Cloud!")
        print(f"🖥️  Server Version: {db_info[0].split(',')[0]}")
        print(f"⏰ Server Time: {db_info[1]}")
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ FAILED TO CONNECT:")
        print(f"Error Details: {e}")

if __name__ == "__main__":
    test_supabase_connection()