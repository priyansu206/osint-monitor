import ssl
import socket
import datetime
import requests
import os
from dotenv import load_dotenv
import sqlite3

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
def check_ssl_expiry(domain):
    print(f"[*] Checking {domain}...")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                # 1. Extract the "notAfter" field from the certificate (This is a string like "Jun 30 12:00:00 2024 GMT")
                expiry_str = cert['notAfter']
                
                # 2. Convert that string into seconds since the epoch
                timestamp = ssl.cert_time_to_seconds(expiry_str)
                
                # 3. Convert seconds into a proper UTC Date object
                expiry_date = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                
                # 4. Calc the diff in days
                return (expiry_date - now_utc).days
    except Exception as e:
        # If the cert is completely invalid/expired, or if there's a connection error, we catch it here and return the error message
        return f"SSL Verification Failed: {e}"
#     DISCORD ALERTING 
def send_discord_alert(domain, issue):
    if not DISCORD_WEBHOOK_URL:
        print("[!] Error: Webhook URL not found in .env file!")
        return

    # Handle both "days left" (int) and "connection errors" (str)
    if isinstance(issue, int):
        status_message = f"SSL expires in **{issue} days**!"
    else:
        status_message = f"Connection Error: `{issue}`"

    message = {
        "content": f"🚨 **SECURITY ALERT PLEASE INVESTIGATE** 🚨\n**Target:** `{domain}`\n**Status:** {status_message}"
    }
    
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=message)
        if response.status_code == 204:
            print(f"[!] Alert sent to Discord for {domain}")
        else:
            print(f"[!] Discord rejected the message. Status Code: {response.status_code}")
    except Exception as e:
        print(f"[!] Webhook failed: {e}")

# --- BATCH ENGINE---
if __name__ == "__main__":
    print("--- OSINT SCANNER STARTING ---")
    
    conn = sqlite3.connect('osint_monitor.db')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, domain_name FROM targets")
        domains_from_db = cursor.fetchall() 
    except sqlite3.OperationalError:
        print("[ERROR] Database not found. Did you run db_setup.py?")
        exit()

    if not domains_from_db:
        print("[!] No domains found in the database.")
        exit()

    for row in domains_from_db:
        target_id = row[0]       
        target_domain = row[1]   
        
        result = check_ssl_expiry(target_domain)
        
        if isinstance(result, int):
            if result < 30:
                status_text = f"🚨 Expiring ({result} days)"
                print(f"[URGENT] {target_domain}: {result} days left!")
                send_discord_alert(target_domain, result)
            else:
                status_text = f"✅ Healthy ({result} days)"
                print(f"[OK] {target_domain}: Healthy ({result} days)")
        else:
            status_text = "❌ Error (See Logs)"
            print(f"[ERROR] {target_domain}: {result}")
            send_discord_alert(target_domain, result)
            
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE targets SET last_checked = ?, status = ? WHERE id = ?", (now_utc, status_text, target_id))

    conn.commit()
    conn.close()
    
    print("\n--- SCAN COMPLETE ---")