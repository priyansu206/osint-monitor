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
                expiry_str = cert['notAfter']
                expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:  %S %Y %Z")
                
                # FIXED: Modern timezone-aware UTC datetime
                now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                return (expiry_date - now_utc).days
    except Exception as e:
        # If the cert is already dead, it triggers this exception
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

#    BATCH ENGINE 
if __name__ == "__main__":
    print("--- OSINT SCANNER STARTING (DB MODE) ---")
    
    # 1. Connect to the database
    conn = sqlite3.connect('osint_monitor.db')
    cursor = conn.cursor()

    # 2. Fetch all domains from the targets table
    try:
        cursor.execute("SELECT id, domain_name FROM targets")
        # .fetchall() grabs all the results and puts them in a list of tuples: [(1, 'google.com'), ...]
        domains_from_db = cursor.fetchall() 
    except sqlite3.OperationalError:
        print("[ERROR] Database not found. Did you run db_setup.py?")
        exit()

    if not domains_from_db:
        print("[!] No domains found in the database. Add some first!")
        exit()

    print(f"Loaded {len(domains_from_db)} targets from the database...\n")

    for row in domains_from_db:
        target_id = row[0]       # The ID number
        target_domain = row[1]   # The actual URL
        
        result = check_ssl_expiry(target_domain)
        
        if isinstance(result, int):
            if result < 30:
                print(f"[URGENT] {target_domain}: {result} days left!")
                send_discord_alert(target_domain, result)
            else:
                print(f"[OK] {target_domain}: Healthy ({result} days)")
        else:
            print(f"[ERROR] {target_domain}: {result}")
            send_discord_alert(target_domain, result)
            
        # 5. Update the database to show we just checked this domain
        # This updates the lastchecked column for this specific ID
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE targets SET last_checked = ? WHERE id = ?", (now_utc, target_id))

    # Save the lastchecked updates and close the connection
    conn.commit()
    conn.close()
    
    print("\n--- SCAN COMPLETE ---")