import ssl
import socket
import datetime
import requests
import os
from dotenv import load_dotenv
import sqlite3

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# 1.UPTIME MONITORING
def check_uptime(domain):
    print(f"[*] Pinging {domain} for uptime...")
    url = f"https://{domain}"
    try:
        # We give the server 5 seconds to answer the door
        response = requests.get(url, timeout=5)
        
        # HTTP 200 = "OK! I am alive!"
        if response.status_code == 200:
            return True
        else:
            return f"HTTP {response.status_code}" 
    except requests.exceptions.RequestException:
        # the server is dead
        return "Connection Failed"

# 2.SSL MONITORING
def check_ssl_expiry(domain):
    print(f"[*] Checking SSL for {domain}...")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                expiry_str = cert['notAfter']
                timestamp = ssl.cert_time_to_seconds(expiry_str)
                expiry_date = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                return (expiry_date - now_utc).days
    except Exception as e:
        return f"SSL Verification Failed: {e}"

# 3.DISCORD ALERTING 
def send_discord_alert(domain, issue):
    if not DISCORD_WEBHOOK_URL:
        print("[!] Error: Webhook URL not found in .env file!")
        return

    # Handles "days left" , "connection errors", and "uptime errors"
    if isinstance(issue, int):
        status_message = f"SSL expires in **{issue} days**!"
    else:
        status_message = f"Issue: `{issue}`"

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

# 4. UPDATED: BATCH ENGINE
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
        
        # --- THE NEW LOGIC FLOW ---
        # Step 1: Ping the server first
        uptime_result = check_uptime(target_domain)

        if uptime_result is True:
            # Step 2: If the server is awake, check the SSL
            ssl_result = check_ssl_expiry(target_domain)
            
            if isinstance(ssl_result, int):
                if ssl_result < 30:
                    status_text = f"🟢 UP | 🚨 Expiring ({ssl_result} days)"
                    print(f"[URGENT] {target_domain}: {ssl_result} days left!")
                    send_discord_alert(target_domain, ssl_result)
                else:
                    status_text = f"🟢 UP | ✅ Healthy ({ssl_result} days)"
                    print(f"[OK] {target_domain}: Healthy ({ssl_result} days)")
            else:
                status_text = f"🟢 UP | ❌ Error (See Logs)"
                print(f"[ERROR] {target_domain}: {ssl_result}")
                send_discord_alert(target_domain, ssl_result)
        else:
            # Step 3: If the server is dead, skip SSL and yell at Discord
            status_text = f"🔴 DOWN ({uptime_result})"
            print(f"[URGENT] {target_domain} IS OFFLINE! ({uptime_result})")
            send_discord_alert(target_domain, f"SERVER OFFLINE: {uptime_result}")
            
        # Step 4: Save the combined status to the database
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE targets SET last_checked = ?, status = ? WHERE id = ?", (now_utc, status_text, target_id))

    conn.commit()
    conn.close()
    
    print("\n--- SCAN COMPLETE ---")