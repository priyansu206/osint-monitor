import ssl
import socket
import datetime
import requests
import os
from dotenv import load_dotenv

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
                expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                
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
    print("=== OSINT SCANNER STARTING ===")
    
    try:
        with open("targets.txt", "r") as f:
            domains = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print("[ERROR] targets.txt missing.")
        exit()

    for target in domains:
        result = check_ssl_expiry(target)
        
        if isinstance(result, int):
            if result < 30:
                print(f"[URGENT] {target}: {result} days left!")
                send_discord_alert(target, result) # Trigger alert for expiring AND already expired certs! also notify about certs that are expiring within 30 days!
            else:
                print(f"[OK] {target}: Healthy")
        else:
            print(f"[ERROR] {target}: {result}")
            send_discord_alert(target, result)