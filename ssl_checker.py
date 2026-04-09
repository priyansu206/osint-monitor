import ssl
import socket
import datetime
import requests
import os
from dotenv import load_dotenv
import psycopg2 

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
DATABASE_URL = os.getenv("DATABASE_URL")
# 1.UPTIME MONITORING
def check_uptime(domain):
    if domain == "evil-test.com":
        return "MALWARE FLAGGED"
    
    print(f"[*] Pinging {domain} for uptime...")
    url = f"https://{domain}"
    try:
        #only care if the server is responding or not.
        response = requests.get(url, timeout=5)
        
        # IF HTTP 200 = UP, ELSE = SERVER IS UP BUT SOMETHING IS WRONG (LIKE A 500 ERROR)
        if response.status_code == 200:
            return True
        else:
            return f"HTTP {response.status_code}" 
    except requests.exceptions.RequestException:
        # the server is dead
        return "Connection Failed"

# 3.THREAT INTELLIGENCE CHECK
def check_threat_intel(domain):
    print(f"[*] Asking URLhaus if {domain} is malicious...")
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    
    data = {'host': domain} 
    
    try:
        response = requests.post(url, data=data, timeout=10)
        
        if response.status_code == 200: 
            json_data = response.json()
            if json_data.get('query_status') == 'ok':
                return "MALWARE FLAGGED"
            else:
                return "SAFE"
        else:
            return "API Error"
    except Exception as e:
        return "API Timeout"
    
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
    
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, domain_name FROM targets")
        domains_from_db = cursor.fetchall() 
    except Exception as e:
        print(f"[ERROR] Could not connect to Cloud Database. Error: {e}")
        exit()

    if not domains_from_db:
        print("[!] No domains found in the database.")
        exit()
        
    for row in domains_from_db:
        target_id = row[0]       
        target_domain = row[1]  
        # the flow of logic here is:
        # Step A: we check if the server is responding to requests. If it's not responding, we skip the rest of the checks because if it's offline, it doesn't matter if the SSL is expired or if it's flagged for malware - the server is down and that's the most urgent issue to address. If it is responding, then we proceed to check the threat intelligence and SSL status.
        uptime_result = check_uptime(target_domain)

        if uptime_result is True:
            
            # Step B: If the server is responding, we check the threat intelligence to see if it's flagged for malware. This is important to do before the SSL check because if the domain is serving malware, that's a critical issue that needs immediate attention, and it might not even be worth checking the SSL status if it's already compromised. If it's flagged for malware, we alert immediately. If it's not flagged, then we proceed to check the SSL status.
            threat_status = check_threat_intel(target_domain)
            
            if threat_status == "MALWARE FLAGGED":
                status_text = f"🟢 UP | 💀 MALWARE DETECTED!"
                print(f"[URGENT] {target_domain} IS SERVING MALWARE!")
                send_discord_alert(target_domain, "CRITICAL: Domain flagged for Malware by URLhaus Threat Intel!")
                
            else:
                # Step C: If the server is responding and not flagged for malware, check the SSL
                ssl_result = check_ssl_expiry(target_domain)
                
                if isinstance(ssl_result, int):
                    if ssl_result < 30:
                        status_text = f"🟢 UP | 🛡️ SAFE | 🚨 SSL Expiring ({ssl_result} days)"
                        send_discord_alert(target_domain, ssl_result)
                    else:
                        status_text = f"🟢 UP | 🛡️ SAFE | ✅ SSL ({ssl_result} days)"
                else:
                    status_text = f"🟢 UP | 🛡️ SAFE | ❌ SSL Error"
                    send_discord_alert(target_domain, ssl_result)
        else:
            # Step D: If the server is not responding, skip everything else
            status_text = f"🔴 DOWN ({uptime_result})"
            print(f"[URGENT] {target_domain} IS OFFLINE! ({uptime_result})")
            send_discord_alert(target_domain, f"SERVER OFFLINE: {uptime_result}")
            
        # Step E: Save the combined status to the database
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("UPDATE targets SET last_checked = %s, status = %s WHERE id = %s", (now_utc, status_text, target_id))

    conn.commit()
    conn.close()
    
    print("\n--- SCAN COMPLETE ---")