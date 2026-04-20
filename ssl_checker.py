import ssl
import socket
import datetime
import requests
import os
from dotenv import load_dotenv
import psycopg2 
import shodan

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
DATABASE_URL = os.getenv("DATABASE_URL")
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
shodan_api = shodan.Shodan(SHODAN_API_KEY)

def check_uptime(domain):
    if domain == "evil-test.com":
        return "MALWARE FLAGGED"
    print(f"[*] Pinging {domain} for uptime...")
    url = f"https://{domain}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True
        else:
            return f"HTTP {response.status_code}" 
    except requests.exceptions.RequestException:
        return "Connection Failed"

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Unknown IP"

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
            return "SAFE"
        return "API Error"
    except Exception:
        return "API Timeout"

def check_shodan_vulnerabilities(ip_address):
    if not SHODAN_API_KEY:
        return "Warning: No Shodan API key found."
    dangerous_ports = [21, 22, 23, 445, 3389] 
    try:
        host = shodan_api.host(ip_address)
        open_ports = host.get('ports', [])
        exposed_critical_ports = [port for port in open_ports if port in dangerous_ports]
        if exposed_critical_ports:
            return f" CRITICAL: Dangerous ports exposed: {exposed_critical_ports}"
        return f"Clean (Open ports: {open_ports})"
    except shodan.APIError as e:
        if 'No information available' in str(e):
            return " Safe (Not indexed by Shodan)"
        return f"Shodan Error: {e}"
    
def check_ssl_expiry(domain):
    print(f"[*] Checking SSL for {domain}...")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                timestamp = ssl.cert_time_to_seconds(cert['notAfter'])
                expiry_date = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                return (expiry_date - now_utc).days
    except Exception as e:
        return f"SSL Verification Failed: {e}"

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
        target_id, target_domain = row[0], row[1]  
        uptime_result = check_uptime(target_domain)

        if uptime_result is True:
            ip_addr = get_ip(target_domain) 
            
            shodan_flag = ""
            if ip_addr != "Unknown IP":
                shodan_status = check_shodan_vulnerabilities(ip_addr)
                print(f"[{target_domain}] Shodan: {shodan_status}")
                if "CRITICAL" in shodan_status:
                    shodan_flag = " | 🔓 PORTS OPEN"
                    send_discord_alert(target_domain, f"INFRASTRUCTURE VULNERABILITY: {shodan_status}")
            
            threat_status = check_threat_intel(target_domain)
            if threat_status == "MALWARE FLAGGED":
                status_text = f" UP ({ip_addr}) | MALWARE DETECTED!"
                print(f"[URGENT] {target_domain} IS SERVING MALWARE!")
                send_discord_alert(target_domain, "CRITICAL: Domain flagged for Malware by URLhaus Threat Intel!") 
            else:
                ssl_result = check_ssl_expiry(target_domain)
                if isinstance(ssl_result, int):
                    if ssl_result < 30: 
                        status_text = f" UP ({ip_addr}) |  SAFE |  SSL Expiring ({ssl_result} days){shodan_flag}"
                        send_discord_alert(target_domain, ssl_result)
                    else:
                        status_text = f" UP ({ip_addr}) |  SAFE |  SSL ({ssl_result} days){shodan_flag}"
                else:   
                    status_text = f" UP ({ip_addr}) |  SAFE |  SSL Error{shodan_flag}"
                    send_discord_alert(target_domain, ssl_result)
        else:
            status_text = f" DOWN ({uptime_result})"
            print(f"[URGENT] {target_domain} IS OFFLINE! ({uptime_result})")
            send_discord_alert(target_domain, f"SERVER OFFLINE: {uptime_result}")     
        
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE targets SET last_checked = %s, status = %s WHERE id = %s", (now_utc, status_text, target_id))

    conn.commit()
    conn.close()
    print("\n--- SCAN COMPLETE ---")