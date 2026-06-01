import requests
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

def hunt_and_inject(domain):
    print(f"[*] Starting OSINT Reconnaissance for: {domain}")
    found_subdomains = set()
    print("[*] Attempting Source 1: crt.sh...")
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        # Shorter 10-second timeout so we don't waste time if they are down
        response = requests.get(url, timeout=10) 
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    if name and not name.startswith('*') and name != domain.lower():
                        found_subdomains.add(name)
            print(f"  + Success: crt.sh found {len(found_subdomains)} records.")
        else:
            print(f"  - crt.sh failed (Status {response.status_code}).")
    except requests.exceptions.RequestException:
        print("  - crt.sh server is unresponsive.")
    print("[*] Attempting Source 2: HackerTarget API...")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            lines = response.text.split('\n')
            ht_count = 0
            for line in lines:
                if ',' in line:
                    sub = line.split(',')[0].strip().lower()
                    if sub and sub != domain.lower():
                        found_subdomains.add(sub)
                        ht_count += 1
            print(f"  + Success: HackerTarget found {ht_count} records.")
        else:
            print(f"  - HackerTarget failed (Status {response.status_code}).")
    except requests.exceptions.RequestException:
        print("  - HackerTarget server is unresponsive.")
    print(f"\n--- 🎯 TOTAL UNIQUE FOUND: {len(found_subdomains)} SUBDOMAINS ---")
    if not found_subdomains:
        print("[!] Recon failed on all sources or no subdomains exist. Try again later.")
        return
    if not DATABASE_URL:
        print("[!] Error: No DATABASE_URL found in .env. Cannot inject targets.")
        return
    print("[*] Connecting to Supabase...")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        cursor.execute("SELECT domain_name FROM targets")
        existing_domains = {row[0] for row in cursor.fetchall()}
        new_targets = found_subdomains - existing_domains        
        if not new_targets:
            print("✅ Database is up to date. All found subdomains are already being monitored.")
        else:
            print(f"[*] Injecting {len(new_targets)} NEW targets into the database...")
            for sub in new_targets:
                cursor.execute(
                    "INSERT INTO targets (domain_name, status) VALUES (%s, %s)", 
                    (sub, "Pending Initial Scan")
                )
                print(f"  + Added: {sub}")
            conn.commit()
            print(f"\n✅ Successfully injected {len(new_targets)} new targets!")            
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[!] Database Error: {e}")
if __name__ == "__main__":
    target = input("Enter a master domain to hunt (e.g., netflix.com): ").strip()
    if target:
        hunt_and_inject(target)