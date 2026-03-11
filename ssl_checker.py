import ssl
import socket
import datetime

def check_ssl_expiry(domain):
    print(f"[*] Connecting to {domain} to inspect SSL Certificate...")
    
    # 1. Create a secure connection tool (Context)
    context = ssl.create_default_context()
    
    try:
        # 2. Open a network connection (Socket) on Port 443 (HTTPS)
        with socket.create_connection((domain, 443)) as sock:
            # 3. Wrap the connection in our secure context
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                
                # 4. Grab the certificate from the server
                cert = secure_sock.getpeercert()
                
                # 5. Extract the "Expiration Date" string and convert it to a real Date object
                expiry_str = cert['notAfter']
                expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                
                # 6. Calculate how many days are left
                days_remaining = (expiry_date - datetime.datetime.utcnow()).days
                
                return days_remaining

    except Exception as e:
        return f"Error connecting to {domain}: {e}"
# --- BATCH PROCESSING ENGINE ---
if __name__ == "__main__":
    print("=== OSINT DOMAIN MONITOR STARTING ===")
    
    # 1. Open the "database" file
    try:
        with open("targets.txt", "r") as file:
            # Read lines and remove any invisible newline characters
            domains = [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print("[ERROR] targets.txt not found. Please create it.")
        exit()

    print(f"Loaded {len(domains)} targets for scanning...\n")

    # 2. Loop through every domain in the list
    for target in domains:
        days_left = check_ssl_expiry(target)
        
        # 3. Generate the Report Line
        if isinstance(days_left, int):
            if days_left < 30:
                print(f"[URGENT] {target}: Expires in {days_left} days! (Action Required)")
            else:
                print(f"[OK] {target}: Healthy ({days_left} days remaining)")
        else:
            print(f"[ERROR] {target}: {days_left}")
            
    print("\n=== SCAN COMPLETE ===")