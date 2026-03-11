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

# --- TEST THE ENGINE ---
if __name__ == "__main__":
    # Let's test it on a real company
    target_company = "google.com" 
    
    days_left = check_ssl_expiry(target_company)
    
    print("-" * 40)
    print(f"Target: {target_company}")
    print(f"SSL Certificate expires in: {days_left} days")
    print("-" * 40)
    
    # Simple Alert Logic
    if type(days_left) == int and days_left < 30:
        print("[CRITICAL ALERT] Certificate expiring soon! Client must be notified.")
    else:
        print("[OK] Certificate is healthy.")