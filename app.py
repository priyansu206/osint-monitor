from flask import Flask, render_template, request, redirect
import sqlite3
import subprocess # <-- NEW: Allows Flask to run terminal commands
import sys        # <-- NEW: Helps Flask find your virtual environment

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('osint_monitor.db')
    conn.row_factory = sqlite3.Row 
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    targets = conn.execute('SELECT * FROM targets').fetchall()
    conn.close()
    return render_template('index.html', targets=targets)

@app.route('/add', methods=['POST'])
def add():
    new_domain = request.form.get('domain')
    if new_domain:
        clean_domain = new_domain.replace("https://", "").replace("http://", "").strip().strip('/')
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO targets (domain_name) VALUES (?)', (clean_domain,))
            conn.commit()
        except sqlite3.IntegrityError:
            pass 
        conn.close()
    return redirect('/')

@app.route('/scan', methods=['POST'])
def run_scan():
    print("[FLASK] Triggering background scanner...")
    try:
        subprocess.run([sys.executable, 'ssl_checker.py'], check=True)
        print("[FLASK] Scan complete!")
    except Exception as e:
        print(f"[FLASK] Error running scanner: {e}")
        
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=5000)