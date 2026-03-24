from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess
import sys

app = Flask(__name__)

# In a production environment, you would want to load this from an environment variable or config file, and it should be a long random string. For development purposes, this is fine.
app.secret_key = 'super_secret_dev_key_do_not_share' 

def get_db_connection():
    conn = sqlite3.connect('osint_monitor.db')
    conn.row_factory = sqlite3.Row 
    return conn

# 1. NEW: THE LOGIN & REGISTER ROUTES

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    hashed_pw = generate_password_hash(password)
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed_pw))
        conn.commit()
    except sqlite3.IntegrityError:
        pass 
    conn.close()
    
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        # Success! Hand them the VIP Wristband
        session['user_id'] = user['id']
        session['username'] = user['username']
        
    return redirect('/')

@app.route('/logout')
def logout():
    # Rip up the VIP Wristband
    session.clear() 
    return redirect('/')

# ==========================================
# 2. UPDATED: PROTECTED DASHBOARD ROUTES
# ==========================================

@app.route('/')
def index():
    if 'user_id' not in session:
        return render_template('index.html', targets=None)
    
    conn = get_db_connection()
    targets = conn.execute('SELECT * FROM targets WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('index.html', targets=targets)

@app.route('/add', methods=['POST'])
def add():

    if 'user_id' not in session:
        return redirect('/')
        
    new_domain = request.form.get('domain')
    if new_domain:
        clean_domain = new_domain.replace("https://", "").replace("http://", "").strip().strip('/')
        conn = get_db_connection()

        conn.execute('INSERT INTO targets (domain_name, user_id) VALUES (?, ?)', (clean_domain, session['user_id']))
        conn.commit()
        conn.close()
    return redirect('/')

@app.route('/scan', methods=['POST'])
def run_scan():
    if 'user_id' not in session:
        return redirect('/')
        
    print(f"[FLASK] Triggering background scanner for User ID {session['user_id']}...")
    try:
        subprocess.run([sys.executable, 'ssl_checker.py'], check=True)
    except Exception as e:
        print(f"[FLASK] Error: {e}")
        
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=8000)