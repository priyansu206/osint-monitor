from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess
import sys

app = Flask(__name__)

app.secret_key = 'super_secret_dev_key_do_not_share' 

def get_db_connection():
    conn = sqlite3.connect('osint_monitor.db')
    conn.row_factory = sqlite3.Row 
    return conn

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
        # Success! VIP Access Granted!
        session['user_id'] = user['id']
        session['username'] = user['username']
        
    return redirect('/')

@app.route('/logout')
def logout():
    # Rip the session out and flush it down the memory hole.
    session.clear() 
    return redirect('/')

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

@app.route('/delete/<int:target_id>', methods=['POST'])
def delete(target_id):
    if 'user_id' not in session:
        return redirect('/')
        
    conn = get_db_connection()
    conn.execute('DELETE FROM targets WHERE id = ? AND user_id = ?', (target_id, session['user_id']))
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
    app.run(debug=True, port=8080)