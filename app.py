from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras # <-- ADDED: Allows Flask to read Postgres rows like dictionaries
import subprocess
import sys
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

app = Flask(__name__)

#pulls the secret key from env files
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secret_dev_key_do_not_share")

# DATABASE CONNECTION FUNCTION - This is a helper function to create a new database connection whenever we need to interact with the database. It uses the DATABASE_URL from the environment variables to connect to the PostgreSQL database. This way, we can easily manage our database connections and ensure that we're connecting to the correct database in different environments (development, staging, production).
def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    hashed_pw = generate_password_hash(password)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username, hashed_pw))
        conn.commit()
    except psycopg2.IntegrityError: # <-- CHANGED: Catching Postgres specific error
        conn.rollback() 
    
    cursor.close()
    conn.close()
    
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    
    cursor.close()
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
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM targets WHERE user_id = %s', (session['user_id'],))
    targets = cursor.fetchall()
    
    cursor.close()
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
        cursor = conn.cursor()

        cursor.execute('INSERT INTO targets (domain_name, user_id) VALUES (%s, %s)', (clean_domain, session['user_id']))
        conn.commit()
        
        cursor.close()
        conn.close()
    return redirect('/')

@app.route('/delete/<int:target_id>', methods=['POST'])
def delete(target_id):
    if 'user_id' not in session:
        return redirect('/')
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM targets WHERE id = %s AND user_id = %s', (target_id, session['user_id']))
    conn.commit()
    
    cursor.close()
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