from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

# Helper function to connect to the database securely
def get_db_connection():
    conn = sqlite3.connect('osint_monitor.db')
    conn.row_factory = sqlite3.Row 
    return conn

# Route 1: homepage that lists all the domains we're monitoring
@app.route('/')
def index():
    conn = get_db_connection()
    targets = conn.execute('SELECT * FROM targets').fetchall()
    conn.close()

    return render_template('index.html', targets=targets)

# Route 2: Adds a New Domain
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

if __name__ == '__main__':
    
    app.run(debug=True, port=5000)