import os
import sqlite3
import subprocess
import hashlib
import pickle
import requests
from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials - security issue
DB_USERNAME = "admin"
DB_PASSWORD = "password123"
API_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456"

# SQL Injection vulnerability
@app.route('/users')
def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability - using string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchall()
    return str(result)

# Command injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Command injection vulnerability - unsanitized input
    result = os.system(f"ping -c 1 {host}")
    return str(result)

# Insecure deserialization
@app.route('/load_data')
def load_data():
    file_path = request.args.get('file')
    with open(file_path, 'rb') as f:
        # Insecure deserialization - pickle can execute arbitrary code
        data = pickle.load(f)
    return str(data)

# Weak hashing algorithm
def hash_password(password):
    # Using MD5 - weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()

# Insecure file operations
@app.route('/read_file')
def read_file():
    filename = request.args.get('filename')
    # Path traversal vulnerability
    with open(filename, 'r') as f:
        content = f.read()
    return content

# Use of dangerous subprocess call
def execute_command(cmd):
    # Shell=True is dangerous
    return subprocess.check_output(cmd, shell=True)

# Unverified SSL
def fetch_data(url):
    # Disabled SSL verification
    return requests.get(url, verify=False)

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode should not be enabled in production

