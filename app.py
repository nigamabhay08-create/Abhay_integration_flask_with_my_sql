from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
import os
from functools import wraps

# Optional: load .env if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Database configuration from environment variables or defaults
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'database': os.getenv('DB_NAME', 'login_db'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASS', 'India@12345')
}

# ✅ Changed app name from __name__ to "srdt"
app = Flask("SRDT")
app.secret_key = os.getenv('SECRET_KEY', 'dev_secret_change_me')


def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print("DB connection error:", e)
        return None


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please login to access that page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not username or not email or not password:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('signup'))

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        hashed = generate_password_hash(password)
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed.', 'danger')
            return redirect(url_for('signup'))

        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE email=%s OR username=%s", (email, username))
            if cursor.fetchone():
                flash('A user with that email or username already exists.', 'warning')
                return redirect(url_for('signup'))

            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed)
            )
            conn.commit()
            flash('Account created. Please login.', 'success')
            return redirect(url_for('login'))
        except Error as e:
            conn.rollback()
            flash('Database error: ' + str(e), 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        conn = get_db_connection()
        if not conn:
            flash('Database connection failed.', 'danger')
            return redirect(url_for('login'))

        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id, username, email, password FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Logged in successfully.', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
        except Error as e:
            flash('Database error: ' + str(e), 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# ✅ Corrected main check
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
