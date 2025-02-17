import os
import random
import string
import psycopg2
import sqlite3
from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask import Flask, g
from authlib.integrations.flask_client import OAuth
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_bcrypt import Bcrypt
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime, timedelta
from config import Config
from time import time


VALID_ROLES = ['Employee', 'Manager']
leave_reasons = {
    'vacation': 3,
    'sick_leave': 2,
    'family_emergency': 2,
    'personal_reason': 1,
    'study_leave': 5
}

class User:
    def __init__(self, id, email, password, name, roles=None, is_admin=False, remaining_vacation_days=None):
        self.id = id
        self.email = email
        self.password = password
        self.name = name
        self.roles = roles or ['Employee']
        self.is_admin = is_admin
        self.remaining_vacation_days = remaining_vacation_days if remaining_vacation_days is not None else 21  # Default to 21

    def __repr__(self):
        return f"<User {self.name} ({self.email})>"

    def has_role(self, role):
        return role in self.roles

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def get_vacation_requests(self):
        # Fetch vacation requests associated with this user
        return get_vacation_requests_by_user_id(self.id)

    def update_vacation_days(self):
        # Get all approved vacation requests
        approved_requests = self.get_vacation_requests()

        total_days_off = 0
        for request in approved_requests:
            if request.status == 'Approved':
                total_days_off += request.calculate_vacation_days()

        # Subtract the vacation days from the remaining days
        self.remaining_vacation_days -= total_days_off
        return self.remaining_vacation_days



class VacationRequest:
    def __init__(self, user_id, start_date, end_date, reason, leave_reason=None, status="Pending"):
        self.user_id = user_id
        self.start_date = start_date
        self.end_date = end_date
        self.reason = reason
        self.leave_reason = leave_reason  # Optional, but you can choose to set it
        self.status = status

    def __repr__(self):
        return f"<VacationRequest {self.user_id} {self.start_date} to {self.end_date}>"

    def calculate_vacation_days(self):
        # If leave_reason is provided, use it to calculate the number of days for that reason.
        leave_days = leave_reasons.get(self.leave_reason, 0)

        # If no leave_reason, calculate the difference between start and end dates
        if not self.leave_reason:
            days_off = (self.end_date - self.start_date).days + 1  # +1 to include the start day
        else:
            # Use the leave reason to get the appropriate day count
            days_off = leave_days
        
        return days_off

# Flask Application Setup
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# Extensions Setup
oauth = OAuth(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# OAuth Configuration
google = oauth.register(
    name='google',
    client_id=app.config['OAUTH2_CLIENT_ID'],
    client_secret=app.config['OAUTH2_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

@login_manager.user_loader
def load_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        print(f"User loaded: {user}, Roles: {user.roles}")
    else:
        print(f"User not found with id: {user_id}")
    return user

app.jinja_env.globals['current_user'] = current_user

google = oauth.register(
    name='google',
    client_id=app.config['OAUTH2_CLIENT_ID'],
    client_secret=app.config['OAUTH2_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

def update_remaining_vacation_days(user_id, new_remaining_days):
    db = get_db()  # Access the database
    cursor = db.cursor()

    try:
        # Ensure the table name is properly quoted to avoid syntax errors
        cursor.execute('UPDATE "user" SET remaining_vacation_days = %s WHERE id = %s', (new_remaining_days, user_id))
        db.commit()
        return True
    except Exception as e:
        print(f"Error updating remaining vacation days for user {user_id}: {e}")
        db.rollback()
        return False
    finally:
        cursor.close()  # Ensure the cursor is always closed



def get_user_remaining_vacation_days(user_id):
    db = get_db()  # Access the database
    cursor = db.cursor()
    
    try:
        # Ensure the table name is properly quoted in case it's a reserved word (like "user")
        cursor.execute('SELECT remaining_vacation_days FROM "user" WHERE id = %s', (user_id,))
        result = cursor.fetchone()
        
        if result:
            return result[0]  # Return the remaining vacation days
        else:
            return 0  # Return 0 if the result is not found (in case the user doesn't exist)
    
    except Exception as e:
        # Log the error and return 0 in case of failure
        print(f"Error fetching remaining vacation days for user {user_id}: {e}")
        return 0
    finally:
        cursor.close()  # Make sure the cursor is always closed

def calculate_remaining_vacation_days(user_id):
    total_vacation_days = 21  # İllik maksimum icazə günləri
    
    # Get the database connection
    db = get_db()  # or get_db_connection() if you're using that
    cursor = db.cursor()

    # Query to get approved vacation requests for the given user_id
    cursor.execute(
        "SELECT start_date, end_date FROM vacation_requests WHERE user_id = %s AND status = %s",
        (user_id, "Approved")
    )
    
    approved_requests = cursor.fetchall()
    
    # Calculate the total used vacation days
    used_vacation_days = sum(
        (datetime.strptime(req[1], '%Y-%m-%d') - datetime.strptime(req[0], '%Y-%m-%d')).days 
        for req in approved_requests
    )
    
    cursor.close()

    # Return the remaining vacation days (not going below 0)
    return max(total_vacation_days - used_vacation_days, 0)


def save_vacation_request(user_id, start_date, end_date, leave_reason):
    # Get the database connection
    db = get_db()
    cursor = db.cursor()

    # Insert the vacation request into the database
    try:
        cursor.execute(
    "INSERT INTO vacation_requests (user_id, start_date, end_date, leave_reason, status) VALUES (%s, %s, %s, %s, %s)",
    (user_id, start_date, end_date, leave_reason, "Pending")
)

        db.commit()  # Commit the transaction
        return True
    except Exception as e:
        print(f"Error: {str(e)}")
        db.rollback()  # Rollback the transaction in case of error
        return False
    finally:
        cursor.close()


def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(
            dbname='smart_water_manage',
            user='superuser',
            password='Qwerty@34',
            host='localhost',
            port='5432'
        )
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.template_filter('format_date')
def format_date_filter(date):
    return date.strftime('%Y-%m-%d')

def get_db_connection():
    try:
        return psycopg2.connect(
            dbname=app.config['DATABASE_NAME'],
            user=app.config['DATABASE_USER'],
            password=app.config['DATABASE_PASSWORD'],
            host=app.config['DATABASE_HOST'],
            port=app.config['DATABASE_PORT']
        )
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        return None

def execute_query(query, params=(), fetchall=False, commit=False):
    conn = get_db_connection()
    if not conn:
        return None

    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            
            if commit:
                conn.commit()
                if 'RETURNING' in query:
                    result = cursor.fetchone()
                    return result[0] if result else None
                return True

            # For SELECT queries, fetch results based on the flag
            result = cursor.fetchall() if fetchall else cursor.fetchone()
            return result if result else None
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()
            

def get_user_by_email(email):
    query = """SELECT id, email, password, name, roles, is_admin, remaining_vacation_days 
               FROM "user" WHERE email = %s"""
    result = execute_query(query, (email,))
    if result:
        user_id, email, password, name, roles, is_admin, remaining_days = result
        return User(
            user_id, email, password, name,
            roles=parse_db_array(roles),
            is_admin=is_admin,
            remaining_vacation_days=remaining_days
        )
    return None

def get_user_by_id(user_id):
    query = """SELECT id, email, password, name, roles, is_admin, remaining_vacation_days 
               FROM "user" WHERE id = %s"""
    result = execute_query(query, (user_id,))
    if result:
        user_id, email, password, name, roles, is_admin, remaining_days = result
        return User(
            user_id, email, password, name,
            roles=parse_db_array(roles),
            is_admin=is_admin,
            remaining_vacation_days=remaining_days
        )
    return None


def create_user(email, name, password, roles=['Operator'], is_admin=False):
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    query = """INSERT INTO "user" (email, name, password, roles, is_admin)
               VALUES (%s, %s, %s, %s, %s) RETURNING id"""
    user_id = execute_query(
        query,
        (email, name, hashed_pw, roles, is_admin),
        commit=True
    )
    return get_user_by_id(user_id) if user_id else None

def parse_db_array(value):
    if isinstance(value, str):
        return value.strip('{}').split(',')
    return value or []

def create_jwt_token(user):
    return jwt.encode({
        'email': user.email,
        'roles': user.roles,
        'sub': str(user.id),
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')


def get_all_vacation_requests():
    query = """SELECT id, user_id, start_date, end_date, leave_reason, status 
               FROM vacation_requests"""
    results = execute_query(query, fetchall=True)
    return [dict(zip(['id', 'user_id', 'start_date', 'end_date', 'leave_reason', 'status'], row)) for row in results]

def get_remaining_vacation_days(user_id):
    query = """SELECT remaining_vacation_days FROM "user" WHERE id = %s"""
    result = execute_query(query, (user_id,))
    
    # If the result is a single value (int), return it directly
    if result:
        return result[0]  # Directly return the int value
    return None  # If no result, return None


def get_taken_vacation_days(user_id):
    # Fetch the taken vacation days from the database (approved requests)
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT SUM(end_date::DATE - start_date::DATE)
        FROM vacation_requests
        WHERE user_id = %s AND status = 'Approved'
    """, (user_id,))
    result = cursor.fetchone()
    connection.close()
    
    return result[0] if result[0] else 0




def create_vacation_request(user_id, start_date, end_date, reason):
    try:
        db = get_db()  # Or get_db_connection() if you're using that
        cursor = db.cursor()

        # Insert the vacation request into the database
        cursor.execute("""
            INSERT INTO vacation_requests (user_id, start_date, end_date, reason, status)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, start_date, end_date, reason, 'Pending'))

        db.commit()
        cursor.close()
    except Exception as e:
        print(f"Error creating vacation request: {e}")
        raise

def create_vacation_request_in_db(user_id, start_date, end_date, reason):
    try:
        db = get_db()  # Or get_db_connection() if you're using that
        cursor = db.cursor()

        # Insert the vacation request into the database
        cursor.execute("""
            INSERT INTO vacation_requests (user_id, start_date, end_date, reason, status)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, start_date, end_date, reason, 'Pending'))

        db.commit()
        cursor.close()
    except Exception as e:
        print(f"Error creating vacation request: {e}")
        raise




def update_vacation_days(user_id, days):
    query = """UPDATE user SET remaining_vacation_days = %s WHERE id = %s"""
    return execute_query(query, (days, user_id), commit=True)

def get_vacation_requests_by_user_id(user_id):
    query = """SELECT id, user_id, start_date, end_date, leave_reason, status 
               FROM vacation_requests WHERE user_id = %s"""
    results = execute_query(query, (user_id,), fetchall=True)
    return [dict(zip(['id', 'user_id', 'start_date', 'end_date', 'leave_reason', 'status'], row)) for row in results]



def get_vacation_request_by_id(request_id):
    query = """SELECT id, user_id, start_date, end_date, leave_reason, status 
               FROM vacation_requests WHERE id = %s"""
    result = execute_query(query, (request_id,))
    if result:
        return dict(zip(['id', 'user_id', 'start_date', 'end_date', 'leave_reason', 'status'], result))
    return None


def delete_vacation_request(request_id):
    query = """DELETE FROM vacation_requests WHERE id = %s"""
    return execute_query(query, (request_id,), commit=True)

def update_user_vacation_days(user_id, delta):
    db = get_db()
    cursor = db.cursor()
    try:
        # Fetch current remaining vacation days for the user
        cursor.execute('SELECT remaining_vacation_days FROM "user" WHERE id = %s', (user_id,))
        current_vacation_days = cursor.fetchone()[0]
        print(f"Current remaining vacation days: {current_vacation_days}")
        
        # Calculate new remaining vacation days
        new_vacation_days = current_vacation_days - delta
        print(f"New remaining vacation days after subtracting delta: {new_vacation_days}")
        
        # Update the user's remaining vacation days in the database
        cursor.execute(
            'UPDATE "user" SET remaining_vacation_days = %s WHERE id = %s', 
            (new_vacation_days, user_id)
        )
        db.commit()
        cursor.close()
        return True
    except Exception as e:
        print(f"Database error: {e}")
        db.rollback()
        cursor.close()
        return False



def get_all_users():
    query = """SELECT id, email, name, roles, is_admin FROM "user" """
    results = execute_query(query, fetchall=True)
    if results:
        return [User(row[0], row[1], None, row[2], row[3], row[4]) for row in results]
    return []


def get_dashboard_route(user):
    if 'Manager' in user.roles:
        return 'admin_dashboard'
    elif 'Employee' in user.roles:
        return 'operator_dashboard'
    else:
        flash("Your role is not recognized. Please contact an administrator.", 'warning')
        return 'home'



@app.before_request
def check_user_roles():
    if current_user.is_authenticated:
        print(f"User roles: {current_user.roles}")
        if request.endpoint == 'admin_dashboard' and 'Manager' not in current_user.roles:
            print("Access denied. Redirecting to login.")
            flash("Access denied.", 'danger')
            return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user_by_email(email)
        if user:
            new_password = request.form['new_password']
            if not new_password:
                flash("Password cannot be empty.", 'danger')
                return render_template('forgot_password.html')
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            query = """UPDATE "user" SET password = %s WHERE email = %s"""
            execute_query(query, (hashed_password, email), commit=True)
            flash("Password updated successfully.", 'success')
            return redirect(url_for('login'))
        else:
            flash("No user found with that email address.", 'danger')
            return render_template('forgot_password.html')
    return render_template('forgot_password.html')

@app.route('/update_user_role', methods=['POST'])
@login_required
def update_user_role():
    if 'Admin' not in current_user.roles:
        flash("Access denied.", 'danger')
        return redirect(url_for('login'))
    
    user_id = request.form.get('user_id')
    new_role = request.form.get('new_role')
    
    # Update roles in database
    query = """UPDATE "user" SET roles = ARRAY[%s]::VARCHAR[] WHERE id = %s"""
    execute_query(query, (new_role, user_id), commit=True)
    
    flash("User role updated successfully", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if 'Admin' not in current_user.roles:
        flash("Access denied.", 'danger')
        return redirect(url_for('login'))
    
    user_id = request.form.get('user_id')
    
    # Delete user from database
    execute_query("""DELETE FROM "user" WHERE id = %s""", (user_id,), commit=True)
    
    flash("User deleted successfully", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form['password']
        user = get_user_by_email(token)  # Simplified token handling
        if user:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            execute_query("""UPDATE "user" SET password = %s WHERE email = %s""", (hashed_password, user.email), commit=True)
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/auth/google')
def google_auth():
    nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    session['oauth_nonce'] = nonce
    return google.authorize_redirect(redirect_uri=url_for('google_callback', _external=True), nonce=nonce)

@app.route('/create_vacation_request', methods=['POST'])
@login_required
def create_vacation_request():
    # Cooldown protection (120 seconds wait time)
    COOLDOWN = 120  # seconds (2 minutes)
    last_action = session.get('last_action_time')
    current_time = time()  # Get current time in seconds

    if last_action and (current_time - last_action) < COOLDOWN:
        flash("Lütfen ard arda işlem yapmadan önce biraz bekleyin.", 'error')
        return redirect(url_for('operator_dashboard'))  # Kullanıcıyı operator_dashboard'a yönlendiriyoruz

    if request.method == 'POST':
        try:
            # Get user details
            user = get_user_by_id(current_user.id)
            leave_reason = request.form.get('reason')
            start_date_str = request.form.get('start_date')
            end_date_str = request.form.get('end_date')

            # Check if all fields are filled
            if not all([leave_reason, start_date_str, end_date_str]):
                flash("All fields are required.", 'danger')
                return redirect(url_for('operator_dashboard'))

            # Check for pending vacation request
            if has_pending_request(user.id):
                flash("You already have a pending vacation request. Please wait until it is processed.", 'danger')
                return redirect(url_for('operator_dashboard'))

            # Convert date strings to datetime objects
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d")
            delta = (end_date - start_date).days

            # Check if the end date is after the start date
            if delta < 0:
                flash("End date must be after the start date.", 'danger')
                return redirect(url_for('operator_dashboard'))

            # Check the maximum allowed vacation days for the leave reason
            max_allowed_days = leave_reasons.get(leave_reason, 0)
            if max_allowed_days == 0:
                flash("Invalid leave reason selected.", 'danger')
                return redirect(url_for('operator_dashboard'))

            # Validate the requested days against the allowed days
            if delta > max_allowed_days:
                flash(f"This leave type allows a maximum of {max_allowed_days} days.", 'danger')
                return redirect(url_for('operator_dashboard'))

            # Check if the user has enough remaining vacation days
            remaining_vacation_days = get_user_remaining_vacation_days(user.id)
            if remaining_vacation_days < delta:
                flash("Not enough vacation days left.", 'danger')
                return redirect(url_for('operator_dashboard'))

            # Save the vacation request to the database (pending status initially)
            if save_vacation_request(user.id, start_date, end_date, leave_reason):
                flash("Request submitted successfully! Waiting for approval.", 'success')
            else:
                flash("Failed to create vacation request.", 'danger')

        except ValueError:
            flash("Invalid date format.", 'danger')
        except Exception as e:
            flash("An error occurred while processing your request.", 'danger')

        # Update the last action time in session to prevent spamming
        session['last_action_time'] = current_time
        
        return redirect(url_for('operator_dashboard'))


@app.route('/cancel_request/<int:request_id>', methods=['POST'])
@login_required
def cancel_request(request_id):
    # Cooldown protection (120 seconds wait time)
    COOLDOWN = 120  # seconds (2 minutes)
    last_action = session.get('last_action_time')
    current_time = time()  # Get current time in seconds

    if last_action and (current_time - last_action) < COOLDOWN:
        flash("Please wait a moment before making another request.", 'error')
        return redirect(url_for('operator_dashboard'))  # Redirect user to the operator dashboard
    
    # Fetch vacation request from the database using raw SQL
    query = """SELECT id, user_id, start_date, end_date, leave_reason, status 
               FROM vacation_requests WHERE id = %s"""
    result = execute_query(query, (request_id,))

    if not result:
        flash("Request not found.", 'error')
        return redirect(url_for('operator_dashboard'))  # Redirect to the operator dashboard

    # Mapping the result to a dictionary for easier access
    vacation_request = dict(zip(['id', 'user_id', 'start_date', 'end_date', 'leave_reason', 'status'], result))

    # Authorization check (ensure the current user owns the vacation request)
    if vacation_request['user_id'] != current_user.id:
        abort(403)  # Forbidden error if not authorized
    
    # Only allow canceling pending requests
    if vacation_request['status'].lower() != 'pending':  # Compare the status in lowercase
        flash("You can only cancel pending requests.", 'error')
        return redirect(url_for('operator_dashboard'))  # Redirect to the operator dashboard
    
    # Check if the request has already been canceled and ensure cooldown
    if vacation_request['status'].lower() == 'cancelled':
        flash("This request has already been canceled.", 'error')
        return redirect(url_for('operator_dashboard'))  # Redirect to the operator dashboard

    # Update the status to 'Cancelled' in the database
    update_query = """UPDATE vacation_requests SET status = 'Cancelled' WHERE id = %s"""
    execute_query(update_query, (request_id,), commit=True)

    # Update the last action time in the session to prevent spamming
    session['last_action_time'] = current_time
    
    flash("Request successfully canceled.", 'success')
    return redirect(url_for('operator_dashboard'))  # Redirect to the operator dashboard







# Helper function to check if the user has a pending vacation request
def has_pending_request(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT * FROM vacation_requests WHERE user_id = %s AND status = %s",
        (user_id, 'Pending')
    )
    pending_request = cursor.fetchone()
    cursor.close()
    return pending_request is not None



# Renaming the helper function to avoid conflict


@app.route('/auth/google/callback')
def google_callback():
    try:
        nonce = session.pop('oauth_nonce', None)
        if not nonce:
            flash('Invalid authentication request', 'danger')
            return redirect(url_for('login'))

        token = google.authorize_access_token()
        id_token = google.parse_id_token(token, nonce=nonce)

        email = id_token.get('email')
        if not email:
            flash('Could not get email from Google.', 'danger')
            return redirect(url_for('login'))

        user = get_user_by_email(email)
        
        if not user:
            name = id_token.get('name', email.split('@')[0])
            random_password = os.urandom(24).hex()
            hashed_password = bcrypt.generate_password_hash(random_password).decode('utf-8')
            user = create_user(email, name, hashed_password)
            
            if not user:
                flash('Account creation failed. Please try again.', 'danger')
                return redirect(url_for('login'))

        login_user(user)
        session['user_token'] = jwt.encode({
                'email': user.email,
                'roles': user.roles,
                'sub': str(user.id),
                'iat': datetime.utcnow(),  # Corrected here
                'exp': datetime.utcnow() + datetime.timedelta(hours=1)
}, app.config['SECRET_KEY'], algorithm='HS256')


        return redirect(url_for(get_dashboard_route(user)))

    except Exception as e:
        flash(f'Login failed: {str(e)}', 'danger')
        return redirect(url_for('login'))
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_token', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        if not email or not password or not name:
            flash('All fields are required.', 'danger')
            return render_template('signup.html')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = create_user(email, name, hashed_password)
        if user:
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        flash('Signup failed. Please try again.', 'danger')
    return render_template('signup.html')
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for(get_dashboard_route(current_user)))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user_by_email(email)

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session['user_token'] = create_jwt_token(user)
            return redirect(url_for(get_dashboard_route(user)))
        
        flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

# Admin Dashboard Route
@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if 'Manager' not in current_user.roles:
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    try:
        # Get all vacation requests with user information
        query = """
        SELECT 
            vr.id AS request_id,
            u.email AS user_email,
            u.name AS user_name,
            vr.start_date,
            vr.end_date,
            vr.leave_reason,
            vr.status,
            (vr.end_date - vr.start_date) + 1 AS total_days
        FROM vacation_requests vr
        INNER JOIN "user" u ON vr.user_id = u.id  -- Use quotes for reserved keywords
        ORDER BY vr.start_date DESC;
        """
        results = execute_query(query, fetchall=True)
        
        vacation_requests = []
        if results:
            columns = ['id', 'email', 'name', 'start_date', 'end_date', 
                      'leave_reason', 'status', 'total_days']
            vacation_requests = [dict(zip(columns, row)) for row in results]

        return render_template(
            'admin_dashboard.html',
            vacation_requests=vacation_requests
        )

    except Exception as e:
        print(f"Database error: {str(e)}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('logout'))  # Redirect to logout to break the loop

# Approval/Rejection Routes
@app.route('/approve_vacation', methods=['POST'])
@login_required
def approve_vacation():
    if 'Manager' not in current_user.roles:
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    
    request_id = request.form.get('request_id')
    execute_query(
        "UPDATE vacation_requests SET status = 'Approved' WHERE id = %s",
        (request_id,),
        commit=True
    )
    flash('Request approved', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_vacation', methods=['POST'])
@login_required
def reject_vacation():
    if 'Manager' not in current_user.roles:
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    
    request_id = request.form.get('request_id')
    execute_query(
        "UPDATE vacation_requests SET status = 'Rejected' WHERE id = %s",
        (request_id,),
        commit=True
    )
    flash('Request rejected', 'success')
    return redirect(url_for('admin_dashboard'))



    
@app.route('/operator-dashboard', methods=['GET', 'POST'])
@login_required
def operator_dashboard():
    if 'Employee' not in current_user.roles:
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    user = current_user

    # Get remaining vacation days from the database, defaulting to 21 if not found
    remaining_vacation_days = get_remaining_vacation_days(user.id)

    # If remaining_vacation_days is None, set it to 21 by default
    if remaining_vacation_days is None:
        remaining_vacation_days = 21

    print(f"Initial Remaining Vacation Days: {remaining_vacation_days}")

    # Get all vacation requests for the current user
    try:
        db = get_db()
        cursor = db.cursor()

        query = """
        SELECT start_date, end_date, leave_reason, status, id 
        FROM vacation_requests 
        WHERE user_id = %s
        ORDER BY start_date DESC
        """
        rows = execute_query(query, (user.id,), fetchall=True) or []

        # Convert tuples to dictionaries
        all_requests = [
            {
                "start_date": row[0],
                "end_date": row[1],
                "leave_reason": row[2],
                "status": row[3],
                "id": row[4],
            }
            for row in rows
        ]

        cursor.close()

    except Exception as e:
        print(f"Error fetching vacation requests: {e}")
        flash('Error fetching vacation requests.', 'danger')
        return redirect(url_for('operator_dashboard'))

    # Calculate total days taken for vacation requests
    total_days_taken = 0
    for request in all_requests:
        start_date = request["start_date"]
        end_date = request["end_date"]

        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, "%Y-%m-%d").date()

        delta_days = (end_date - start_date).days

        if request["status"] == 'Approved':
            total_days_taken += delta_days

    print(f"Remaining Vacation Days before subtraction: {remaining_vacation_days}")

    # Subtract total days taken from remaining vacation days
    remaining_vacation_days -= total_days_taken

    print(f"Remaining Vacation Days after subtraction: {remaining_vacation_days}")

    if remaining_vacation_days < 0:
        remaining_vacation_days = 0

    print(f"Final Remaining Vacation Days: {remaining_vacation_days}")

    return render_template(
        "operator_dashboard.html",
        user=user,
        remaining_vacation_days=remaining_vacation_days,
        requests=all_requests
    )




@app.route('/manage-systems')
def manage_systems():
    # Example data
    systems = [
        {"id": 1, "name": "Water System A", "status": "Active"},
        {"id": 2, "name": "Water System B", "status": "Inactive"}
    ]
    return render_template('manage_systems.html', systems=systems)

@app.route('/generate-reports')
def generate_reports():
    return render_template('generate_reports.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required  # Ensures the user is logged in before accessing this page
def settings():
    if current_user.is_authenticated:
        user = current_user  # Access the current logged-in user

        if request.method == 'POST':
            # Handle form submission and update user settings
            name = request.form['name']
            password = request.form['password']
            
            # Update user information in the database (you should have logic for this)
            update_user_info(user.id, name, password)
            flash("Settings updated successfully!", "success")

        return render_template('settings.html', user=user)
    else:
        flash("You need to be logged in to access the settings.", "danger")
        return redirect(url_for('login'))  # Redirect to login if the user is not authenticated

@app.route('/add-system')
def add_system():
    return render_template('add_system.html')

@app.route('/view-systems')
def view_systems():
    systems = [
        {"id": 1, "name": "Water System A", "status": "Active"},
        {"id": 2, "name": "Water System B", "status": "Faulty"}
    ]
    return render_template('view_systems.html', systems=systems)

@app.route('/resolve-faults')
def resolve_faults():
    return render_template('resolve_faults.html')

@app.route('/planner_dashboard')
@login_required
def planner_dashboard():
    return render_template('planner_dashboard.html')

if __name__ == "__main__":
    app.run(debug=True)