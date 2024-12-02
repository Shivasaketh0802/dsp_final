from flask import Blueprint, render_template, request, redirect, url_for, session, Flask, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_principal import Principal, Permission
from app.models import db, HealthRecord, encrypt_data
from config import Config
from hashlib import sha256
import pandas as pd
from werkzeug.security import generate_password_hash

bp = Blueprint('main', __name__)
login_manager = LoginManager()
login_manager.login_view = 'main.login'

principal = Principal()

# Define roles
admin_permission = Permission('admin')
readonly_permission = Permission('readonly')

from .models import User


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize the SQLAlchemy instance with the app
    db.init_app(app)

    # Initialize login manager and principal
    login_manager.init_app(app)
    principal.init_app(app)

    # Register blueprints or other configurations
    from .routes import bp as main_bp  # Import route definitions
    app.register_blueprint(main_bp)

    return app


# Utility to compute a hash for record integrity
def compute_hash(record):
    record_str = f"{record.first_name}{record.last_name}{record.age}{record.gender}{record.weight}{record.height}{record.health_history}"
    return sha256(record_str.encode()).hexdigest()


# Helper functions to fetch data based on user group with integrity checks
def get_data_for_group_H():
    # Fetch all health records
    records = HealthRecord.query.all()

    data = []
    for record in records:
        # Validate record integrity
        if record.hash != compute_hash(record):
            continue  # Skip invalid records

        # Include all fields for Group H
        data.append({
            'first_name': record.first_name,
            'last_name': record.last_name,
            'age': record.age,
            'gender': record.gender,
            'weight': record.weight,
            'height': record.height,
            'health_history': record.health_history,
        })

    return data


def get_data_for_group_R():
    # Fetch all health records
    records = HealthRecord.query.all()

    data = []
    for record in records:
        # Validate record integrity
        if record.hash != compute_hash(record):
            continue  # Skip invalid records

        # Exclude first_name and last_name for Group R
        data.append({
            'age': record.age,
            'gender': record.gender,
            'weight': record.weight,
            'height': record.height,
            'health_history': record.health_history,
        })

    return data


@bp.route('/insert_data', methods=['GET'])
def insert_data():
    file_path = r"C:\Users\ashish\Downloads\Group 6\userdetials.xlsx"
    df = pd.read_excel(file_path)

    for index, row in df.iterrows():
        if row['gender'] not in ['Male', 'Female']:
            row['gender'] = 'Male'  # Default to 'Male' for non-standard values

        age_encrypted = encrypt_data(row['age'])
        gender_encrypted = encrypt_data(row['gender'])
        health_history_encrypted = encrypt_data(row['health_history'])

        new_record = HealthRecord(
            first_name=row['first_name'],
            last_name=row['last_name'],
            age=age_encrypted,
            gender=gender_encrypted,
            weight=row['weight'],
            height=row['height'],
            health_history=health_history_encrypted
        )
        # Compute hash for integrity and add to the record
        new_record.hash = compute_hash(new_record)
        db.session.add(new_record)

    db.session.commit()
    return 'Data inserted successfully!'


# Route to validate record integrity
@bp.route('/test_data_integrity', methods=['GET'])
def test_data_integrity():
    records = HealthRecord.query.all()
    issues = []

    for record in records:
        # Compute the hash for the current record
        computed_hash = compute_hash(record)
        if record.hash != computed_hash:
            issues.append(f"Record ID {record.id} has been modified.")

    if issues:
        return {"status": "failure", "issues": issues}, 400
    return {"status": "success", "message": "All records are verified."}, 200

@bp.route('/fix_hashes', methods=['GET'])
def fix_hashes():
    records = HealthRecord.query.all()

    for record in records:
        # Recompute the hash
        correct_hash = compute_hash(record)
        # Update the hash in the database
        record.hash = correct_hash
        db.session.add(record)

    db.session.commit()
    return {"status": "success", "message": "Hashes updated successfully."}, 200


@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form inputs
        username = request.form['username']
        password = request.form['password']
        group = request.form['group']

        # Hash the password securely
        hashed_password = generate_password_hash(password)

        # Create a new user instance with hashed password
        new_user = User(username=username, password_hash=hashed_password, group=group)

        # Save the user to the database
        db.session.add(new_user)
        db.session.commit()

        # Log in the user after signup
        login_user(new_user)

        # Redirect to the dashboard
        return redirect(url_for('main.dashboard'))

    return render_template('signup.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Log the user in after successful login
            login_user(user)

            return redirect(url_for('main.dashboard'))

        else:
            return render_template('login.html', message='Invalid username or password')

    return render_template('login.html')


@bp.route('/home')
def home():
    return render_template('home.html')


@bp.route('/')
def redirect_home():
    return redirect(url_for('main.home'))


@bp.route('/dashboard')
@login_required
def dashboard():
    # Fetch data based on user group
    if current_user.group == 'H':
        health_data = get_data_for_group_H()
    elif current_user.group == 'R':
        health_data = get_data_for_group_R()
    else:
        flash('Invalid user group', 'error')
        return redirect(url_for('main.login'))

    return render_template('dashboard.html', health_data=health_data)


@bp.route('/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    if current_user.group == 'H':
        if request.method == 'POST':
            # Get form data
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            age = request.form['age']
            gender = request.form['gender']
            weight = request.form['weight']
            height = request.form['height']
            health_history = request.form['health_history']

            # Create a new HealthRecord object
            new_record = HealthRecord(
                first_name=first_name,
                last_name=last_name,
                age=age,
                gender=gender,
                weight=weight,
                height=height,
                health_history=health_history
            )
            # Compute hash for integrity
            new_record.hash = compute_hash(new_record)

            # Add the new record to the database
            db.session.add(new_record)
            db.session.commit()

            flash('New patient added successfully!', 'success')

            return redirect(url_for('main.dashboard'))

        return render_template('add_patient.html')

    else:
        flash('Invalid user group.', 'error')
        return redirect(url_for('main.dashboard'))


@bp.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('main.login'))
