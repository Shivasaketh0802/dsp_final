from app import db
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from flask_login import UserMixin
from werkzeug.security import check_password_hash
from hashlib import sha256


key = 'MU1dcZuVnAxNaW6E_krdQBtJ8BjkYG4C4EvfRp3BzHQ='
cipher_suite = Fernet(key)


def encrypt_data(data):
    data_str = str(data)
    encrypted_data = cipher_suite.encrypt(data_str.encode())
    return encrypted_data


def decrypt_data(data):
    try:
        decrypted_data = cipher_suite.decrypt(data)
        return decrypted_data.decode('utf-8')  # Assuming your data is stored as utf-8
    except (InvalidToken, UnicodeDecodeError):
        return None


class HealthRecord(db.Model):
    __tablename__ = 'healthrecord'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(20))
    weight = db.Column(db.Float)
    height = db.Column(db.Float)
    health_history = db.Column(db.String(100))
    hash = db.Column(db.String(64))  # Store SHA-256 hash


class User(UserMixin,db.Model):
    __tablename__ = 'users'  # Matches your table name
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # Matches column name
    group = db.Column(db.String(1), nullable=False)


    @property
    def is_active(self):
        # Example: Return True to indicate the user is active
        return True

    def set_password(self, password):
        
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if isinstance(self.password_hash, bytes):
            self.password_hash = self.password_hash.decode('utf-8')  # Decode to string
        return check_password_hash(self.password_hash, password)
        
    def compute_hash(self):
        # Concatenate fields and compute hash
        record_str = f"{self.first_name}{self.last_name}{self.age}{self.gender}{self.weight}{self.height}{self.health_history}"
        return sha256(record_str.encode()).hexdigest()