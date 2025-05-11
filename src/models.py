# src/models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

# db instance to be imported
db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and API key management."""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # Hashed password
    api_keys = db.relationship('APIKey', backref='user', lazy=True)  # One-to-many

class APIKey(db.Model):
    """API keys for authenticated requests."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)  # Randomly generated key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Links to User
    is_active = db.Column(db.Boolean, default=True)  # Can revoke keys


class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String, unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    #commands to confirm db entries sqlite3 db/database.db --> .tables --> SELECT id, email, passowrd_hash FROM user;
