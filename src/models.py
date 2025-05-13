# src/models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

# db instance to be imported
db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and API key management."""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    api_keys = db.relationship('APIKey', backref='user', lazy=True)
    posts = db.relationship('BlogPost', back_populates='user', cascade='all, delete-orphan')
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade='all, delete-orphan')


class APIKey(db.Model):
    """API keys for authenticated requests."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)


class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String, unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    profile_picture = db.Column(db.String(200))

    user = db.relationship('User', back_populates='profile')


class BlogPost(db.Model):
    """Blog post model for storing user-generated posts."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    country = db.Column(db.String(80), nullable=False)
    date_of_visit = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=datetime.now)

    user = db.relationship('User', back_populates='posts')

    #commands to confirm db entries sqlite3 db/database.db --> .tables --> SELECT id, email, passowrd_hash FROM user;
