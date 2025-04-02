import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

class Config:
    """Base configuration (override with .env)."""
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///../db/database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-fallback-key')  # Change in production!