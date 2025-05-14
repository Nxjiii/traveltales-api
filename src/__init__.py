from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from src.config import Config
from src.models import db
from dotenv import load_dotenv
import os
from apscheduler.schedulers.background import BackgroundScheduler
from .cli import register_cli_commands
from flask_cors import CORS
from flask import Flask, session

load_dotenv()  # Load environment variables

def create_app(config_class=Config):
    """Factory function to create and configure the Flask app."""
    
    # Create the Flask app instance
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    CORS(app,
        supports_credentials=True,
        resources={
            r"/api/*": {
                "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"]
            }
        })
    
    # Configure the database (SQLite for simplicity)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../db/database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Silence deprecation warnings
    
    # Initialize extensions with the app
    db.init_app(app)
    
    # Import and register blueprints
    from src.routes import auth_bp
    app.register_blueprint(auth_bp)
    
    # Ensure app context is available for db operations
    with app.app_context():
        print("Creating tables...")  # Debugging line
        db.create_all()  # Create tables
    
    register_cli_commands(app)
    
    # Import cleanup function here to avoid circular imports
    from src.services.cleanup import cleanup_blacklist
    
    # Create a wrapper function that provides app context
    def scheduled_cleanup():
        with app.app_context():
            cleanup_blacklist()
    
    # Set up the scheduler for token cleanup with the wrapper function
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=scheduled_cleanup, trigger="interval", minutes=10)  # Run every 10 minutes
    scheduler.start()
    
    return app

# Create the app instance
app = create_app()