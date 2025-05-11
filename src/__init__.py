from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from src.config import Config
from src.models import db  #db from models
from dotenv import load_dotenv
import os
from services.cleanup import cleanup_blacklist
from apscheduler.schedulers.background import BackgroundScheduler


from flask import Flask, session

load_dotenv()
# Load environment variables
def create_app(config_class=Config):
    """Factory function to create and configure the Flask app."""
    
    # Create the Flask app instance
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configure the database (SQLite for simplicity)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../db/database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Silence deprecation warnings
    
    # Initialise extensions with the app
    db.init_app(app)
    
    # Import and register blueprints
    from src.routes import auth_bp
    app.register_blueprint(auth_bp)
    
    # Ensure app context is available for db operations
    with app.app_context():
        print("Creating tables...")  # Debugging line
        db.create_all()  # Create tables 

    # Set up the scheduler for token cleanup
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=cleanup_blacklist, trigger="interval", hours=2)  # Run every 2 hours only runs when flask is running
    scheduler.start()

    
    return app

# Create the app instance
app = create_app()