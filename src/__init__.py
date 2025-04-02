from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from src.config import Config
from src.models import db  #db from models

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
    
    return app

# Create the app instance
app = create_app()