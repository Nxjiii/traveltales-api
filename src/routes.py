# src/routes.py
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timezone, timedelta
from src.models import User, db

# Initialise Blueprint for auth routes
auth_bp = Blueprint('auth', __name__, url_prefix='/api')

# ------------------------------------------------------------------- #
#                       TEST ENDPOINT
# -------------------------------------------------------------------
@auth_bp.route('/test', methods=['GET'])
def test_route():
    return "Test route is working", 200
    
# ------------------------------------------------------------------- #
#                       REGISTER ENDPOINT
# -------------------------------------------------------------------
@auth_bp.route('/register', methods=['POST'])
def register():
    print("Register endpoint hit!")  # Debugging line
    """
    Register a new user.
    
    Request Body (JSON):
        {
            "email": "user@example.com",
            "password": "securepassword123"
        }
    
    Returns:
        - 201: User created
        - 400: Invalid input or email exists
    """
    try:
        data = request.get_json()
        
        # Validate input
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400
            
        # Hash password and create user
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_user = User(email=data['email'], password_hash=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Database error: {e}")  # This will show error
        return jsonify({'error': f"Registration failed: {str(e)}"}), 400

# ------------------------------------------------------------------- #
#                          LOGIN ENDPOINT
# -------------------------------------------------------------------
@auth_bp.route('/login', methods=['POST'])
def login():
    print("Login endpoint hit!")
    """
    Authenticate user and return JWT token.

    Request Body (JSON):
        {
            "email": "user@example.com",
            "password": "securepassword123"
        }

    Returns:
        - 200: Success (returns token and message)
        - 401: Invalid credentials
    """

    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    # Validate credentials
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401


    # Generate JWT token (expires 1 hour)
    token = jwt.encode(
        {
            'user_id': user.id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=1)
        },
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    return jsonify({
        'message': f"Login successful for {user.email}. JWT token generated.",   #display the email of the user and that token is generated
    }), 200

    
    # Debugging line to check token generation and encryption
  #  print("Generated JWT:", token)
  #  return jsonify({'token': token}), 200
# ------------------------------------------------------------------- #
    