# src/routes.py
from flask import Blueprint, request, jsonify, current_app, g
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timezone, timedelta
from src.models import User, db, APIKey, TokenBlacklist
from middleware.auth import auth_required
import requests
import secrets


# Initialise Blueprint for auth routes
auth_bp = Blueprint('auth', __name__, url_prefix='/api')

# ------------------------------------------------------------------- #
#                       TEST ENDPOINT
# -------------------------------------------------------------------
@auth_bp.route('/test', methods=['GET'])
def test_route():
    return "Test route is working", 200
    
# ------------------------------------------------------------------- #
#                       REGISTER ENDPOINT                                #
# ------------------------------------------------------------------- #
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
        - 201: User created with JWT token and API key
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
        
        # Generate API key for the user
        api_key = secrets.token_hex(32)  # 64-character hex string
        new_api_key = APIKey(key=api_key, user_id=new_user.id)
        db.session.add(new_api_key)
        db.session.commit()
        
        # Generate JWT token
        token = jwt.encode(
            {
                'user_id': new_user.id,
                'exp': datetime.now(timezone.utc) + timedelta(hours=1)
            },
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        
        return jsonify({
            'message': f"User registered successfully. JWT token and API key generated.",
            'token': token,
            'api_key': api_key
        }), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed. Please try again later.'}), 400


# ------------------------------------------------------------------- #
#                          LOGIN ENDPOINT
# -------------------------------------------------------------------
@auth_bp.route('/login', methods=['POST'])
def login():
    current_app.logger.info("Login endpoint hit")
    
    data = request.get_json()

    # Validate that required fields are provided
    if 'email' not in data or 'password' not in data:
        current_app.logger.warning("Email or password not provided")
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=data['email']).first()

    # Validate credentials
    if not user or not check_password_hash(user.password_hash, data['password']):
        current_app.logger.warning(f"Failed login attempt for {data['email']}")
        return jsonify({'error': 'Invalid email or password'}), 401

    # fetch API key for the user or generate if they don't have one
    existing_key = APIKey.query.filter_by(user_id=user.id, is_active=True).first()
    if existing_key:
        api_key = existing_key.key
    else:
        api_key = secrets.token_hex(32)  # 64-character hex string
        new_api_key = APIKey(key=api_key, user_id=user.id)
        db.session.add(new_api_key)
        db.session.commit()

    # Generate JWT token
    token = jwt.encode(
        {
            'user_id': user.id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=1)
        },
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    # Log successful login
    current_app.logger.info(f"Login successful for {user.email}")

    return jsonify({
        'message': f"Login successful for {user.email}. JWT token generated and API key provided.",
        'token': token,
        'api_key': api_key
    }), 200
    

# ------------------------------------------------------------------- #
#                       LOGOUT ENDPOINT
# -------------------------------------------------------------------


@auth_bp.route('/logout', methods=['POST'])
@auth_required
def logout():
    token = request.token  
    
    try:
        # Decode the token to extract expiry from request.token
        decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        exp = datetime.fromtimestamp(decoded['exp'], tz=timezone.utc)
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token already expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

    # Token to blacklist
    blacklisted = TokenBlacklist(token=token, expires_at=exp)
    db.session.add(blacklisted)
    db.session.commit()

    return jsonify({'message': 'Logout successful. Token has been invalidated.'}), 200

# ------------------------------------------------------------------- #
#                       DELETE USER ENDPOINT
# -------------------------------------------------------------------

@auth_bp.route('/delete', methods=['DELETE'])
@auth_required
def delete_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header is missing or invalid'}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Decode the token
        decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

    try:
        # Delete user and related data
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Delete the user and related records (APIKey, etc.)
        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': 'User and related data deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting user: {str(e)}")
        return jsonify({'error': 'Failed to delete user. Please try again later.'}), 500


# ------------------------------------------------------------------- #
#                       COUNTRY DETAILS ENDPOINT
# -------------------------------------------------------------------
@auth_bp.route('/countries/<country_name>', methods=['GET'])
def get_country_info(country_name):
    """
    Fetch country details from the RestCountries API.
    This endpoint requires API key authentication.
    
    Request Headers:
        Authorization: Bearer <API_KEY>
    
    Parameters:
        country_name (str): The country name to fetch details for.
        
    Returns:
        - 200: Country data successfully retrieved.
        - 401: Invalid API key or missing API key.
        - 404: Country not found.
    """
    # Extract API key from Authorization header
    api_key = request.headers.get('Authorization')

    if not api_key:
        return jsonify({'error': 'API key is required'}), 401
    
    # Check if the API key is valid
    api_key = api_key.split(" ")[1]  # Remove "Bearer" part from the header
    key = APIKey.query.filter_by(key=api_key, is_active=True).first()

    if not key:
        return jsonify({'error': 'Invalid or inactive API key'}), 401

    # Fetch country data from RestCountries API
    url = f"https://restcountries.com/v3.1/name/{country_name}"
    response = requests.get(url)
    
    if response.status_code == 200:
        country_data = response.json()[0]

        # Extract relevant country details
        country_info = {
            'name': country_data['name']['common'],
            'currency': list(country_data['currencies'].keys())[0] if 'currencies' in country_data else 'N/A',
            'capital': country_data['capital'][0] if 'capital' in country_data else 'N/A',
            'languages': list(country_data['languages'].values()) if 'languages' in country_data else ['N/A'],
            'flag': country_data['flags']['png']
        }

        return jsonify(country_info), 200
    else:
        return jsonify({'error': 'Country not found'}), 404