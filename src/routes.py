# src/routes.py
from flask import Blueprint, request, jsonify, current_app, g
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timezone, timedelta
from src.models import *
from middleware.auth import auth_required
import requests
import secrets


# Initialise Blueprint for auth routes
auth_bp = Blueprint('auth', __name__, url_prefix='/api')
limiter = Limiter(get_remote_address)

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
@limiter.limit("5 per minute") 
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
        
        # Password validation
        password = data['password']
        password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[_&])[A-Za-z\d_&]{8,}$'
        if not re.match(password_pattern, password):
            return jsonify({'error': 'Password must be at least 8 characters long and include letters, numbers, and special characters (_&).'}), 400
       
         # Validate email
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        email = data['email']
        if not re.match(email_pattern, email):
         return jsonify({'error': 'Invalid email format'}), 400

         
        
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
@limiter.limit("5 per minute")  
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
@limiter.limit("5 per minute") 
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
#                       UPDATE PASSWORD ENDPOINT
# -------------------------------------------------------------------
@auth_bp.route('/users/<int:user_id>/password', methods=['PUT'])
@auth_required
def update_password(user_id):
    if request.user_id != user_id:
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json()
    old_password = data.get('oldPassword')
    new_password = data.get('newPassword')
    
    # Validate input
    if not old_password or not new_password:
        return jsonify({'error': 'Both old and new passwords are required'}), 400

    # Password validation
    password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[_&])[A-Za-z\d_&]{8,}$'
    if not re.match(password_pattern, new_password):
        return jsonify({'error': 'New password must be at least 8 characters long and include letters, numbers, and special characters (_&).'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not check_password_hash(user.password_hash, old_password):
        return jsonify({'error': 'Old password is incorrect'}), 401

    user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()

    return jsonify({'message': 'Password updated successfully'}), 200



# ------------------------------------------------------------------- #
#                       CREATE PROFILE ENDPOINT (POST)
# ------------------------------------------------------------------- #
@auth_bp.route('/profile', methods=['POST'])
@auth_required
def create_profile():
    """
    Create a new profile for the authenticated user.

    Request Body (JSON):
        {
            "username": "user123",
            "profile_picture": "https://example.com/profile.jpg"
        }

    Returns:
        - 201: Profile created successfully
        - 400: Invalid input or missing fields
        - 409: Profile already exists for this user
    """

    try:
        data = request.get_json()

        # Validate input
        if not data or 'username' not in data:
            return jsonify({'error': 'Username is required'}), 400

        # Check if profile already exists for the user
        user_id = request.user_id  # Extracted from JWT token
        existing_profile = Profile.query.filter_by(user_id=user_id).first()

        if existing_profile:
            return jsonify({'error': 'Profile already exists for this user'}), 409

        # Create new profile
        new_profile = Profile(
            user_id=user_id,
            username=data['username'],
            profile_picture=data.get('profile_picture')
        )

        db.session.add(new_profile)
        db.session.commit()

        return jsonify({'message': 'Profile created successfully'}), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating profile: {str(e)}")
        return jsonify({'error': 'Failed to create profile. Please try again later.'}), 500

# ------------------------------------------------------------------- #
#                       UPDATE PROFILE ENDPOINT
# ------------------------------------------------------------------- #
@auth_bp.route('/profile', methods=['PUT'])
@auth_required
def update_profile():
    """
    Update the profile for the authenticated user.

    Request Body (JSON):
        {
            "username": "new_username",
            "profile_picture": "https://example.com/new_profile.jpg"
        }

    Returns:
        - 200: Profile updated successfully
        - 400: Invalid input
        - 404: Profile not found
    """

    try:
        data = request.get_json()

        # Validate input
        if not data or 'username' not in data:
            return jsonify({'error': 'Username is required'}), 400

        # Get the user's profile
        user_id = request.user_id  # Extracted from JWT token
        profile = Profile.query.filter_by(user_id=user_id).first()

        if not profile:
            return jsonify({'error': 'Profile not found'}), 404

        # Update profile fields
        profile.username = data['username']
        profile.profile_picture = data.get('profile_picture', profile.profile_picture)  # Keep existing if no new picture

        db.session.commit()

        return jsonify({'message': 'Profile updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating profile: {str(e)}")
        return jsonify({'error': 'Failed to update profile. Please try again later.'}), 500




# ------------------------------------------------------------------- #
#                       COUNTRY DETAILS ENDPOINT
# -------------------------------------------------------------------
@auth_bp.route('/countries/<country_name>', methods=['GET'])
@limiter.limit("5 per minute")
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
    

    # src/routes.py (add these to your existing routes)

# ------------------------------------------------------------------- #
#                       CREATE BLOG POST ENDPOINT 
# ------------------------------------------------------------------- #
@auth_bp.route('/blogpost', methods=['POST'])
@auth_required
def create_blog_post():
    """
    Create a new blog post for the authenticated user.

    Request Body (JSON):
        {
            "title": "My Trip to Japan",
            "content": "This is the content of my blog post.",
            "country": "Japan",
            "date_of_visit": "2025-05-12T12:00:00Z"
        }

    Returns:
        - 201: Blog post created successfully
        - 400: Invalid input or missing fields
        - 409: Blog post already exists for the user
    """

    try:
        data = request.get_json()

        # Validate input
        if not data or 'title' not in data or 'content' not in data or 'country' not in data or 'date_of_visit' not in data:
            return jsonify({'error': 'All fields (title, content, country, date_of_visit) are required'}), 400

        # Check if the blog post already exists
        user_id = request.user_id  # Extracted from JWT token
        existing_post = BlogPost.query.filter_by(user_id=user_id, title=data['title']).first()

        if existing_post:
            return jsonify({'error': 'Blog post with this title already exists for this user'}), 409

        # Create new blog post
        new_blog_post = BlogPost(
            title=data['title'],
            content=data['content'],
            country=data['country'],
            date_of_visit=datetime.fromisoformat(data['date_of_visit']),
            user_id=user_id
        )

        db.session.add(new_blog_post)
        db.session.commit()

        return jsonify({'message': 'Blog post created successfully'}), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating blog post: {str(e)}")
        return jsonify({'error': 'Failed to create blog post. Please try again later.'}), 500

# ------------------------------------------------------------------- #
#                       UPDATE BLOG POST ENDPOINT
# ------------------------------------------------------------------- #
@auth_bp.route('/blogpost/<int:post_id>', methods=['PUT'])
@auth_required
def update_blog_post(post_id):
    """
    Update the blog post for the authenticated user.

    Request Body (JSON):
        {
            "title": "Updated Trip to Japan",
            "content": "Updated content of my blog post.",
            "country": "Japan",
            "date_of_visit": "2025-05-13T12:00:00Z"
        }

    Returns:
        - 200: Blog post updated successfully
        - 400: Invalid input
        - 404: Blog post not found
    """

    try:
        data = request.get_json()

        # Validate input
        if not data or 'title' not in data or 'content' not in data or 'country' not in data or 'date_of_visit' not in data:
            return jsonify({'error': 'All fields (title, content, country, date_of_visit) are required'}), 400

        # Get the blog post
        user_id = request.user_id  # Extracted from JWT token
        blog_post = BlogPost.query.filter_by(id=post_id, user_id=user_id).first()

        if not blog_post:
            return jsonify({'error': 'Blog post not found'}), 404

        # Update blog post fields
        blog_post.title = data['title']
        blog_post.content = data['content']
        blog_post.country = data['country']
        blog_post.date_of_visit = datetime.fromisoformat(data['date_of_visit'])

        # `updated_at` will be updated automatically by the database's `onupdate` functionality
        db.session.commit()

        return jsonify({'message': 'Blog post updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating blog post: {str(e)}")
        return jsonify({'error': 'Failed to update blog post. Please try again later.'}), 500
