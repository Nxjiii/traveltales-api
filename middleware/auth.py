from functools import wraps
from flask import request, jsonify, current_app
import jwt
from src.models import TokenBlacklist
from datetime import datetime, timezone

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401

        token = auth_header.split(" ")[1]

        try:
            # Check if token is blacklisted
            if TokenBlacklist.query.filter_by(token=token).first():
                return jsonify({"error": "Token has been revoked"}), 401

            # Decode token
            decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])

            # Attach user_id and token to request for downstream use
            request.user_id = decoded['user_id']
            request.token = token  # <- ADD THIS LINE

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated_function
