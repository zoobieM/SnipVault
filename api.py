"""
SnipVault REST API
Provides JSON endpoints for external apps (browser extensions, mobile apps)
"""

from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from functools import wraps

# Import database functions
from database import (
    get_user_by_username,
    create_user,
    get_user_snippets,
    create_snippet,
    update_snippet,
    delete_snippet,
    get_db_conn,
    is_postgres
)

# Create Blueprint - keeps API routes separate from web routes
# Blueprint = like a mini Flask app, keeps code organized
api = Blueprint('api', __name__, url_prefix='/api')

# Secret key for JWT tokens (should match Flask app secret)
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_secret_key_change_in_production')

# ============================
# HELPER FUNCTIONS
# ============================

def generate_token(user_id, username):
    """
    Generate JWT token for authenticated user
    
    Token contains:
    - user_id: Unique user identifier
    - username: Display name
    - exp: Expiration time (24 hours)
    
    Returns: JWT token string
    """
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Token expires in 24 hours
    }
    
    # jwt.encode creates encrypted token
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def token_required(f):
    """
    Decorator to protect API routes - requires valid JWT token
    
    Usage:
        @api.route('/protected')
        @token_required
        def protected_route(current_user):
            # current_user is automatically provided by decorator
            return jsonify({'message': f'Hello {current_user["username"]}'})
    
    How it works:
    1. Checks for Authorization header: "Bearer <token>"
    2. Decodes and validates token
    3. If valid: calls the route function with user data
    4. If invalid: returns 401 error
    """
    @wraps(f)  # Preserves function metadata
    def decorator(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            # Format: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            try:
                token = auth_header.split(' ')[1]  # Get token after "Bearer "
            except IndexError:
                return jsonify({'error': 'Invalid token format. Use: Bearer <token>'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing. Include Authorization header.'}), 401
        
        try:
            # Decode and verify token
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = {
                'id': data['user_id'],
                'username': data['username']
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired. Please login again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token. Authentication failed.'}), 401
        
        # Call the actual route function with current_user
        return f(current_user, *args, **kwargs)
    
    return decorator

# ============================
# AUTHENTICATION ROUTES
# ============================

@api.route('/auth/register', methods=['POST'])
def register():
    """
    Register new user account
    
    Request Body (JSON):
    {
        "username": "john_doe",
        "password": "securepass123"
    }
    
    Response:
    Success (201):
    {
        "message": "User created successfully",
        "username": "john_doe"
    }
    
    Error (400):
    {
        "error": "Username already exists"
    }
    """
    # Get JSON data from request
    data = request.get_json()
    
    # Validation
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    
    username = data['username'].strip()
    password = data['password']
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    # Check if username exists
    if get_user_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400
    
    # Create user
    password_hash = generate_password_hash(password)
    if create_user(username, password_hash):
        return jsonify({
            'message': 'User created successfully',
            'username': username
        }), 201
    else:
        return jsonify({'error': 'Failed to create user'}), 500

@api.route('/auth/login', methods=['POST'])
def login():
    """
    Login and receive JWT token
    
    Request Body (JSON):
    {
        "username": "john_doe",
        "password": "securepass123"
    }
    
    Response:
    Success (200):
    {
        "message": "Login successful",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "user": {
            "id": 1,
            "username": "john_doe"
        }
    }
    
    Error (401):
    {
        "error": "Invalid credentials"
    }
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    
    username = data['username'].strip()
    password = data['password']
    
    # Find user
    user = get_user_by_username(username)
    
    if user and check_password_hash(user[2], password):
        # Login successful - generate token
        token = generate_token(user[0], user[1])
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1]
            }
        }), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# ============================
# SNIPPET ROUTES
# ============================

@api.route('/snippets', methods=['GET'])
@token_required
def get_snippets(current_user):
    """
    Get all snippets for authenticated user
    
    Query Parameters:
    - q: Search query (optional)
    
    Example: GET /api/snippets?q=python
    
    Response (200):
    {
        "snippets": [
            {
                "id": 1,
                "content": "Hello World",
                "tag": "greeting",
                "created_at": "2024-01-04 10:30:00",
                "last_edited": "2024-01-04 10:30:00"
            },
            ...
        ],
        "count": 5
    }
    """
    search_query = request.args.get('q', '').strip()
    
    snippets = get_user_snippets(
        current_user['id'],
        search_query if search_query else None
    )
    
    # Convert to list of dictionaries for JSON response
    snippets_list = []
    for snippet in snippets:
        snippets_list.append({
            'id': snippet[0],
            'content': snippet[1],
            'tag': snippet[2],
            'created_at': str(snippet[3]) if snippet[3] else None,
            'last_edited': str(snippet[4]) if snippet[4] else None
        })
    
    return jsonify({
        'snippets': snippets_list,
        'count': len(snippets_list)
    }), 200

@api.route('/snippets/<int:snippet_id>', methods=['GET'])
@token_required
def get_snippet(current_user, snippet_id):
    """
    Get specific snippet by ID
    
    Response (200):
    {
        "id": 1,
        "content": "Hello World",
        "tag": "greeting",
        "created_at": "2024-01-04 10:30:00",
        "last_edited": "2024-01-04 10:30:00"
    }
    
    Error (404):
    {
        "error": "Snippet not found"
    }
    """
    # Get snippet from database
    conn = get_db_conn()
    c = conn.cursor()
    
    if is_postgres():
        query = "SELECT id, content, tag, created_at, last_edited FROM snippets WHERE id = %s AND user_id = %s"
    else:
        query = "SELECT id, content, tag, created_at, last_edited FROM snippets WHERE id = ? AND user_id = ?"
    
    c.execute(query, (snippet_id, current_user['id']))
    snippet = c.fetchone()
    conn.close()
    
    if not snippet:
        return jsonify({'error': 'Snippet not found'}), 404
    
    return jsonify({
        'id': snippet[0],
        'content': snippet[1],
        'tag': snippet[2],
        'created_at': str(snippet[3]) if snippet[3] else None,
        'last_edited': str(snippet[4]) if snippet[4] else None
    }), 200

@api.route('/snippets', methods=['POST'])
@token_required
def create_snippet_api(current_user):
    """
    Create new snippet
    
    Request Body (JSON):
    {
        "content": "print('Hello World')",
        "tag": "python"  // optional
    }
    
    Response (201):
    {
        "message": "Snippet created successfully",
        "snippet": {
            "content": "print('Hello World')",
            "tag": "python"
        }
    }
    """
    data = request.get_json()
    
    if not data or not data.get('content'):
        return jsonify({'error': 'Content is required'}), 400
    
    content = data['content'].strip()
    tag = data.get('tag', '').strip() if data.get('tag') else None
    
    if create_snippet(current_user['id'], content, tag):
        return jsonify({
            'message': 'Snippet created successfully',
            'snippet': {
                'content': content,
                'tag': tag
            }
        }), 201
    else:
        return jsonify({'error': 'Failed to create snippet'}), 500

@api.route('/snippets/<int:snippet_id>', methods=['PUT'])
@token_required
def update_snippet_api(current_user, snippet_id):
    """
    Update existing snippet
    
    Request Body (JSON):
    {
        "content": "Updated content",
        "tag": "updated_tag"  // optional
    }
    
    Response (200):
    {
        "message": "Snippet updated successfully"
    }
    """
    data = request.get_json()
    
    if not data or not data.get('content'):
        return jsonify({'error': 'Content is required'}), 400
    
    content = data['content'].strip()
    tag = data.get('tag', '').strip() if data.get('tag') else None
    
    if update_snippet(snippet_id, current_user['id'], content, tag):
        return jsonify({'message': 'Snippet updated successfully'}), 200
    else:
        return jsonify({'error': 'Failed to update snippet'}), 500

@api.route('/snippets/<int:snippet_id>', methods=['DELETE'])
@token_required
def delete_snippet_api(current_user, snippet_id):
    """
    Delete snippet
    
    Response (200):
    {
        "message": "Snippet deleted successfully"
    }
    """
    if delete_snippet(snippet_id, current_user['id']):
        return jsonify({'message': 'Snippet deleted successfully'}), 200
    else:
        return jsonify({'error': 'Failed to delete snippet'}), 500

# ============================
# USER INFO ROUTE
# ============================

@api.route('/user', methods=['GET'])
@token_required
def get_user_info(current_user):
    """
    Get current user information
    
    Response (200):
    {
        "id": 1,
        "username": "john_doe"
    }
    """
    return jsonify({
        'id': current_user['id'],
        'username': current_user['username']
    }), 200

# ============================
# API STATUS ROUTE
# ============================

@api.route('/status', methods=['GET'])
def api_status():
    """
    Check if API is working (no authentication required)
    
    Response (200):
    {
        "status": "ok",
        "message": "SnipVault API is running",
        "version": "1.0"
    }
    """
    return jsonify({
        'status': 'ok',
        'message': 'SnipVault API is running',
        'version': '1.0'
    }), 200
