"""
SnipVault REST API
Provides programmatic access to snippets and folders
"""

from flask import Blueprint, request, jsonify
from functools import wraps
import secrets
from database import (
    get_user_by_username,
    get_user_snippets,
    create_snippet,
    update_snippet,
    delete_snippet,
    get_user_folders,
    create_folder,
    update_folder,
    delete_folder,
    get_db_conn,
    is_postgres
)

api = Blueprint('api', __name__, url_prefix='/api')

# ============================
# API KEY AUTHENTICATION
# ============================

def require_api_key(f):
    """Decorator to require API key for endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'API key required', 'message': 'Include X-API-Key header'}), 401
        
        # Verify API key and get user
        conn = get_db_conn()
        c = conn.cursor()
        
        if is_postgres():
            c.execute("SELECT user_id FROM api_keys WHERE key = %s AND is_active = TRUE", (api_key,))
        else:
            c.execute("SELECT user_id FROM api_keys WHERE key = ? AND is_active = 1", (api_key,))
        
        result = c.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Add user_id to request context
        request.user_id = result[0]
        return f(*args, **kwargs)
    
    return decorated_function


# ============================
# AUTHENTICATION ENDPOINTS
# ============================

@api.route('/auth', methods=['POST'])
def authenticate():
    """
    Generate API key from username/password
    
    Request:
        {
            "username": "johndoe",
            "password": "password123"
        }
    
    Response:
        {
            "api_key": "sk_abc123...",
            "message": "API key generated successfully"
        }
    """
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    # Verify user credentials
    from werkzeug.security import check_password_hash
    user_data = get_user_by_username(username)
    
    if not user_data or not check_password_hash(user_data[2], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user_id = user_data[0]
    
    # Generate API key
    api_key = 'sk_' + secrets.token_urlsafe(32)
    
    # Store API key
    conn = get_db_conn()
    c = conn.cursor()
    
    if is_postgres():
        c.execute("INSERT INTO api_keys (user_id, key) VALUES (%s, %s)", (user_id, api_key))
    else:
        c.execute("INSERT INTO api_keys (user_id, key) VALUES (?, ?)", (user_id, api_key))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'api_key': api_key,
        'message': 'API key generated successfully',
        'note': 'Store this key securely - it will not be shown again'
    }), 201


@api.route('/keys', methods=['GET'])
@require_api_key
def list_api_keys():
    """List all API keys for authenticated user"""
    conn = get_db_conn()
    c = conn.cursor()
    
    if is_postgres():
        c.execute("SELECT id, key, created_at, is_active FROM api_keys WHERE user_id = %s ORDER BY created_at DESC", (request.user_id,))
    else:
        c.execute("SELECT id, key, created_at, is_active FROM api_keys WHERE user_id = ? ORDER BY created_at DESC", (request.user_id,))
    
    keys = c.fetchall()
    conn.close()
    
    return jsonify({
        'keys': [
            {
                'id': k[0],
                'key': k[1][:10] + '...' + k[1][-4:],  # Masked
                'created_at': str(k[2]),
                'is_active': bool(k[3])
            }
            for k in keys
        ]
    })


@api.route('/keys/<int:key_id>', methods=['DELETE'])
@require_api_key
def revoke_api_key(key_id):
    """Revoke an API key"""
    conn = get_db_conn()
    c = conn.cursor()
    
    if is_postgres():
        c.execute("UPDATE api_keys SET is_active = FALSE WHERE id = %s AND user_id = %s", (key_id, request.user_id))
    else:
        c.execute("UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?", (key_id, request.user_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'API key revoked successfully'})


# ============================
# SNIPPET ENDPOINTS
# ============================

@api.route('/snippets', methods=['GET'])
@require_api_key
def get_snippets():
    """
    Get all snippets for authenticated user
    
    Query params:
        - q: Search query
        - folder: Filter by folder ID
        - limit: Max results (default 100)
        - offset: Pagination offset
    
    Response:
        {
            "snippets": [...],
            "count": 42
        }
    """
    search_query = request.args.get('q')
    folder_id = request.args.get('folder')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    # Convert folder to int
    folder_id = int(folder_id) if folder_id else None
    
    snippets = get_user_snippets(request.user_id, search_query, folder_id)
    
    # Apply pagination
    paginated = snippets[offset:offset + limit]
    
    return jsonify({
        'snippets': [
            {
                'id': s[0],
                'content': s[1],
                'tag': s[2],
                'folder_id': s[3],
                'created_at': str(s[4]),
                'last_edited': str(s[5])
            }
            for s in paginated
        ],
        'count': len(snippets),
        'limit': limit,
        'offset': offset
    })


@api.route('/snippets/<int:snippet_id>', methods=['GET'])
@require_api_key
def get_snippet(snippet_id):
    """Get a single snippet by ID"""
    conn = get_db_conn()
    c = conn.cursor()
    
    if is_postgres():
        c.execute("SELECT id, content, tag, folder_id, created_at, last_edited FROM snippets WHERE id = %s AND user_id = %s", (snippet_id, request.user_id))
    else:
        c.execute("SELECT id, content, tag, folder_id, created_at, last_edited FROM snippets WHERE id = ? AND user_id = ?", (snippet_id, request.user_id))
    
    snippet = c.fetchone()
    conn.close()
    
    if not snippet:
        return jsonify({'error': 'Snippet not found'}), 404
    
    return jsonify({
        'id': snippet[0],
        'content': snippet[1],
        'tag': snippet[2],
        'folder_id': snippet[3],
        'created_at': str(snippet[4]),
        'last_edited': str(snippet[5])
    })


@api.route('/snippets', methods=['POST'])
@require_api_key
def create_snippet_api():
    """
    Create a new snippet
    
    Request:
        {
            "content": "def hello():\n    print('Hi')",
            "tag": "python",
            "folder_id": 1
        }
    
    Response:
        {
            "id": 123,
            "message": "Snippet created successfully"
        }
    """
    data = request.get_json()
    
    if not data or 'content' not in data:
        return jsonify({'error': 'Content is required'}), 400
    
    content = data['content']
    tag = data.get('tag')
    folder_id = data.get('folder_id')
    
    try:
        create_snippet(request.user_id, content, tag, folder_id)
        return jsonify({'message': 'Snippet created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/snippets/<int:snippet_id>', methods=['PUT'])
@require_api_key
def update_snippet_api(snippet_id):
    """
    Update a snippet
    
    Request:
        {
            "content": "updated content",
            "tag": "javascript",
            "folder_id": 2
        }
    """
    data = request.get_json()
    
    if not data or 'content' not in data:
        return jsonify({'error': 'Content is required'}), 400
    
    content = data['content']
    tag = data.get('tag')
    folder_id = data.get('folder_id')
    
    try:
        update_snippet(snippet_id, request.user_id, content, tag, folder_id)
        return jsonify({'message': 'Snippet updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/snippets/<int:snippet_id>', methods=['DELETE'])
@require_api_key
def delete_snippet_api(snippet_id):
    """Delete a snippet"""
    try:
        delete_snippet(snippet_id, request.user_id)
        return jsonify({'message': 'Snippet deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================
# FOLDER ENDPOINTS
# ============================

@api.route('/folders', methods=['GET'])
@require_api_key
def get_folders_api():
    """Get all folders for authenticated user"""
    folders = get_user_folders(request.user_id)
    
    return jsonify({
        'folders': [
            {
                'id': f[0],
                'name': f[1],
                'color': f[2]
            }
            for f in folders
        ]
    })


@api.route('/folders', methods=['POST'])
@require_api_key
def create_folder_api():
    """
    Create a new folder
    
    Request:
        {
            "name": "Python Scripts",
            "color": "#10b981"
        }
    """
    data = request.get_json()
    
    if not data or 'name' not in data:
        return jsonify({'error': 'Name is required'}), 400
    
    name = data['name']
    color = data.get('color', '#6366f1')
    
    try:
        folder_id = create_folder(request.user_id, name, color)
        return jsonify({'id': folder_id, 'message': 'Folder created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/folders/<int:folder_id>', methods=['PUT'])
@require_api_key
def update_folder_api(folder_id):
    """Update a folder"""
    data = request.get_json()
    
    if not data or 'name' not in data:
        return jsonify({'error': 'Name is required'}), 400
    
    name = data['name']
    color = data.get('color', '#6366f1')
    
    try:
        update_folder(folder_id, request.user_id, name, color)
        return jsonify({'message': 'Folder updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/folders/<int:folder_id>', methods=['DELETE'])
@require_api_key
def delete_folder_api(folder_id):
    """Delete a folder"""
    try:
        delete_folder(folder_id, request.user_id)
        return jsonify({'message': 'Folder deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================
# HEALTH CHECK
# ============================

@api.route('/health', methods=['GET'])
def health_check():
    """Public health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'SnipVault API',
        'version': '1.0.0'
    })
