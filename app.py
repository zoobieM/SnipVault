"""
SnipVault - Secure Universal Snippet Manager
A cross-platform snippet manager with user authentication, OAuth, and cloud sync
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Import database functions
from database import (
    init_db, 
    get_user_by_username, 
    create_user, 
    get_user_snippets,
    create_snippet, 
    update_snippet, 
    delete_snippet,
    get_db_conn,
    is_postgres,
    get_user_folders,
    create_folder,
    update_folder,
    delete_folder
)

# Import OAuth
from oauth import init_oauth

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# Load OAuth config
app.config['GOOGLE_CLIENT_ID'] = os.environ.get("GOOGLE_CLIENT_ID")
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get("GOOGLE_CLIENT_SECRET")
app.config['GITHUB_CLIENT_ID'] = os.environ.get("GITHUB_CLIENT_ID")
app.config['GITHUB_CLIENT_SECRET'] = os.environ.get("GITHUB_CLIENT_SECRET")

# Initialize OAuth
oauth = init_oauth(app)

# Initialize database tables on startup
init_db()

# ============================
# FLASK-LOGIN SETUP
# ============================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE id = %s" if is_postgres() else "SELECT id, username FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1])
    return None

# ============================
# TEMPLATE FILTERS
# ============================

def format_timestamp(timestamp_str):
    """Convert database timestamp to human-readable relative time"""
    if not timestamp_str:
        return ""
    
    try:
        if isinstance(timestamp_str, str):
            created = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        else:
            created = timestamp_str
        
        now = datetime.utcnow()
        diff = now - created
        seconds = diff.total_seconds()
        
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            mins = int(seconds / 60)
            return f"{mins} min{'s' if mins != 1 else ''} ago"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif seconds < 604800:
            days = int(seconds / 86400)
            return f"{days} day{'s' if days != 1 else ''} ago"
        else:
            return created.strftime("%b %d, %Y")
    except Exception as e:
        return str(timestamp_str)

app.jinja_env.filters['format_timestamp'] = format_timestamp

# ============================
# OAUTH ROUTES
# ============================

@app.route('/auth/google')
def google_login():
    """Redirect to Google's OAuth login page"""
    redirect_uri = url_for('google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    """Handle callback from Google after user authorizes"""
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if user_info:
            email = user_info.get('email')
            username = email.split('@')[0]
            
            conn = get_db_conn()
            c = conn.cursor()
            
            if is_postgres():
                c.execute("SELECT id, username FROM users WHERE username = %s", (username,))
            else:
                c.execute("SELECT id, username FROM users WHERE username = ?", (username,))
            
            existing_user = c.fetchone()
            
            if existing_user:
                user = User(existing_user[0], existing_user[1])
                login_user(user, remember=True)
                flash(f'Welcome back, {username}!', 'success')
            else:
                random_password = os.urandom(24).hex()
                password_hash = generate_password_hash(random_password)
                
                if is_postgres():
                    c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id", (username, password_hash))
                    user_id = c.fetchone()[0]
                else:
                    c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
                    user_id = c.lastrowid
                
                conn.commit()
                
                user = User(user_id, username)
                login_user(user, remember=True)
                flash(f'Welcome to SnipVault, {username}! 🎉', 'success')
            
            conn.close()
            return redirect(url_for('home'))
        
        else:
            flash('Failed to get user information from Google.', 'warning')
            return redirect(url_for('login'))
    
    except Exception as e:
        flash(f'Authentication failed: {str(e)}', 'warning')
        return redirect(url_for('login'))

# ============================
# GITHUB OAUTH ROUTES
# ============================

@app.route('/auth/github')
def github_login():
    """Redirect to GitHub's OAuth login page"""
    redirect_uri = url_for('github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@app.route('/auth/github/callback')
def github_callback():
    """Handle callback from GitHub after user authorizes"""
    try:
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get('user', token=token)
        user_info = resp.json()
        
        if user_info:
            github_username = user_info.get('login')
            username = github_username
            
            conn = get_db_conn()
            c = conn.cursor()
            
            if is_postgres():
                c.execute("SELECT id, username FROM users WHERE username = %s", (username,))
            else:
                c.execute("SELECT id, username FROM users WHERE username = ?", (username,))
            
            existing_user = c.fetchone()
            
            if existing_user:
                user = User(existing_user[0], existing_user[1])
                login_user(user, remember=True)
                flash(f'Welcome back, {username}!', 'success')
            else:
                random_password = os.urandom(24).hex()
                password_hash = generate_password_hash(random_password)
                
                if is_postgres():
                    c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id", (username, password_hash))
                    user_id = c.fetchone()[0]
                else:
                    c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
                    user_id = c.lastrowid
                
                conn.commit()
                
                user = User(user_id, username)
                login_user(user, remember=True)
                flash(f'Welcome to SnipVault, {username}! 🎉', 'success')
            
            conn.close()
            return redirect(url_for('home'))
        
        else:
            flash('Failed to get user information from GitHub.', 'warning')
            return redirect(url_for('login'))
    
    except Exception as e:
        flash(f'Authentication failed: {str(e)}', 'warning')
        return redirect(url_for('login'))

# ============================
# ROUTES
# ============================

@app.route('/')
def home():
    """Home page - shows user's snippets or login prompt"""
    from database import get_user_tags, get_snippet_count_by_folder
    
    q = request.args.get('q', '').strip()
    folder_filter = request.args.get('folder')
    tag_filter = request.args.get('tag')
    date_filter = request.args.get('date')
    snippets = []
    folders = []
    tags = []
    folder_counts = []
    
    if current_user.is_authenticated:
        folders = get_user_folders(current_user.id)
        tags = get_user_tags(current_user.id)
        folder_counts = get_snippet_count_by_folder(current_user.id)
        
        # Convert folder_filter to int if provided
        folder_id = None
        if folder_filter is not None:
            try:
                folder_id = int(folder_filter)
            except:
                folder_id = None
        
        snippets = get_user_snippets(
            current_user.id, 
            q if q else None, 
            folder_id,
            tag_filter,
            date_filter
        )
    
    return render_template(
        'index.html', 
        snippets=snippets, 
        folders=folders,
        tags=tags,
        folder_counts=folder_counts,
        q=q, 
        current_folder=folder_filter,
        current_tag=tag_filter,
        current_date=date_filter
    )

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required.', 'warning')
            return redirect(url_for('signup'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'warning')
            return redirect(url_for('signup'))
        
        if get_user_by_username(username):
            flash('Username already taken. Please choose another.', 'warning')
            return redirect(url_for('signup'))
        
        password_hash = generate_password_hash(password)
        
        if create_user(username, password_hash):
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error creating account. Please try again.', 'warning')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required.', 'warning')
            return redirect(url_for('login'))
        
        user_data = get_user_by_username(username)
        
        if user_data and check_password_hash(user_data[2], password):
            user = User(user_data[0], user_data[1])
            login_user(user, remember=True)
            flash(f'Welcome back, {username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'warning')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Log out current user"""
    username = current_user.username
    logout_user()
    flash(f'Goodbye, {username}! Logged out successfully.', 'info')
    return redirect(url_for('home'))

# ============================
# FOLDER ROUTES
# ============================

@app.route('/folders/create', methods=['POST'])
@login_required
def create_folder_route():
    """Create a new folder"""
    name = request.form.get('name', '').strip()
    color = request.form.get('color', '#6366f1').strip()
    
    if not name:
        flash('Folder name cannot be empty.', 'warning')
        return redirect(url_for('home'))
    
    if create_folder(current_user.id, name, color):
        flash(f'Folder "{name}" created!', 'success')
    else:
        flash('Error creating folder.', 'warning')
    
    return redirect(url_for('home'))


@app.route('/folders/<int:folder_id>/edit', methods=['POST'])
@login_required
def edit_folder_route(folder_id):
    """Edit folder name and color"""
    name = request.form.get('name', '').strip()
    color = request.form.get('color', '#6366f1').strip()
    
    if not name:
        flash('Folder name cannot be empty.', 'warning')
        return redirect(url_for('home'))
    
    if update_folder(folder_id, current_user.id, name, color):
        flash('Folder updated!', 'success')
    else:
        flash('Error updating folder.', 'warning')
    
    return redirect(url_for('home'))


@app.route('/folders/<int:folder_id>/delete', methods=['POST'])
@login_required
def delete_folder_route(folder_id):
    """Delete a folder"""
    if delete_folder(folder_id, current_user.id):
        flash('Folder deleted.', 'info')
    else:
        flash('Error deleting folder.', 'warning')
    
    return redirect(url_for('home'))

# ============================
# SNIPPET ROUTES
# ============================

@app.route('/add', methods=['POST'])
@login_required
def add_snippet():
    """Create a new snippet"""
    content = request.form.get('content', '').strip()
    tag = request.form.get('tag', '').strip()
    folder_id = request.form.get('folder_id', '').strip()
    
    if not content:
        flash('Snippet cannot be empty.', 'warning')
        return redirect(url_for('home'))
    
    # Convert folder_id to int or None
    folder_id = int(folder_id) if folder_id and folder_id != '' else None
    
    if create_snippet(current_user.id, content, tag if tag else None, folder_id):
        flash('Snippet saved successfully!', 'success')
    else:
        flash('Error saving snippet.', 'warning')
    
    return redirect(url_for('home'))

@app.route('/edit/<int:snippet_id>', methods=['POST'])
@login_required
def edit_snippet_route(snippet_id):
    """Update an existing snippet"""
    content = request.form.get('content', '').strip()
    tag = request.form.get('tag', '').strip()
    folder_id = request.form.get('folder_id', '').strip()
    
    if not content:
        flash('Snippet cannot be empty.', 'warning')
        return redirect(url_for('home'))
    
    # Convert folder_id to int or None
    folder_id = int(folder_id) if folder_id and folder_id != '' else None
    
    if update_snippet(snippet_id, current_user.id, content, tag if tag else None, folder_id):
        flash('Snippet updated successfully!', 'success')
    else:
        flash('Error updating snippet.', 'warning')
    
    return redirect(url_for('home'))

@app.route('/delete/<int:snippet_id>', methods=['POST'])
@login_required
def delete_snippet_route(snippet_id):
    """Delete a snippet"""
    if delete_snippet(snippet_id, current_user.id):
        flash('Snippet deleted.', 'info')
    else:
        flash('Error deleting snippet.', 'warning')
    
    return redirect(url_for('home'))

# ============================
# ERROR HANDLERS
# ============================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 - Page Not Found"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 - Internal Server Error"""
    return render_template('500.html'), 500

# ============================
# RUN APPLICATION
# ============================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
