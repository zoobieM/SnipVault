"""
SnipVault - Database Connection and Initialization Module
Supports both PostgreSQL (production) and SQLite (local development)
"""

import os
import psycopg2
import sqlite3

def get_db_conn():
    DATABASE_URL = os.environ.get("DATABASE_URL")
    
    # Fix Render's postgres:// URL format (should be postgresql://)
    if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    
    if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
        # ✅ PostgreSQL connection (production)
        print("[DB] Using PostgreSQL connection ✅")
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        return conn
    else:
        # ✅ SQLite connection (local development)
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        DB_PATH = os.path.join(BASE_DIR, "snippets.db")
        print(f"[DB] Using SQLite connection at {DB_PATH} ✅")
        conn = sqlite3.connect(DB_PATH)
        return conn


def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    
    DATABASE_URL = os.environ.get("DATABASE_URL")
    
    if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
        # ===== PostgreSQL Schema =====
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # NEW: Folders table
        c.execute("""
            CREATE TABLE IF NOT EXISTS folders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name VARCHAR(255) NOT NULL,
                color VARCHAR(7) DEFAULT '#6366f1',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        # API Key table
        c.execute("""
                  create table if not exists api_keys (
                  id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        key VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
""" if DATABASE_URL and DATABASE_URL.startswith("postgresql://") else """
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
""")
        # UPDATED: Snippets table with folder_id
        c.execute("""
            CREATE TABLE IF NOT EXISTS snippets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                folder_id INTEGER,
                content TEXT NOT NULL,
                tag VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_edited TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (folder_id) REFERENCES folders (id) ON DELETE SET NULL
            )
        """)
        
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_snippets_user_id 
            ON snippets(user_id)
        """)
        
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_snippets_folder_id 
            ON snippets(folder_id)
        """)
        
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_folders_user_id 
            ON folders(user_id)
        """)
        
    else:
        # ===== SQLite Schema =====
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # NEW: Folders table
        c.execute("""
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                color TEXT DEFAULT '#6366f1',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # UPDATED: Snippets table with folder_id
        c.execute("""
            CREATE TABLE IF NOT EXISTS snippets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER,
                content TEXT NOT NULL,
                tag TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_edited TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (folder_id) REFERENCES folders (id) ON DELETE SET NULL
            )
        """)
        
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_snippets_user_id 
            ON snippets(user_id)
        """)
        
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_snippets_folder_id 
            ON snippets(folder_id)
        """)
        
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_folders_user_id 
            ON folders(user_id)
        """)
    
    conn.commit()
    conn.close()


def execute_query(query, params=(), fetch_one=False, fetch_all=False):
    conn = get_db_conn()
    c = conn.cursor()
    
    try:
        c.execute(query, params)
        
        if fetch_one:
            result = c.fetchone()
            conn.close()
            return result
        elif fetch_all:
            result = c.fetchall()
            conn.close()
            return result
        else:
            conn.commit()
            conn.close()
            return None
            
    except Exception as e:
        conn.rollback()
        conn.close()
        raise e


def is_postgres():
    """
    Returns True if connected to PostgreSQL (DATABASE_URL starts with postgresql://).
    """
    DATABASE_URL = os.environ.get("DATABASE_URL")
    return bool(DATABASE_URL and DATABASE_URL.startswith("postgresql://"))


# ============================
# USER FUNCTIONS
# ============================

def get_user_by_username(username):
    if is_postgres():
        query = "SELECT id, username, password_hash FROM users WHERE username = %s"
    else:
        query = "SELECT id, username, password_hash FROM users WHERE username = ?"
    
    return execute_query(query, (username,), fetch_one=True)


def create_user(username, password_hash):
    try:
        if is_postgres():
            query = "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
        else:
            query = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
        
        execute_query(query, (username, password_hash))
        return True
    except:
        return False


# ============================
# FOLDER FUNCTIONS
# ============================

def get_user_folders(user_id):
    """Get all folders for a user"""
    if is_postgres():
        query = "SELECT id, name, color FROM folders WHERE user_id = %s ORDER BY name"
    else:
        query = "SELECT id, name, color FROM folders WHERE user_id = ? ORDER BY name"
    
    return execute_query(query, (user_id,), fetch_all=True)


def create_folder(user_id, name, color='#6366f1'):
    """Create a new folder"""
    try:
        if is_postgres():
            query = "INSERT INTO folders (user_id, name, color) VALUES (%s, %s, %s) RETURNING id"
            conn = get_db_conn()
            c = conn.cursor()
            c.execute(query, (user_id, name, color))
            folder_id = c.fetchone()[0]
            conn.commit()
            conn.close()
            return folder_id
        else:
            query = "INSERT INTO folders (user_id, name, color) VALUES (?, ?, ?)"
            execute_query(query, (user_id, name, color))
            return True
    except:
        return False


def update_folder(folder_id, user_id, name, color):
    """Update folder name and color"""
    if is_postgres():
        query = "UPDATE folders SET name = %s, color = %s WHERE id = %s AND user_id = %s"
    else:
        query = "UPDATE folders SET name = ?, color = ? WHERE id = ? AND user_id = ?"
    
    execute_query(query, (name, color, folder_id, user_id))
    return True


def delete_folder(folder_id, user_id):
    """Delete a folder (snippets will become uncategorized)"""
    if is_postgres():
        query = "DELETE FROM folders WHERE id = %s AND user_id = %s"
    else:
        query = "DELETE FROM folders WHERE id = ? AND user_id = ?"
    
    execute_query(query, (folder_id, user_id))
    return True


# ============================
# SNIPPET FUNCTIONS
# ============================

def get_user_snippets(user_id, search_query=None, folder_id=None, tag_filter=None, date_filter=None):
    """Get snippets with enhanced search capabilities"""
    
    # Determine placeholder and base query
    if is_postgres():
        placeholder = "%s"
        base_query = "SELECT id, content, tag, folder_id, created_at, last_edited FROM snippets WHERE user_id = %s"
    else:
        placeholder = "?"
        base_query = "SELECT id, content, tag, folder_id, created_at, last_edited FROM snippets WHERE user_id = ?"
    
    params = [user_id]
    
    # Search query - search in content and tags
    if search_query:
        search_param = '%' + search_query + '%'
        base_query += f" AND (content LIKE {placeholder} OR tag LIKE {placeholder})"
        params.extend([search_param, search_param])
    
    # Folder filter
    if folder_id is not None:
        if folder_id == 0:  # Uncategorized
            base_query += " AND folder_id IS NULL"
        else:
            base_query += f" AND folder_id = {placeholder}"
            params.append(folder_id)
    
    # Tag filter
    if tag_filter:
        base_query += f" AND tag = {placeholder}"
        params.append(tag_filter)
    
    # Date filter
    if date_filter:
        if date_filter == 'today':
            if is_postgres():
                base_query += " AND DATE(created_at) = CURRENT_DATE"
            else:
                base_query += " AND DATE(created_at) = DATE('now')"
        elif date_filter == 'week':
            if is_postgres():
                base_query += " AND created_at >= CURRENT_DATE - INTERVAL '7 days'"
            else:
                base_query += " AND created_at >= DATE('now', '-7 days')"
        elif date_filter == 'month':
            if is_postgres():
                base_query += " AND created_at >= CURRENT_DATE - INTERVAL '30 days'"
            else:
                base_query += " AND created_at >= DATE('now', '-30 days')"
    
    # Order by date
    base_query += " ORDER BY last_edited DESC, id DESC"
    
    return execute_query(base_query, tuple(params), fetch_all=True)


def get_user_tags(user_id):
    """Get all unique tags for a user"""
    if is_postgres():
        query = """
            SELECT DISTINCT tag 
            FROM snippets 
            WHERE user_id = %s AND tag IS NOT NULL AND tag != ''
            ORDER BY tag
        """
    else:
        query = """
            SELECT DISTINCT tag 
            FROM snippets 
            WHERE user_id = ? AND tag IS NOT NULL AND tag != ''
            ORDER BY tag
        """
    
    results = execute_query(query, (user_id,), fetch_all=True)
    return [tag[0] for tag in results if tag[0]]


def get_snippet_count_by_folder(user_id):
    """Get snippet count for each folder"""
    if is_postgres():
        query = """
            SELECT f.id, f.name, COUNT(s.id) as count
            FROM folders f
            LEFT JOIN snippets s ON f.id = s.folder_id
            WHERE f.user_id = %s
            GROUP BY f.id, f.name
            ORDER BY f.name
        """
    else:
        query = """
            SELECT f.id, f.name, COUNT(s.id) as count
            FROM folders f
            LEFT JOIN snippets s ON f.id = s.folder_id
            WHERE f.user_id = ?
            GROUP BY f.id, f.name
            ORDER BY f.name
        """
    
    return execute_query(query, (user_id,), fetch_all=True)


def create_snippet(user_id, content, tag=None, folder_id=None):
    """Create a new snippet"""
    if is_postgres():
        query = "INSERT INTO snippets (user_id, content, tag, folder_id) VALUES (%s, %s, %s, %s)"
    else:
        query = "INSERT INTO snippets (user_id, content, tag, folder_id) VALUES (?, ?, ?, ?)"
    
    execute_query(query, (user_id, content, tag, folder_id))
    return True


def update_snippet(snippet_id, user_id, content, tag=None, folder_id=None):
    """Update an existing snippet"""
    if is_postgres():
        query = "UPDATE snippets SET content = %s, tag = %s, folder_id = %s, last_edited = CURRENT_TIMESTAMP WHERE id = %s AND user_id = %s"
    else:
        query = "UPDATE snippets SET content = ?, tag = ?, folder_id = ?, last_edited = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"
    
    execute_query(query, (content, tag, folder_id, snippet_id, user_id))
    return True


def delete_snippet(snippet_id, user_id):
    """Delete a snippet"""
    if is_postgres():
        query = "DELETE FROM snippets WHERE id = %s AND user_id = %s"
    else:
        query = "DELETE FROM snippets WHERE id = ? AND user_id = ?"
    
    execute_query(query, (snippet_id, user_id))
    return True

def get_user_tags(user_id):
    """Get all unique tags for a user"""
    if is_postgres():
        query = "SELECT DISTINCT tag FROM snippets WHERE user_id = %s AND tag IS NOT NULL AND tag != '' ORDER BY tag"
    else:
        query = "SELECT DISTINCT tag FROM snippets WHERE user_id = ? AND tag IS NOT NULL AND tag != '' ORDER BY tag"
    
    results = execute_query(query, (user_id,), fetch_all=True)
    return [tag[0] for tag in results if tag[0]]


def get_snippet_count_by_folder(user_id):
    """Get snippet count for each folder"""
    if is_postgres():
        query = """
            SELECT f.id, f.name, COUNT(s.id) as count
            FROM folders f
            LEFT JOIN snippets s ON f.id = s.folder_id
            WHERE f.user_id = %s
            GROUP BY f.id, f.name
            ORDER BY f.name
        """
    else:
        query = """
            SELECT f.id, f.name, COUNT(s.id) as count
            FROM folders f
            LEFT JOIN snippets s ON f.id = s.folder_id
            WHERE f.user_id = ?
            GROUP BY f.id, f.name
            ORDER BY f.name
        """
    
    return execute_query(query, (user_id,), fetch_all=True)
