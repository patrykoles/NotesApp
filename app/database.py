import sqlite3
from datetime import datetime

DATABASE = '/app/data/database.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_email(email):
    db = get_db()
    return db.execute('SELECT id, email, username, password, totp_secret FROM users WHERE email = ?', (email,)).fetchone()


def get_user_by_username(username):
    db = get_db()
    return db.execute('SELECT id, email, username, password, totp_secret FROM users WHERE username = ?', (username,)).fetchone()

def insert_user(username, email, hashed_password, totp_full, private_key_full, public_key):
    db = get_db()
    db.execute(
        'INSERT INTO users (username, email, password, totp_secret, private_key, public_key) '
        'VALUES (?, ?, ?, ?, ?, ?)', 
        (
            username, email, hashed_password, totp_full,
            private_key_full, public_key
        )
    )
    db.commit()

def get_attempts(ip_address, action_type):
    db = get_db()
    return db.execute(
        'SELECT failed_attempts, last_failed_attempt FROM attempt_logs WHERE ip_address = ? AND action_type = ?',
        (ip_address, action_type)
    ).fetchone()

def reset_attempts(ip_address, action_type):
    db = get_db()
    db.execute(
        'UPDATE attempt_logs SET failed_attempts = 0 WHERE ip_address = ? AND action_type = ?',
        (ip_address, action_type)
    )
    db.commit()

def log_login(user_id, ip_address, user_agent):
    db = get_db()
    db.execute(
        'INSERT INTO login_logs (user_id, ip, user_agent, created_at) VALUES (?, ?, ?, ?)',
        (user_id, ip_address, user_agent, datetime.now())
    )
    db.commit()

def increment_failed_attempts(ip_address, action_type):
    db = get_db()
    attempts = get_attempts(ip_address, action_type)
    if attempts:
        db.execute(
            'UPDATE attempt_logs SET failed_attempts = failed_attempts + 1, last_failed_attempt = ? '
            'WHERE ip_address = ? AND action_type = ?',
            (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ip_address, action_type)
        )
    else:
        db.execute(
            'INSERT INTO attempt_logs (ip_address, action_type, failed_attempts, last_failed_attempt) '
            'VALUES (?, ?, ?, ?)',
            (ip_address, action_type, 1, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
    db.commit()

def get_login_logs(username):
    db = get_db()
    logs = db.execute('''
        SELECT login_logs.user_agent, login_logs.ip, login_logs.created_at 
        FROM login_logs 
        INNER JOIN users ON login_logs.user_id = users.id 
        WHERE users.username = ? 
        ORDER BY login_logs.created_at DESC 
        LIMIT 10
    ''', (username,)).fetchall()
    db.commit()
    return logs
def get_user_notes(user_id):
    db = get_db()
    return db.execute('SELECT notes.id, notes.note, notes.signature, users.public_key FROM notes JOIN users ON users.id = notes.user_id WHERE user_id = ?', (user_id,)).fetchall()
def update_note_signature(signature, note_id):
    db = get_db()
    db.execute('UPDATE notes SET signature = ? WHERE id = ?', (signature, note_id))
    db.commit()
def update_user(hashed_password, private_key, public_key, username):
    db = get_db()
    db.execute(
                'UPDATE users SET password = ?, private_key = ?, public_key = ? WHERE username = ?',
                (hashed_password, private_key, public_key, username)
            )
    db.commit()

def get_user_private_key(username):
    db = get_db()

    return db.execute(
        'SELECT id, private_key FROM users WHERE username = ?', (username,)
    ).fetchone()

def insert_note(user_id, note_title, sanitized_html, signature):
    db = get_db()
    db.execute(
        'INSERT INTO notes (user_id, title, note, signature) VALUES (?, ?, ?, ?)', 
        (user_id, note_title, sanitized_html, signature)
    )
    db.commit()

def get_all_notes():
    db = get_db()
    return db.execute('SELECT notes.id, notes.note, notes.signature, users.username, notes.created_at, notes.title FROM notes JOIN users ON notes.user_id = users.id').fetchall()

def get_user_detailed_notes(note_user):
    db = get_db()
    return db.execute('SELECT notes.id, notes.note, notes.signature, users.username, notes.created_at, notes.title FROM notes JOIN users ON notes.user_id = users.id WHERE users.username = ?', (note_user,)).fetchall()

def get_note_with_pub_key(note_id):
    db = get_db()
    return db.execute('SELECT notes.id, notes.note, notes.signature, users.public_key FROM notes JOIN users ON notes.user_id = users.id WHERE notes.id = ?', 
                        (note_id,)).fetchone()
def get_note(note_id):
    db = get_db()
    return db.execute('SELECT notes.id, notes.note, notes.signature, users.username, notes.created_at, notes.title FROM notes JOIN users ON notes.user_id = users.id WHERE notes.id = ?', 
                      (note_id,)).fetchone()        

