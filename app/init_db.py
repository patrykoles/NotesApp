import sqlite3
def initialize_db():
    connection = sqlite3.connect('/app/data/database.db')
    connection.row_factory = sqlite3.Row

    connection.execute('''
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL, 
        public_key TEXT NOT NULL, 
        private_key TEXT NOT NULL, 
        totp_secret TEXT NOT NULL
    );
    ''')

    connection.execute('''
        CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL, 
        note TEXT NOT NULL, 
        signature TEXT NOT NULL, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
        FOREIGN KEY (user_id) REFERENCES users (id) 
    );
    ''')

    connection.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        user_agent TEXT NOT NULL, 
        ip TEXT NOT NULL, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
        FOREIGN KEY (user_id) REFERENCES users (id) 
    );
    ''')

    connection.execute('''
        CREATE TABLE IF NOT EXISTS attempt_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        action_type TEXT NOT NULL, 
        failed_attempts INTEGER DEFAULT 0, 
        last_failed_attempt TIMESTAMP
    );
    ''')

    connection.commit()
    connection.close()