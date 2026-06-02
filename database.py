import sqlite3
import hashlib
from datetime import datetime


DATABASE = 'papertrail.db'


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    conn = get_connection()
    c = conn.cursor()

    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            department TEXT,
            bio TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            owner_id INTEGER NOT NULL,
            visibility TEXT NOT NULL DEFAULT 'private',
            status TEXT NOT NULL DEFAULT 'draft',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (document_id) REFERENCES documents(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (document_id) REFERENCES documents(id)
        );

        CREATE TABLE IF NOT EXISTS document_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            UNIQUE(document_id, user_id)
        );
    """)

    now = datetime.utcnow().isoformat()

    existing_admin = c.execute("SELECT id FROM users WHERE email='admin@papertrail.io'").fetchone()
    if not existing_admin:
        c.execute(
            "INSERT INTO users (name, email, password_hash, role, department, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ('Admin', 'admin@papertrail.io', hash_password('admin123'), 'admin', 'Engineering', now)
        )
        c.execute(
            "INSERT INTO users (name, email, password_hash, role, department, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ('Alice Chen', 'alice@papertrail.io', hash_password('alice2024'), 'member', 'Legal', now)
        )
        c.execute(
            "INSERT INTO users (name, email, password_hash, role, department, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ('Bob Martinez', 'bob@papertrail.io', hash_password('bobsecure!'), 'member', 'Finance', now)
        )

        admin_id = c.execute("SELECT id FROM users WHERE email='admin@papertrail.io'").fetchone()['id']
        alice_id = c.execute("SELECT id FROM users WHERE email='alice@papertrail.io'").fetchone()['id']

        c.execute(
            "INSERT INTO documents (title, content, owner_id, visibility, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ('Q3 Budget Proposal', 'This document outlines the proposed budget allocation for Q3 2024. '
             'Total requested: $2.4M across Engineering, Marketing, and Operations.', alice_id, 'public', 'in_review', now, now)
        )
        c.execute(
            "INSERT INTO documents (title, content, owner_id, visibility, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ('Vendor Contract - Acme Corp', 'CONFIDENTIAL: Service agreement with Acme Corp. '
             'Annual value: $480,000. Auto-renewal clause in section 7.3.', alice_id, 'private', 'draft', now, now)
        )
        c.execute(
            "INSERT INTO documents (title, content, owner_id, visibility, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ('Employee Handbook v4.2', 'Updated policies for remote work, PTO accrual, and performance reviews. '
             'Effective January 1, 2025.', admin_id, 'public', 'approved', now, now)
        )

    conn.commit()
    conn.close()
    print("[papertrail] Database initialized.")


if __name__ == '__main__':
    init_db()
