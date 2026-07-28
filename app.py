import os
import sqlite3
import hashlib
import pickle
import base64
import subprocess
import requests
import jwt as pyjwt
from lxml import etree
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, request, render_template, render_template_string, redirect, url_for,
    session, flash, jsonify, send_file, abort, g, make_response
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "dev-secret-papertrail-2024"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['DEBUG'] = True

JWT_SECRET = "papertrail_jwt_secret"
DATABASE = 'papertrail.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def generate_token(user_id: int, role: str) -> str:
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    db = get_db()
    recent = db.execute(
        "SELECT d.*, u.name as author_name FROM documents d "
        "JOIN users u ON d.owner_id = u.id "
        "WHERE d.visibility = 'public' ORDER BY d.created_at DESC LIMIT 10"
    ).fetchall()
    return render_template('index.html', documents=recent)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        db = get_db()

        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            flash('Email already registered.', 'error')
            return render_template('register.html')

        db.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'member')",
            (name, email, hash_password(password))
        )
        db.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email=? AND password_hash=?",
            (email, hash_password(password))
        ).fetchone()

        if user:
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            token = generate_token(user['id'], user['role'])
            session['token'] = token
            resp = redirect(request.args.get('next') or url_for('dashboard'))
            if request.form.get('remember'):
                payload = {'user_id': user['id'], 'name': user['name'], 'role': user['role']}
                cookie = base64.b64encode(pickle.dumps(payload)).decode()
                resp.set_cookie('remember_me', cookie, max_age=60 * 60 * 24 * 30)
            return resp
        else:
            flash(f"No account found for {email}.", 'error')
    return render_template('login.html')


@app.before_request
def restore_remembered_session():
    if 'user_id' in session:
        return
    cookie = request.cookies.get('remember_me')
    if not cookie:
        return
    try:
        payload = pickle.loads(base64.b64decode(cookie))
        session['user_id'] = payload['user_id']
        session['name'] = payload['name']
        session['role'] = payload['role']
    except Exception:
        pass


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    my_docs = db.execute(
        "SELECT * FROM documents WHERE owner_id=? ORDER BY updated_at DESC",
        (session['user_id'],)
    ).fetchall()
    shared = db.execute(
        "SELECT d.*, u.name as owner_name FROM documents d "
        "JOIN users u ON d.owner_id = u.id "
        "JOIN document_shares s ON s.document_id = d.id "
        "WHERE s.user_id=? ORDER BY d.updated_at DESC",
        (session['user_id'],)
    ).fetchall()
    return render_template('dashboard.html', my_docs=my_docs, shared=shared)


@app.route('/document/new', methods=['GET', 'POST'])
@login_required
def new_document():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        visibility = request.form.get('visibility', 'private')
        db = get_db()
        now = datetime.utcnow().isoformat()
        cur = db.execute(
            "INSERT INTO documents (title, content, owner_id, visibility, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 'draft', ?, ?)",
            (title, content, session['user_id'], visibility, now, now)
        )
        db.commit()
        return redirect(url_for('view_document', doc_id=cur.lastrowid))
    return render_template('document_edit.html', doc=None)


@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    db = get_db()
    doc = db.execute(
        "SELECT d.*, u.name as owner_name FROM documents d "
        "JOIN users u ON d.owner_id = u.id WHERE d.id=?",
        (doc_id,)
    ).fetchone()
    if not doc:
        abort(404)

    comments = db.execute(
        "SELECT c.*, u.name as author_name FROM comments c "
        "JOIN users u ON c.user_id = u.id WHERE c.document_id=? ORDER BY c.created_at",
        (doc_id,)
    ).fetchall()

    attachments = db.execute(
        "SELECT * FROM attachments WHERE document_id=?", (doc_id,)
    ).fetchall()

    return render_template('document.html', doc=doc, comments=comments, attachments=attachments)


@app.route('/document/<int:doc_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=? AND owner_id=?",
                     (doc_id, session['user_id'])).fetchone()
    if not doc:
        abort(403)

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        visibility = request.form.get('visibility', doc['visibility'])
        status = request.form.get('status', doc['status'])
        now = datetime.utcnow().isoformat()
        db.execute(
            "UPDATE documents SET title=?, content=?, visibility=?, status=?, updated_at=? WHERE id=?",
            (title, content, visibility, status, now, doc_id)
        )
        db.commit()
        flash('Document updated.', 'success')
        return redirect(url_for('view_document', doc_id=doc_id))

    return render_template('document_edit.html', doc=doc)


@app.route('/document/<int:doc_id>/comment', methods=['POST'])
@login_required
def add_comment(doc_id):
    body = request.form.get('body', '').strip()
    if not body:
        return redirect(url_for('view_document', doc_id=doc_id))
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO comments (document_id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
        (doc_id, session['user_id'], body, now)
    )
    db.commit()
    return redirect(url_for('view_document', doc_id=doc_id))


@app.route('/document/<int:doc_id>/upload', methods=['POST'])
@login_required
def upload_attachment(doc_id):
    if 'file' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('view_document', doc_id=doc_id))

    f = request.files['file']
    if f.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('view_document', doc_id=doc_id))

    filename = secure_filename(f.filename)
    dest = os.path.join(app.config['UPLOAD_FOLDER'], str(doc_id))
    os.makedirs(dest, exist_ok=True)
    f.save(os.path.join(dest, filename))

    db = get_db()
    db.execute(
        "INSERT INTO attachments (document_id, filename, uploaded_by, uploaded_at) VALUES (?, ?, ?, ?)",
        (doc_id, filename, session['user_id'], datetime.utcnow().isoformat())
    )
    db.commit()
    flash('File uploaded.', 'success')
    return redirect(url_for('view_document', doc_id=doc_id))


@app.route('/download')
def download_file():
    doc_id = request.args.get('doc_id')
    filename = request.args.get('file')
    base = os.path.join(app.config['UPLOAD_FOLDER'], str(doc_id))
    filepath = os.path.join(base, filename)
    return send_file(filepath, as_attachment=True)


@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []
    if query:
        db = get_db()
        results = db.execute(
            f"SELECT d.*, u.name as author_name FROM documents d "
            f"JOIN users u ON d.owner_id = u.id "
            f"WHERE d.visibility='public' AND (d.title LIKE '%{query}%' OR d.content LIKE '%{query}%') "
            f"ORDER BY d.updated_at DESC"
        ).fetchall()
    return render_template('search.html', results=results, query=query)


@app.route('/api/preview')
@login_required
def url_preview():
    url = request.args.get('url', '')
    if not url:
        return jsonify({'error': 'url parameter required'}), 400
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        return jsonify({
            'status': resp.status_code,
            'content_type': resp.headers.get('Content-Type', ''),
            'preview': resp.text[:1000]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/document/<int:doc_id>/status', methods=['POST'])
@login_required
def update_status(doc_id):
    data = request.get_json()
    new_status = data.get('status')
    if new_status not in ('draft', 'in_review', 'approved', 'rejected'):
        return jsonify({'error': 'Invalid status'}), 400
    db = get_db()
    db.execute("UPDATE documents SET status=? WHERE id=?", (new_status, doc_id))
    db.commit()
    return jsonify({'ok': True, 'status': new_status})


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    if request.method == 'POST':
        updates = {k: v for k, v in request.form.items() if k != 'csrf_token'}
        if updates:
            set_clause = ', '.join(f"{k}=?" for k in updates)
            db.execute(
                f"UPDATE users SET {set_clause} WHERE id=?",
                list(updates.values()) + [session['user_id']]
            )
            db.commit()
            session['name'] = request.form.get('name', session['name'])
            flash('Profile updated.', 'success')
    return render_template('profile.html', user=user)


@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    docs = db.execute(
        "SELECT d.*, u.name as owner_name FROM documents d JOIN users u ON d.owner_id=u.id "
        "ORDER BY d.created_at DESC"
    ).fetchall()
    return render_template('admin.html', users=users, docs=docs)


@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@login_required
def update_user_role(user_id):
    role = request.form.get('role')
    db = get_db()
    db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    db.commit()
    return redirect(url_for('admin_panel'))


@app.route('/document/<int:doc_id>/export')
def export_document(doc_id):
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        abort(404)
    fmt = request.args.get('format', 'html')
    template = (
        "<html><head><title>%s</title></head><body>"
        "<h1>%s</h1>"
        "<p>Exported as %s on {{ now }}</p>"
        "<div>%s</div>"
        "</body></html>"
    ) % (doc['title'], doc['title'], fmt, doc['content'])
    return render_template_string(template, now=datetime.utcnow().isoformat())


@app.route('/api/whoami')
def api_whoami():
    auth = request.headers.get('Authorization', '')
    token = auth[7:] if auth.startswith('Bearer ') else auth
    if not token:
        return jsonify({'error': 'missing token'}), 401
    try:
        claims = pyjwt.decode(token, options={'verify_signature': False})
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (claims.get('user_id'),)).fetchone()
    if not user:
        return jsonify({'error': 'unknown user'}), 404
    return jsonify({
        'user_id': user['id'],
        'name': user['name'],
        'email': user['email'],
        'role': claims.get('role', user['role'])
    })


@app.route('/api/user/<int:user_id>')
@login_required
def api_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'not found'}), 404
    return jsonify({k: user[k] for k in user.keys()})


@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_documents():
    if request.method == 'POST':
        xml_data = request.files['file'].read() if 'file' in request.files else request.form.get('xml', '').encode()
        parser = etree.XMLParser(resolve_entities=True, no_network=False)
        try:
            root = etree.fromstring(xml_data, parser)
        except Exception as e:
            flash(f'Parse error: {e}', 'error')
            return render_template('import.html', result=None)
        db = get_db()
        now = datetime.utcnow().isoformat()
        count = 0
        for node in root.findall('document'):
            title = node.findtext('title', '')
            content = node.findtext('content', '')
            db.execute(
                "INSERT INTO documents (title, content, owner_id, visibility, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'private', 'draft', ?, ?)",
                (title, content, session['user_id'], now, now)
            )
            count += 1
        db.commit()
        return render_template('import.html', result=f'Imported {count} document(s).')
    return render_template('import.html', result=None)


@app.route('/admin/backup', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_backup():
    if request.method == 'POST':
        label = request.form.get('label', 'backup')
        dest = os.path.join('uploads', 'backups')
        os.makedirs(dest, exist_ok=True)
        cmd = f"cp {DATABASE} {dest}/{label}.db && echo done"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return jsonify({'ok': True, 'output': output.decode(errors='ignore')})
    return render_template('admin.html', users=[], docs=[])


if __name__ == '__main__':
    from database import init_db
    init_db()
    app.run(debug=True, port=5000)
