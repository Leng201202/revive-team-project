"""Secure NoteVault Flask application.

The original course target is intentionally vulnerable. This version keeps the
same small feature set while applying the remediations documented in REPORT.md.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import hmac
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import uuid

import jwt
from flask import (
    Flask,
    Response,
    abort,
    current_app,
    g,
    jsonify,
    make_response,
    redirect,
    render_template_string,
    request,
)
from werkzeug.security import check_password_hash, generate_password_hash


JWT_ALGORITHM = "HS256"
JWT_AUDIENCE = "notevault-web"
JWT_ISSUER = "notevault"
SESSION_TTL = timedelta(minutes=15)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


PAGE = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>NoteVault</title></head>
<body>
<h1>NoteVault</h1>
{% if user %}
  <p>Signed in as <b>{{ user }}</b></p>
  <form method="post" action="/logout">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <button>Logout</button>
  </form>
  {% if is_admin %}<p><a href="/admin">Admin</a></p>{% endif %}
  <form method="post" action="/notes">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input name="title" maxlength="100" placeholder="title" required>
    <input name="body" maxlength="5000" placeholder="note" required>
    <button>Add note</button>
  </form>
  <h3>Your notes</h3>
  <ul>
  {% for note in notes %}
    <li>#{{ note.id }} <b>{{ note.title }}</b>: {{ note.body }}</li>
  {% endfor %}
  </ul>
  <form action="/search">
    <input name="q" maxlength="200" placeholder="search notes">
    <button>Search</button>
  </form>
{% else %}
  <form method="post" action="/login">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    user <input name="username" maxlength="32" autocomplete="username" required>
    pass <input name="password" type="password" maxlength="128" autocomplete="current-password" required>
    <button>Login</button>
  </form>
  <form method="post" action="/register">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    new: <input name="username" maxlength="32" autocomplete="username" required>
    <input name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required>
    <button>Register</button>
  </form>
{% endif %}
</body>
</html>
"""


SEARCH_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Search</title></head>
<body><a href="/">back</a><ul>
{% for note in notes %}<li>{{ note.title }}: {{ note.body }}</li>{% endfor %}
</ul></body></html>
"""


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class LoginLimiter:
    """Small in-process login limiter suitable for this single-process app."""

    def __init__(self, attempts: int = 5, window_seconds: int = 60) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self.failures: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        entries = self.failures[key]
        cutoff = now - self.window_seconds
        while entries and entries[0] <= cutoff:
            entries.popleft()
        return entries

    def limited(self, key: str, now: float) -> bool:
        with self.lock:
            return len(self._prune(key, now)) >= self.attempts

    def record_failure(self, key: str, now: float) -> None:
        with self.lock:
            self._prune(key, now).append(now)

    def clear(self, key: str) -> None:
        with self.lock:
            self.failures.pop(key, None)


def team_marker(team_id: str, team_salt: str) -> str:
    return hmac.new(team_salt.encode(), team_id.encode(), hashlib.sha256).hexdigest()[:12]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def initialize_database(app: Flask) -> None:
    database = Path(app.config["DATABASE"])
    database.parent.mkdir(parents=True, exist_ok=True)
    with app.app_context():
        connection = get_db()
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'))
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                owner TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                FOREIGN KEY (owner) REFERENCES users(username) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );
            """
        )
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            connection.executemany(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                [
                    ("alice", generate_password_hash("alicepw"), "user"),
                    ("admin", generate_password_hash("admin123"), "admin"),
                ],
            )
            marker = team_marker(app.config["TEAM_ID"], app.config["TEAM_SALT"])
            connection.executemany(
                "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)",
                [
                    ("alice", "groceries", "milk, eggs"),
                    ("admin", "infra", "production operations note"),
                    ("admin", "build-tag", f"team={app.config['TEAM_ID']} marker={marker}"),
                ],
            )
        connection.execute(
            "DELETE FROM revoked_tokens WHERE expires_at < ?",
            (int(datetime.now(timezone.utc).timestamp()),),
        )
        connection.commit()


def csrf_token() -> str:
    token = request.cookies.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        g.new_csrf_token = token
    return token


def csrf_protected(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        expected = request.cookies.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        origin = request.headers.get("Origin")
        trusted_origin = request.host_url.rstrip("/")
        if origin and origin.rstrip("/") != trusted_origin:
            security_event("csrf_rejected", level=logging.WARNING)
            abort(403)
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            security_event("csrf_rejected", level=logging.WARNING)
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def decode_session_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(
            token,
            current_app.config["JWT_SECRET"],
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["sub", "iat", "exp", "jti", "aud", "iss"]},
        )
    except jwt.PyJWTError:
        return None
    revoked = get_db().execute(
        "SELECT 1 FROM revoked_tokens WHERE jti = ?", (payload["jti"],)
    ).fetchone()
    return None if revoked else payload


def current_user() -> str | None:
    if "current_user" in g:
        return g.current_user
    token = request.cookies.get("session", "")
    payload = decode_session_token(token) if token else None
    username = payload.get("sub") if payload else None
    if username:
        exists = get_db().execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not exists:
            username = None
    g.current_user = username
    g.session_payload = payload
    return username


def require_user(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return "auth required", 401
        return view(*args, **kwargs)

    return wrapped


def role_of(username: str) -> str | None:
    row = get_db().execute(
        "SELECT role FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row["role"] if row else None


def security_event(event: str, username: str | None = None, level: int = logging.INFO) -> None:
    actor = username or getattr(g, "current_user", None) or "anonymous"
    current_app.logger.log(
        level,
        "security_event=%s actor=%r remote_addr=%r",
        event,
        actor,
        request.remote_addr or "unknown",
    )


def issue_session(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + SESSION_TTL,
        "jti": str(uuid.uuid4()),
        "aud": JWT_AUDIENCE,
        "iss": JWT_ISSUER,
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm=JWT_ALGORITHM)


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=os.environ.get("NOTEVAULT_DB", "/data/notevault.db"),
        JWT_SECRET=os.environ.get("APP_SECRET", ""),
        TEAM_ID=os.environ.get("TEAM_ID", "REVIVE"),
        TEAM_SALT=os.environ.get("TEAM_SALT", "notevault-anti-copy-dev-salt"),
        COOKIE_SECURE=env_bool("COOKIE_SECURE", True),
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)
    if len(app.config["JWT_SECRET"]) < 32:
        raise RuntimeError("APP_SECRET must be set to a random value of at least 32 characters")

    app.extensions["login_limiter"] = LoginLimiter()
    app.config["DUMMY_PASSWORD_HASH"] = generate_password_hash("not-the-password")
    app.teardown_appcontext(close_db)
    initialize_database(app)

    @app.after_request
    def secure_response(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cache-Control"] = "no-store"
        if hasattr(g, "new_csrf_token"):
            response.set_cookie(
                "csrf_token",
                g.new_csrf_token,
                max_age=3600,
                httponly=True,
                secure=app.config["COOKIE_SECURE"],
                samesite="Strict",
            )
        return response

    @app.errorhandler(500)
    def internal_error(_error):
        app.logger.exception("security_event=unhandled_error")
        return "internal server error", 500

    @app.get("/")
    def home():
        user = current_user()
        notes = []
        if user:
            notes = get_db().execute(
                "SELECT id, title, body FROM notes WHERE owner = ? ORDER BY id", (user,)
            ).fetchall()
        return render_template_string(
            PAGE,
            user=user,
            is_admin=(user is not None and role_of(user) == "admin"),
            notes=notes,
            csrf_token=csrf_token(),
        )

    @app.post("/register")
    @csrf_protected
    def register():
        data = request.get_json(silent=True) or request.form
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if not USERNAME_RE.fullmatch(username) or not 12 <= len(password) <= 128:
            return "username or password does not meet policy", 400
        try:
            connection = get_db()
            connection.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                (username, generate_password_hash(password)),
            )
            connection.commit()
        except sqlite3.IntegrityError:
            security_event("registration_duplicate", username, logging.WARNING)
            return "username unavailable", 409
        security_event("registration_success", username)
        return redirect("/")

    @app.post("/login")
    @csrf_protected
    def login():
        data = request.get_json(silent=True) or request.form
        username = str(data.get("username", ""))[:128]
        password = str(data.get("password", ""))[:128]
        key = request.remote_addr or "unknown"
        limiter: LoginLimiter = app.extensions["login_limiter"]
        now = datetime.now(timezone.utc).timestamp()
        if limiter.limited(key, now):
            security_event("login_rate_limited", username, logging.WARNING)
            response = make_response("too many login attempts", 429)
            response.headers["Retry-After"] = str(limiter.window_seconds)
            return response
        row = get_db().execute(
            "SELECT username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        candidate_hash = row["password_hash"] if row else app.config["DUMMY_PASSWORD_HASH"]
        valid = check_password_hash(candidate_hash, password)
        if not row or not valid:
            limiter.record_failure(key, now)
            security_event("login_failed", username, logging.WARNING)
            return "login failed", 401
        limiter.clear(key)
        canonical_username = row["username"]
        token = issue_session(canonical_username)
        response = make_response(redirect("/"))
        response.set_cookie(
            "session",
            token,
            max_age=int(SESSION_TTL.total_seconds()),
            httponly=True,
            secure=app.config["COOKIE_SECURE"],
            samesite="Strict",
        )
        security_event("login_success", canonical_username)
        return response

    @app.post("/logout")
    @csrf_protected
    @require_user
    def logout():
        payload = g.session_payload
        connection = get_db()
        connection.execute(
            "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
            (payload["jti"], int(payload["exp"])),
        )
        connection.commit()
        security_event("logout", current_user())
        response = make_response(redirect("/"))
        response.delete_cookie(
            "session",
            httponly=True,
            secure=app.config["COOKIE_SECURE"],
            samesite="Strict",
        )
        return response

    @app.post("/notes")
    @csrf_protected
    @require_user
    def add_note():
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title or not body or len(title) > 100 or len(body) > 5000:
            return "invalid note", 400
        user = current_user()
        connection = get_db()
        connection.execute(
            "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)",
            (user, title, body),
        )
        connection.commit()
        security_event("note_created", user)
        return redirect("/")

    @app.get("/api/notes/<int:note_id>")
    @require_user
    def api_note(note_id: int):
        row = get_db().execute(
            "SELECT id, owner, title, body FROM notes WHERE id = ? AND owner = ?",
            (note_id, current_user()),
        ).fetchone()
        return jsonify(dict(row)) if row else (jsonify(error="not found"), 404)

    @app.get("/search")
    @require_user
    def search():
        term = request.args.get("q", "")[:200]
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = get_db().execute(
            """SELECT id, title, body FROM notes
               WHERE owner = ? AND body LIKE ? ESCAPE '\\' ORDER BY id""",
            (current_user(), f"%{escaped}%"),
        ).fetchall()
        return render_template_string(SEARCH_PAGE, notes=rows)

    @app.get("/admin")
    @require_user
    def admin():
        user = current_user()
        if role_of(user) != "admin":
            security_event("admin_denied", user, logging.WARNING)
            return "forbidden", 403
        rows = get_db().execute(
            "SELECT id, username, role FROM users ORDER BY id"
        ).fetchall()
        security_event("admin_view", user)
        return jsonify([dict(row) for row in rows])

    @app.get("/export")
    @require_user
    def export_notes():
        output_format = request.args.get("fmt", "txt")
        if output_format not in {"txt", "json"}:
            security_event("export_rejected", current_user(), logging.WARNING)
            return "unsupported export format", 400
        rows = get_db().execute(
            "SELECT id, title, body FROM notes WHERE owner = ? ORDER BY id",
            (current_user(),),
        ).fetchall()
        security_event("export_success", current_user())
        if output_format == "json":
            response = jsonify([dict(row) for row in rows])
        else:
            content = "\n".join(f"#{row['id']} {row['title']}: {row['body']}" for row in rows)
            response = make_response(content + ("\n" if content else ""))
            response.mimetype = "text/plain"
        response.headers["Content-Disposition"] = f'attachment; filename="notes.{output_format}"'
        return response

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=8080, debug=False)
