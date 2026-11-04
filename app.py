"""
NoteVault — a small team note-sharing web app + JSON API (term-project starter).

This is your TERM-PROJECT TARGET. It is a normal-looking app that contains several
realistic security weaknesses. Your job (see project/README.md): threat-model it,
find and document the vulnerabilities, fix them, and harden the build/release.

We do NOT list the vulnerabilities here — finding them is the assignment.

Run:  docker compose up   (then http://localhost:8080)
"""
import hashlib
import hmac
import os
import sqlite3
import subprocess

import jwt  # PyJWT
from flask import Flask, request, jsonify, render_template_string, redirect, make_response

app = Flask(__name__)
DB = "/tmp/notevault.db"
SECRET = "notevault-dev-secret"  # used to sign session tokens

# Anti-copying: every team's build is seeded with a marker derived from their own TEAM_ID, so
# any evidence a team submits (SQLi dump, IDOR response, admin-panel screenshot) that shows the
# admin's notes carries a value traceable to exactly one team — see instructor/anti-cheating.md.
TEAM_ID = os.environ.get("TEAM_ID", "unassigned")
TEAM_SALT = os.environ.get("TEAM_SALT", "notevault-anti-copy-dev-salt")


def team_marker():
    return hmac.new(TEAM_SALT.encode(), TEAM_ID.encode(), hashlib.sha256).hexdigest()[:12]


PAGE = """
<!doctype html><title>NoteVault</title>
<h1>NoteVault</h1>
{% if user %}<p>Signed in as <b>{{ user }}</b> · <a href="/logout">logout</a>
  {% if is_admin %}· <a href="/admin">admin</a>{% endif %}</p>
<form method=post action="/notes"><input name=title placeholder=title>
  <input name=body placeholder=note><button>Add note</button></form>
<h3>Your notes</h3>{{ notes_html|safe }}
<form action="/search"><input name=q placeholder="search notes"><button>Search</button></form>
{% else %}
<form method=post action="/login">user <input name=username> pass <input name=password type=password>
  <button>Login</button></form>
<form method=post action="/register">new: <input name=username> <input name=password type=password>
  <button>Register</button></form>
{% endif %}
"""


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def seed():
    con = db()
    con.executescript(
        "DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS notes;"
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);"
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT);"
    )
    con.executemany("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                    [("alice", hashlib.md5(b"alicepw").hexdigest(), "user"),
                     ("admin", hashlib.md5(b"admin123").hexdigest(), "admin")])
    con.executemany("INSERT INTO notes (owner, title, body) VALUES (?,?,?)",
                    [("alice", "groceries", "milk, eggs"),
                     ("admin", "infra", "prod db password is hunter2"),
                     ("admin", "build-tag", "team=%s marker=%s" % (TEAM_ID, team_marker()))])
    con.commit()
    con.close()


def current_user():
    tok = request.cookies.get("session", "")
    if not tok:
        return None
    try:
        data = jwt.decode(tok, SECRET, algorithms=["HS256", "none"])
        return data.get("sub")
    except Exception:
        return None


def role_of(username):
    con = db()
    r = con.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    return r["role"] if r else None


@app.route("/")
def home():
    user = current_user()
    notes_html = ""
    if user:
        con = db()
        rows = con.execute("SELECT id,title,body FROM notes WHERE owner = ?", (user,)).fetchall()
        con.close()
        notes_html = "".join(
            "<li>#%d <b>%s</b>: %s</li>" % (r["id"], r["title"], r["body"]) for r in rows)
    return render_template_string(PAGE, user=user, is_admin=(user and role_of(user) == "admin"),
                                  notes_html=notes_html)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username") or (request.json or {}).get("username")
    password = request.form.get("password") or (request.json or {}).get("password")
    role = request.form.get("role") or (request.json or {}).get("role") or "user"
    con = db()
    con.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                (username, hashlib.md5(password.encode()).hexdigest(), role))
    con.commit()
    con.close()
    return redirect("/")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username") or (request.json or {}).get("username")
    password = request.form.get("password") or (request.json or {}).get("password")
    con = db()
    q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username, hashlib.md5((password or "").encode()).hexdigest())
    row = con.execute(q).fetchone()
    con.close()
    if not row:
        return "login failed", 401
    tok = jwt.encode({"sub": username}, SECRET, algorithm="HS256")
    resp = make_response(redirect("/"))
    resp.set_cookie("session", tok)
    return resp


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session")
    return resp


@app.route("/notes", methods=["POST"])
def add_note():
    user = current_user()
    if not user:
        return "auth required", 401
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    con = db()
    con.execute("INSERT INTO notes (owner,title,body) VALUES (?,?,?)", (user, title, body))
    con.commit()
    con.close()
    return redirect("/")


@app.route("/api/notes/<int:nid>")
def api_note(nid):
    if not current_user():
        return jsonify(error="auth required"), 401
    con = db()
    r = con.execute("SELECT id,owner,title,body FROM notes WHERE id = ?", (nid,)).fetchone()
    con.close()
    return (jsonify(dict(r)) if r else (jsonify(error="not found"), 404))


@app.route("/search")
def search():
    user = current_user()
    if not user:
        return "auth required", 401
    term = request.args.get("q", "")
    con = db()
    q = "SELECT id,title,body FROM notes WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, term)
    rows = con.execute(q).fetchall()
    con.close()
    return render_template_string("<a href=/>back</a><ul>" +
        "".join("<li>%s: %s</li>" % (r["title"], r["body"]) for r in rows) + "</ul>")


@app.route("/admin")
def admin():
    user = current_user()
    if not user or role_of(user) != "admin":
        return "forbidden", 403
    con = db()
    rows = con.execute("SELECT id,username,password,role FROM users").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


@app.route("/export")
def export():
    if not current_user():
        return "auth required", 401
    fmt = request.args.get("fmt", "txt")
    # convenience "export" feature
    out = subprocess.run("echo exporting notes as " + fmt, shell=True,
                         capture_output=True, text=True)
    return "<pre>%s</pre>" % out.stdout


if __name__ == "__main__":
    seed()
    app.run(host="0.0.0.0", port=8080, debug=True)
