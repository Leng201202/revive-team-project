# Term Project Report — Secure Build

> Fill in every section. Keep the headings. Total **100 pts** (see rubric at the end).
> This is **team work** (2–3). Do not share your report with other teams.

## Cover

| Field | Value |
|---|---|
| Team name | REVIVE |
| Members (name + ID) | Panaikron Marohabut (6631503126), Sai Shang Hlang (6631503129), Zaw Phyo Aung (6631503130) |
| Target application | NoteVault (Python/Flask) |
| Repository URL | https://github.com/Leng201202/revive-team-project |
| Demo video URL | **Add the unlisted YouTube/Drive URL after recording with `script.md`.** |
| Date | 3 November 2026 |

## AI-tool usage disclosure
*Academic integrity: state how you used any AI tools (ChatGPT, Copilot, etc.) — e.g. searching, coding, translating, drafting. "None" is a valid answer.*

| Tool | How it was used |
|---|---|
| OpenAI Codex | Repository audit, code-remediation assistance, regression-test drafting, CI/SBOM workflow drafting, and report editing. The team remains responsible for reviewing the code, running the demo, and verifying every submitted claim. |

---

## 1. Executive Summary

NoteVault is a Python/Flask note-taking application with JWT cookie sessions,
SQLite storage, an admin API, search, and note export. Testing of the supplied
baseline identified **19 findings: 3 Critical, 10 High, 5 Medium, and 1 Low**.
The most serious paths allowed unauthenticated SQL-injection login bypass,
database extraction, admin-token forgery, and authenticated OS command
execution as root. Several weaker controls—MD5 password storage, missing
cookie flags, stored XSS, and excessive admin data—made those primary attacks
substantially more damaging.

The remediation branch removes shell execution, parameterizes every query,
enforces ownership and server-selected roles, escapes untrusted output, uses
Werkzeug's salted slow password KDF, and issues short-lived revocable JWTs from
a runtime-only secret. It adds CSRF protection, login throttling, security
headers, audit events, non-destructive persistent database initialization, and
21 regression tests. The build now uses hash-locked current dependencies, a
digest-pinned base image, a non-root/read-only container, a CycloneDX SBOM, and
CI gates for SAST, SCA, secret scanning, and HIGH/CRITICAL container findings.
Residual deployment risks are TLS termination, the single-process in-memory
rate limiter, and completion of the external GitHub tag/sign/video steps.

---

## 2. System Scope & Function

NoteVault is a small team note-sharing web app + JSON API (single Flask process,
SQLite storage, one Docker container, plain HTTP on port 8080). It provides
registration/login with a JWT session cookie, per-user note creation and
search, a JSON note endpoint, an admin panel listing all users, and an
"export" convenience endpoint backed by a shell command.

**In-scope components and endpoints:**

- `POST /register`, `POST /login`, `GET /logout` — auth & session issuing (P1)
- `GET /`, `POST /notes` — note list and creation (P2)
- `GET /search` — per-user note search (P3)
- `GET /admin` — admin panel, dumps the users table (P4)
- `GET /export` — shell-backed export stub (P5 → OS shell)
- `GET /api/notes/<id>` — JSON note fetch (P6)
- Data stores: SQLite `/tmp/notevault.db` (`users`, `notes`), `session` JWT
  cookie, process env / config (`APP_SECRET`, `TEAM_ID`, `TEAM_SALT`, source
  constant `SECRET`)
- Build/runtime: `Dockerfile`, `docker-compose.yml`, `requirements.txt`

**Data-Flow Diagram (DFD):** full version with element/flow tables in
[`threat-model/02-dataflow.md`](threat-model/02-dataflow.md). A plain-language narrative of
every identified problem — before any formal modelling — is in
[`threat-model/01-problems.md`](threat-model/01-problems.md) (each entry links back
to its DFD element and STRIDE row).

```mermaid
flowchart LR
    U(["E1 — User / Attacker<br/>(web browser)"])

    subgraph ZC["Zone A — Untrusted client"]
        CK[("D3 — session cookie<br/>JWT (HS256)<br/>no HttpOnly/Secure/SameSite")]
    end

    subgraph ZS["Zone B — Trusted: Docker container (root)"]
        subgraph APP["P0 — Flask app (app.py :8080, debug=True)"]
            P1["P1 Auth &amp; Sessions<br/>/register /login /logout"]
            P2["P2 Notes UI<br/>GET / POST /notes"]
            P3["P3 Search<br/>GET /search"]
            P4["P4 Admin<br/>GET /admin"]
            P5["P5 Export<br/>GET /export"]
            P6["P6 JSON API<br/>GET /api/notes/&lt;id&gt;"]
        end
        DB[("D1/D2 — SQLite<br/>users · notes")]
        ENV[("D4 — Env / config<br/>APP_SECRET · TEAM_ID · TEAM_SALT")]
        SH[["P7 — OS shell (root)"]]
    end

    U == "F1 credentials / forms<br/>(plaintext HTTP)" ==> P1
    P1 -- "F2 Set-Cookie: session=JWT" --> CK
    CK -- "F3 session cookie" --> P2 & P3 & P4 & P5 & P6
    P1 -- "F5 SQL users" --> DB
    P2 & P3 & P6 -- "F4 SQL notes" --> DB
    P4 -- "F6 SELECT users incl. hashes" --> DB
    P4 -. "F9 JSON dump" .-> U
    P5 == "F7 'echo … ' + fmt" ==> SH
    APP -. "F8 env vars" .-> ENV
```

**Trust boundaries:** TB1 = client ↔ server (F1, F3, F7-input, F9) · TB2 = app
↔ SQLite (F4–F6) · TB3 = app ↔ OS shell (F7) · TB4 = container ↔ host/image
(F8, runtime config).

---

## 3. Threat Model — STRIDE  *(20 pts)*

Full write-up in [`threat-model/03-stride.md`](threat-model/03-stride.md).

| Element / data flow | S | T | R | I | D | E | Top threat & mitigation |
|---|---|---|---|---|---|---|---|
| F1 login/register (credentials in transit) | ✓ | | | ✓ | | | Sniffed credentials over plaintext HTTP → TLS |
| No rate limiting / lockout | ✓ | | | | ✓ | | Brute force + resource exhaustion → rate limit, lockout, size caps |
| P1 auth logic (/login, /register) | ✓ | ✓ | | | | ✓ | SQLi bypass + client-set `role` + duplicate `admin` (no UNIQUE) → parameterised queries, fixed role, constraint |
| F2/F3 session JWT cookie | ✓ | ✓ | | ✓ | | ✓ | `alg=none` + hardcoded secret → forgery; no `exp` → no expiry/revocation; no flags → XSS theft. Pin HS256, env secret, `exp`/`aud`, flags |
| P2 notes create/render | | ✓ | | ✓ | | | Stored XSS via `notes_html\|safe` → output encoding, CSP |
| P6 GET /api/notes/<id> | | | | ✓ | | | IDOR/BOLA — no owner check → enforce `owner = current_user` |
| P3 GET /search | | ✓ | | ✓ | | | SQLi via `q` → parameterised LIKE |
| P4 GET /admin | | | | ✓ | | | Excessive data exposure — all MD5 hashes → never return hashes; strong KDF |
| F7 export → OS shell | | ✓ | | ✓ | ✓ | ✓ | Command injection via `fmt` → RCE + DoS. Drop `shell=True`, whitelist |
| D1/D2 SQLite store | | ✓ | | ✓ | ✓ | | Tamper/dump via SQLi; `seed()` wipes data each restart → least-privilege FS, persistent volume |
| Password storage (MD5, no salt) | | | | ✓ | | | Offline cracking → bcrypt/argon2 + salt |
| Container/host (Dockerfile, debug=True) | | | | ✓ | | ✓ | Root + baked secret + unpinned base + debugger → non-root, runtime secrets, pin, debug off |

*Global note: there is no logging anywhere, so Repudiation applies to every
flow in principle; we call it out where it matters most.*

**Top 5 risks (likelihood × impact):**

1. **RCE via `/export?fmt=`** — High × Critical. `shell=True` with unvalidated
   input runs commands as root in the container; exposes env secrets.
2. **SQL injection (login bypass + `/search` UNION dump)** — High × Critical.
   String-formatted queries allow auth bypass and dumping every user's
   credentials and every note.
3. **JWT session forgery via the hardcoded weak secret** — High × High. The
   committed key lets an attacker mint an admin HS256 token. Although `none`
   was incorrectly allow-listed, PyJWT 1.7.1 rejected the tested unsigned token.
4. **Privilege escalation via mass-assigned `role` on `/register`** — High ×
   High. Self-provisioned admin reaches the full user/hash dump.
5. **IDOR on `GET /api/notes/<id>`** — High × Medium–High. Sequential ids with
   no ownership check expose every user's private notes.

---

## 4. Vulnerability Findings  *(25 pts)*

All findings verified live against the Docker container
(`revive-team-project-notevault-1`, `TEAM_ID=REVIVE`) — see
`threat-model/01-problems.md` for plain-language explanations and
`evidence/` for artifacts.

**Numbering note.** Threat-model problems (`P-XX`, 20 total) are ordered by
category in `01-problems.md`; findings (`F-XX`, 19 total) are ordered by
severity/discovery. Every problem maps to exactly one finding; F-10 covers two
problems. Full mapping:

| Finding | Problem | Finding | Problem |
|---|---|---|---|
| F-01 RCE `/export` | P-08 | F-11 No rate limiting | P-11 |
| F-02 SQLi login | P-04 | F-12 No CSRF | P-15 |
| F-03 UNION search | P-06 | F-13 `debug=True` | P-16 |
| F-04 `role=admin` | P-01 | F-14 Vulnerable deps | P-18 |
| F-05 Duplicate admin | P-02 | F-15 Dockerfile | P-17 |
| F-06 JWT forgery | P-03 | F-16 No logging | P-19 |
| F-07 IDOR | P-05 | F-17 `seed()` wipes | P-20 |
| F-08 `/admin` hashes | P-07 | F-18 Unsalted MD5 | P-10 |
| F-09 Stored XSS | P-09 | F-19 Plain HTTP | P-14 |
| F-10 Cookie/JWT | P-12 + P-13 | | |

### Finding F-01 — OS command injection via `/export?fmt=` (RCE as root)
| Field | Value |
|---|---|
| CWE | CWE-78 |
| OWASP 2025 | A05 |
| Severity | Critical |
| Location | `app.py:202-203`, `GET /export` |
| Reproduction | `GET /export?fmt=txt;id` → `uid=0(root)`; `fmt=txt;cat /etc/passwd` dumps passwd; `fmt=txt;env` leaks `APP_SECRET`, `TEAM_ID`, `TEAM_SALT` |
| Impact | Arbitrary commands as **root** in the container; env-secret theft enables offline JWT minting (attack chain 3) |
| Evidence | ![F-01](evidence/img/F-01.png) |

### Finding F-02 — SQL injection: authentication bypass on `/login`
| Field | Value |
|---|---|
| CWE | CWE-89 |
| OWASP 2025 | A05 |
| Severity | Critical |
| Location | `app.py:128-129`, `POST /login` |
| Reproduction | `POST /login` with `username=alice'--` and any `password` → `302` + session cookie issued |
| Impact | Login as any user without credentials |
| Evidence | ![F-02](evidence/img/F-02.png) |

### Finding F-03 — SQL injection: UNION dump via `/search`
| Field | Value |
|---|---|
| CWE | CWE-89 |
| OWASP 2025 | A05 |
| Severity | Critical |
| Location | `app.py:178`, `GET /search?q=` |
| Reproduction | `GET /search?q=' UNION SELECT id,username,password FROM users--` returns every user's MD5 hash as "search results" |
| Impact | Full `users` table exfiltration (all password hashes) |
| Evidence | ![F-03](evidence/img/F-03.png) |

### Finding F-04 — Privilege escalation via mass-assigned `role` on `/register`
| Field | Value |
|---|---|
| CWE | CWE-915 / CWE-266 |
| OWASP 2025 | A01 + API3 |
| Severity | High |
| Location | `app.py:114`, `POST /register` |
| Reproduction | `POST /register` with `username=mallory&password=pw123&role=admin` → new account reaches `/admin` |
| Impact | Self-provisioned admin account — persistent full access |
| Evidence | ![F-04](evidence/img/F-04.png) |

### Finding F-05 — Duplicate `admin` registration (no UNIQUE constraint)
| Field | Value |
|---|---|
| CWE | CWE-269 |
| OWASP 2025 | A01 |
| Severity | High |
| Location | `app.py:64` (schema), `app.py:91` (`role_of()`) |
| Reproduction | Re-register `admin`/`myownpw` → login with own password → `role_of()` returns the *real* admin's role → `/admin` access |
| Impact | Privilege escalation without touching `role` field |
| Evidence | ![F-05](evidence/img/F-05.png) |

### Finding F-06 — JWT forgery via hardcoded `SECRET`
| Field | Value |
|---|---|
| CWE | CWE-321 (hardcoded key), CWE-347 |
| OWASP 2025 | A07 |
| Severity | High |
| Location | `app.py:23,83` |
| Reproduction | `jwt.encode({'sub':'admin'}, 'notevault-dev-secret', algorithm='HS256')` → forged cookie reaches `/admin`. (Note: `alg=none` is whitelisted but blocked by PyJWT 1.7.1's key-guard — the working attack is key theft.) |
| Impact | Impersonate any user without credentials |
| Evidence | ![F-06](evidence/img/F-06.png) |

### Finding F-07 — IDOR on `GET /api/notes/<id>`
| Field | Value |
|---|---|
| CWE | CWE-639 |
| OWASP 2025 | A01 + API1 |
| Severity | High |
| Location | `app.py:163-166` |
| Reproduction | As `alice`: `GET /api/notes/2` → admin's `infra` note ("prod db password is hunter2"); `/api/notes/3` → `build-tag` marker |
| Impact | Read every user's private notes incl. admin secrets |
| Evidence | ![F-07](evidence/img/F-07.png) |

### Finding F-08 — Excessive data exposure on `/admin`
| Field | Value |
|---|---|
| CWE | CWE-200 / CWE-359 |
| OWASP 2025 | API3 |
| Severity | High |
| Location | `app.py:191` |
| Reproduction | Any admin-reachable path (F-04/05/06) → `GET /admin` returns `password` column (MD5 hashes) for all users |
| Impact | Every password hash leaks through an official endpoint |
| Evidence | ![F-08](evidence/img/F-08.png) |

### Finding F-09 — Stored XSS in note title/body
| Field | Value |
|---|---|
| CWE | CWE-79 |
| OWASP 2025 | A05 |
| Severity | High |
| Location | `app.py:43,104-106,181-182` (`notes_html\|safe`) |
| Reproduction | `POST /notes` with `body=<script>alert(document.cookie)</script>` → every viewer executes it; cookie readable (no HttpOnly) |
| Impact | Session theft of any viewer incl. admin (chains with F-10) |
| Evidence | ![F-09](evidence/img/F-09.png) |

### Finding F-10 — Session cookie missing flags + JWT never expires
| Field | Value |
|---|---|
| CWE | CWE-1004 / CWE-614 / CWE-613 |
| OWASP 2025 | A05 / A07 |
| Severity | Medium |
| Location | `app.py:134,136` |
| Reproduction | `Set-Cookie: session=…; Path=/` — no `HttpOnly`, `Secure`, `SameSite`; payload `{"sub":"alice"}` has no `exp`/`aud`; logout deletes only the client copy |
| Impact | XSS→instant session theft; stolen tokens work forever |
| Evidence | ![F-10](evidence/img/F-10.png) |

### Finding F-11 — No rate limiting / lockout
| Field | Value |
|---|---|
| CWE | CWE-307 |
| OWASP 2025 | API4 |
| Severity | Medium |
| Location | `app.py:123-137`, `POST /login` |
| Reproduction | 30+ rapid failed logins → all `401`, no delay or lockout |
| Impact | Online password brute force; unbounded resource use |
| Evidence | ![F-11](evidence/img/F-11.png) |

### Finding F-12 — No CSRF protection
| Field | Value |
|---|---|
| CWE | CWE-352 |
| OWASP 2025 | A01 |
| Severity | Medium |
| Location | `app.py:147-155` (`/notes`, `/login`, `/register`) |
| Reproduction | `POST /notes` with `Origin: http://evil.example` → `302` accepted; no token or Origin/Referer check |
| Impact | Third-party pages can act as any logged-in user |
| Evidence | ![F-12](evidence/img/F-12.png) |

### Finding F-13 — `debug=True` → Werkzeug debugger exposure
| Field | Value |
|---|---|
| CWE | CWE-489 / CWE-215 |
| OWASP 2025 | A02 |
| Severity | High |
| Location | `app.py:209` |
| Reproduction | `GET /search?q='` → `sqlite3.OperationalError` → full traceback page with interactive console ("execute arbitrary Python code") |
| Impact | Info disclosure by default; second RCE path via console (PIN in logs) |
| Evidence | ![F-13](evidence/img/F-13.png) |

### Finding F-14 — Vulnerable dependencies (known CVEs)
| Field | Value |
|---|---|
| CWE | CWE-1395 |
| OWASP 2025 | A03 |
| Severity | High |
| Location | `requirements.txt` |
| Reproduction | `pip-audit -r requirements.txt` → **81 known vulnerabilities in 7 packages** (Flask 2.0.1, Werkzeug 2.0.1, Jinja2 3.0.1, PyJWT 1.7.1, requests 2.25.1, urllib3 1.26.4, idna 2.10) |
| Impact | Attackers use published exploits; no new bug needed |
| Evidence | `evidence/F-14.txt` |

### Finding F-15 — Dockerfile misconfigurations
| Field | Value |
|---|---|
| CWE | CWE-250 (root), CWE-798 (baked secret), CWE-1357 |
| OWASP 2025 | A02 |
| Severity | High |
| Location | `Dockerfile` |
| Reproduction | `docker history` → `ENV APP_SECRET=notevault-dev-secret` visible in layer; `docker exec … whoami` → `root`; `FROM python:3.12` unpinned; `COPY . .` drags whole context; `pip install` without `--require-hashes` |
| Impact | Root compromise inside container; secret recoverable from image; unpinned supply chain |
| Evidence | `evidence/F-15.txt` |

### Finding F-16 — No logging or audit trail
| Field | Value |
|---|---|
| CWE | CWE-778 |
| OWASP 2025 | A09 |
| Severity | Medium |
| Location | `app.py` (no `logging` anywhere) |
| Reproduction | After the full attack session, `docker logs` shows only werkzeug access lines — no auth events, no alerts, no audit |
| Impact | Breaches are invisible; repudiation impossible; no detection |
| Evidence | `evidence/F-16.txt` |

### Finding F-17 — `seed()` drops all data on every restart
| Field | Value |
|---|---|
| CWE | CWE-664 (improper resource lifetime control) |
| OWASP 2025 | A06 |
| Severity | Low |
| Location | `app.py:63,208` |
| Reproduction | `docker restart` → `/admin` shows only the 2 seed users; all registered accounts/notes gone |
| Impact | Anyone who can crash the app (or any ops restart) destroys all data |
| Evidence | ![F-17](evidence/img/F-17.png) |

### Finding F-18 — Passwords stored with fast, unsalted MD5
| Field | Value |
|---|---|
| CWE | CWE-916 / CWE-327 |
| OWASP 2025 | A04 |
| Severity | High |
| Location | Baseline `app.py:68-69,117` |
| Reproduction | The baseline stores `hashlib.md5(password.encode()).hexdigest()`; known inputs reproduce the exact database hashes without a per-user salt |
| Impact | A database or admin-response leak becomes rapid offline password cracking; equal passwords also have equal hashes |
| Evidence | `evidence/F-18.txt` |

### Finding F-19 — Plain HTTP transport
| Field | Value |
|---|---|
| CWE | CWE-319 |
| OWASP 2025 | A04 |
| Severity | Medium |
| Location | Baseline `app.py:209`, `docker-compose.yml:5-6` |
| Reproduction | The Flask server listens without TLS on `http://0.0.0.0:8080`, and Compose publishes that port directly |
| Impact | A network-positioned attacker can observe or modify credentials, cookies, notes, and responses |
| Evidence | `evidence/F-19.txt` |

---

## 5. Remediation  *(25 pts)*

The changes are on `security-remediation`. Application controls and tests are
in commit `deb2381` (`F-01`–`F-13`, `F-16`–`F-19`). Dependency, container,
SBOM, CI, signing, and provenance controls are in `38ecdba` (`F-14`, `F-15`,
`F-17`, `F-19`). The table maps every finding to its regression proof.

### Representative before/after changes

**F-01 — remove the OS command interpreter:**

```diff
- out = subprocess.run("echo exporting notes as " + fmt, shell=True, ...)
+ if output_format not in {"txt", "json"}:
+     return "unsupported export format", 400
+ rows = get_db().execute("SELECT ... WHERE owner = ?", (current_user(),))
```

No attacker input reaches a shell. Export formats are an exact allow-list and
the response is generated in Python.

**F-02/F-03 — parameterize SQL:**

```diff
- q = "SELECT * FROM users WHERE username = '%s' ..." % username
- row = con.execute(q).fetchone()
+ row = get_db().execute(
+     "SELECT username, password_hash FROM users WHERE username = ?", (username,)
+ ).fetchone()
```

Input remains data instead of becoming SQL grammar. Search also escapes the
`LIKE` wildcard characters before using a bound parameter.

**F-07 — enforce object ownership in the query:**

```diff
- SELECT id,owner,title,body FROM notes WHERE id = ?
+ SELECT id,owner,title,body FROM notes WHERE id = ? AND owner = ?
```

The database returns a note only when both its identifier and authenticated
owner match.

**F-09 — restore Jinja output encoding:**

```diff
- {{ notes_html|safe }}
+ {% for note in notes %}{{ note.title }}: {{ note.body }}{% endfor %}
```

Titles and bodies are passed as template data and automatically HTML-escaped;
the CSP is a second layer of defense.

**F-06/F-10 — secure and bound the session:**

```diff
- SECRET = "notevault-dev-secret"
- jwt.decode(token, SECRET, algorithms=["HS256", "none"])
- resp.set_cookie("session", token)
+ jwt.decode(token, runtime_secret, algorithms=["HS256"],
+            audience="notevault-web", issuer="notevault",
+            options={"require": ["sub", "iat", "exp", "jti", "aud", "iss"]})
+ resp.set_cookie("session", token, httponly=True, secure=True,
+                 samesite="Strict", max_age=900)
```

The key is supplied only at runtime, the algorithm and claims are pinned, each
token expires after 15 minutes, logout stores its `jti` in a revocation table,
and browser cookie controls reduce theft and cross-site use.

### Finding-to-fix traceability

| Finding | Problem | Implemented control | Regression proof |
|---|---|---|
| F-01 | P-08 | Removed `subprocess` and `shell=True`; `txt/json` allow-list | `test_f01_export_command_injection_is_rejected` |
| F-02 | P-04 | Parameterized login query and constant-time-style dummy hash check | `test_f02_login_sql_injection_fails` |
| F-03 | P-06 | Parameterized `LIKE`, escaped wildcards, fixed template | `test_f03_search_union_injection_fails` |
| F-04 | P-01 | Server always inserts role `user` | `test_f04_registration_ignores_attacker_role` |
| F-05 | P-02 | `UNIQUE COLLATE NOCASE` username constraint | `test_f05_duplicate_admin_registration_is_blocked` |
| F-06 | P-03 | Runtime 32+ character key; HS256 only; required claims | `test_f06_forged_jwt_with_old_secret_is_rejected` |
| F-07 | P-05 | Note query includes authenticated owner | `test_f07_idor_returns_not_found_for_another_users_note` |
| F-08 | P-07 | Admin DTO selects only id, username, role | `test_f08_admin_response_excludes_password_hash` |
| F-09 | P-09 | Jinja autoescaping plus restrictive CSP | `test_f09_stored_xss_is_escaped` |
| F-10 | P-12+P-13 | 15-minute JWT, audience/issuer/JTI, revocation, cookie flags | `test_f10_session_has_flags_claims_and_logout_revokes` |
| F-11 | P-11 | Five failures/minute/IP limiter with 429/Retry-After | `test_f11_login_rate_limit_returns_429` |
| F-12 | P-15 | Double-submit CSRF token and Origin validation on every POST | `test_f12_csrf_is_required_and_origin_checked` |
| F-13 | P-16 | Gunicorn entry point, generic 500 response, debug disabled | `test_f13_debug_disabled_and_errors_are_generic` |
| F-14 | P-18 | Current direct pins plus complete SHA-256 lockfile | `test_f14_dependencies_are_upgraded`; `pip-audit` clean |
| F-15 | P-17 | Digest pin, non-root UID, read-only FS, dropped capabilities, narrow COPY | `test_f15_dockerfile_is_hardened` |
| F-16 | P-19 | Authentication, admin, CSRF, export, and note audit events | `test_f16_security_events_are_logged` |
| F-17 | P-20 | `CREATE TABLE IF NOT EXISTS`, seed only when empty, named volume | `test_f17_database_initialization_preserves_existing_data` |
| F-18 | P-10 | Werkzeug salted `scrypt` password hashes | `test_weak_md5_password_storage_is_replaced` |
| F-19 | P-14 | Loopback-only container binding, Secure cookie and HSTS; TLS required at deployment edge | `test_security_headers_are_present`; deployment check |

Local verification on 3 November 2026: **21 tests passed**, Bandit reported
zero findings, and pip-audit reported **no known vulnerabilities**.

---

## 6. Supply-Chain Hardening  *(15 pts)*

- `requirements.lock` pins the complete production graph and includes SHA-256
  hashes. Docker installs it with `--require-hashes`.
- [`supply-chain/sbom.cdx.json`](supply-chain/sbom.cdx.json) is a validated,
  reproducible **CycloneDX 1.6** SBOM containing **9 components**.
- The base image is `python:3.12.16-slim-bookworm` pinned to manifest digest
  `sha256:e697c818…d9d337`.
- The release workflow builds and pushes an immutable GHCR image, keyless-signs
  `image@digest` with Cosign/OIDC, attaches the CycloneDX attestation, generates
  GitHub build provenance, verifies the signature, and uploads
  `cosign-verify.txt` as evidence.

**Signing status:** repository automation is complete; the signature itself is
created only when a team member pushes a `v*` tag. After that run, download the
`release-security-evidence` artifact and add its `cosign-verify.txt` output or
screenshot here. Do not claim the image is signed before that workflow passes.

**SLSA self-assessment:** the tagged GitHub build targets **SLSA Build Level 2**:
the build runs on a hosted build service and produces authenticated provenance
bound to the image digest. It is not claimed as Level 3 because the workflow
still depends on version-tagged third-party Actions and has not undergone a
formal hardened-build-platform review.

---

## 7. Security CI Pipeline  *(10 pts)*

Workflow: [`.github/workflows/security.yml`](.github/workflows/security.yml).

| Gate | Tool | Failure condition |
|---|---|---|
| Regression | Pytest | Any functional/security test fails |
| SAST | Bandit | Any HIGH-severity finding (`-lll`) |
| SCA | pip-audit | Any known vulnerable locked dependency |
| Secrets | Gitleaks v3 | Any verified secret pattern in history/diff |
| Container SCA | Trivy | Any fixed HIGH or CRITICAL OS/library vulnerability |
| SBOM | CycloneDX | Generation, JSON check, or schema validation fails |

The workflow runs on pushes to `main`, `security-remediation`, and `dev`, and on
pull requests to `main`.

**Passing run** — all three jobs green on `dev`:

![Security CI passing run](evidence/img/ci-pass.png)

**Failing gate** — the container gate blocked a run when the Trivy check could
not complete (kept as proof the pipeline fails closed rather than skipping the
scan):

![Container gate failing](evidence/img/ci-fail-trivy.png)

---

## 8. Conclusion & Reflection  *(5 pts — clarity)*

The baseline showed how apparently separate weaknesses form attack chains:
SQL injection or JWT forgery reaches the admin hash dump; weak MD5 then turns a
temporary access bug into reusable credentials; XSS plus a readable,
non-expiring cookie creates durable account takeover; command injection becomes
critical because the container runs as root. The main lesson is that secure
code, identity controls, runtime confinement, and supply-chain evidence must be
treated as one system rather than four independent checklists.

Residual risks are explicit. Production still needs TLS termination and network
policy outside this single-container teaching repository. The in-memory login
limiter is appropriate only for the configured single Gunicorn worker; a scaled
deployment should use a shared Redis-backed limiter. Default course passwords
must never be used outside the local demo. Future work should add centralized
log shipping/alerts, database encryption/backups, action references pinned to
full commit SHAs, periodic key/secret rotation, and an independent penetration
retest.

---

## Appendix

**Tools:** curl, Docker/Compose, Pytest, Bandit, pip-audit, CycloneDX,
Gitleaks, Trivy, Cosign, GitHub Actions, SQLite, and browser developer tools.

**Primary references:** OWASP Top 10:2025, OWASP API Security Top 10:2023,
MITRE CWE, Flask/Werkzeug security documentation, CycloneDX 1.6, Sigstore
Cosign, and SLSA v1.0.

**Proposed task split—team must confirm before submission:** Panaikron owns the
threat model/finding narration; Sai owns application fixes/regression tests;
Zaw owns container/SBOM/CI/signing. All three review the report and appear in
the demo video.

---

## Grading rubric (100)

| Criterion | Pts |
|---|---|
| Threat model quality & completeness (§3) | 20 |
| Vulnerability findings — correctness, CWE/OWASP mapping, depth (§4) | 25 |
| Remediation quality — correct, minimal, well-explained (§5) | 25 |
| Supply-chain hardening — SBOM + signing + provenance (§6) | 15 |
| CI pipeline — works, fails build appropriately (§7) | 10 |
| Presentation & report clarity (§1, §8) | 5 |

*All work stays within the [ethics policy](../ETHICS.md).*
