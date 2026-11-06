# STRIDE analysis — NoteVault

> Plain-language narrative of every threat lives in
> [`01-problems.md`](01-problems.md) — this file is the formal STRIDE view of the
> same material. Its **Links** lines cite rows below as "STRIDE row N".

Method: each process/data-flow/data-store in [`02-dataflow.md`](02-dataflow.md) is checked
against the six STRIDE categories (✓ = credible threat on the baseline).

## STRIDE per element

| # | Element / data flow | S | T | R | I | D | E | Top threat & mitigation |
|---|---|---|---|---|---|---|---|---|
| 1 | `F1 (TB1)` — login/register credentials in transit | ✓ | | | ✓ | | | Sniffed credentials over plaintext HTTP → TLS |
| 2 | `P1 / F1 (TB1)` — `/login` rate & resource limits (API4) | ✓ | | | | ✓ | | Unlimited `/login` attempts → credential brute force; unbounded requests/notes/`export` → exhaustion → rate limit + lockout + size caps |
| 3 | `P1 / F5 (TB2)` — auth logic (`/login`, `/register`) | ✓ | ✓ | | | | ✓ | SQLi auth bypass + client-set `role=admin` + **no UNIQUE(username)** → re-register `admin` with own password also yields admin. Parameterised queries, fixed role, UNIQUE constraint |
| 4 | `D3 / F2–F3 (TB1)` — session JWT cookie | ✓ | ✓ | | ✓ | | ✓ | Hardcoded weak `SECRET` → forged admin HS256 token (verified → `/admin` dump); `alg=none` whitelisted but blocked by PyJWT's key-guard; **no `exp`/`aud`** → token never expires, stateless logout can't revoke theft; no HttpOnly/Secure → XSS theft. Pin `HS256`, env secret, require `exp`/`aud`, cookie flags |
| 5 | `P2 / F4 (TB2)` — notes create/render (`GET /`, `POST /notes`) | | ✓ | | ✓ | | | Stored XSS via `notes_html\|safe` → output encoding, CSP |
| 6 | `P6 / F4 (TB2)` — `GET /api/notes/<id>` | | | | ✓ | | | IDOR/BOLA — no owner check, any note readable → enforce `owner = current_user` |
| 7 | `P3 / F4 (TB2)` — `GET /search` | | ✓ | | ✓ | | | SQLi via `q` (UNION dump of users+notes) → parameterised LIKE |
| 8 | `P4 / F6 / F9 (TB1–TB2)` — `GET /admin` | | | | ✓ | | | Excessive data exposure — leaks every user's MD5 hash → never return hashes; strong KDF |
| 9 | `P5 → P7 / F7 (TB3)` — `/export` → OS shell | | ✓ | | ✓ | ✓ | ✓ | Command injection via `fmt` (`;id`, `;sleep 999`) → RCE + DoS. Remove `shell=True`, whitelist fmt |
| 10 | `D1 / D2 (TB2)` — SQLite store (`users`, `notes`) | | ✓ | | ✓ | ✓ | | Tamper/dump via upstream SQLi; `/tmp` file; `seed()` drops all data on every restart → least-privilege FS, no raw SQL, persistent volume |
| 11 | `D1` — `users` password store (MD5, no salt) | | | | ✓ | | | Offline cracking of dumped hashes → slow salted KDF (`scrypt`/argon2/bcrypt) |
| 12 | `P0 / D4 / F8 (TB4)` — Container & runtime (`Dockerfile`, `debug=True`) | | | | ✓ | | ✓ | Root process + baked `APP_SECRET` + unpinned base + Werkzeug debugger (interactive console → potential RCE) → non-root, runtime secrets, pin digest, debug off |

## Top 5 risks (likelihood × impact)

| Rank | Risk | Likelihood | Impact | Rationale |
|---|---|---|---|---|
| R1 | **Remote command execution via `/export?fmt=`** (TB3) | High — one URL-encoded `;cmd` | Critical — arbitrary commands as **root** in container; read env secrets, pivot to host | `shell=True` + unvalidated input; also exposes `APP_SECRET`, enables container escape attempts |
| R2 | **SQL injection — login bypass + search UNION dump** (TB2) | High — `sqlmap` finds it instantly | Critical — bypass auth as *any* user; dump all credentials + all notes incl. admin's `infra` secret and the `build-tag` marker; write access possible | Two string-formatted queries (`/login`, `/search`) |
| R3 | **Session forgery — hardcoded JWT `SECRET`** | High — secret is in the repo, `jwt.encode({"sub":"admin"}, SECRET)` just works | High — impersonate any user incl. `admin` → reaches P4 hash dump | `SECRET` committed to source, no `exp`. (`alg=none` whitelisted but not exploitable — PyJWT rejects unsigned tokens when a key is supplied) |
| R4 | **Privilege escalation via mass-assigned `role` on `/register`** | High — one extra form field | High — self-provisioned admin → full user/hash dump, persistent | `role` taken straight from request body |
| R5 | **IDOR on `GET /api/notes/<id>`** | High — increment an integer | Medium–High — read every user's private notes incl. admin secrets (and marker) | No ownership check; ids are sequential |

## Secondary risks (tracked, lower rank)

- Stored XSS in note title/body (`notes_html|safe`) → session theft amplified by missing `HttpOnly`
- Unsalted MD5 password hashes dumped by `/admin` or SQLi → trivially cracked (rainbow tables)
- Plaintext HTTP → credential/session sniffing on any shared network
- `debug=True` → Werkzeug debugger exposure (potential RCE) and verbose error leakage
- No CSRF protection on `/notes`, `/login`, `/register`
- Container runs as root; base image unpinned; `APP_SECRET` baked into image layer
- Outdated baseline dependencies (`requirements.txt`) with known CVEs — confirmed in `evidence/F-14.txt`
- No logging or audit trail anywhere → R (repudiation) applies globally
- No security headers (CSP, X-Frame-Options) → clickjacking + XSS impact amplification

## Abuse cases (attacker personas)

| Persona | Abuse case |
|---|---|
| **A1 — unauthenticated outsider** | Forge an HS256 JWT with the committed `SECRET` or SQLi the login → becomes any user without credentials; mass-assign `role=admin` at `/register` → full admin without ever logging in |
| **A2 — authenticated regular user (e.g. `alice`)** | Reads other users' notes via IDOR (`/api/notes/<id>`); UNION-dumps the users table via `/search`; plants stored-XSS notes that steal the admin's session cookie when admin logs in; runs `;cat /etc/passwd` via `/export` |

## Attack chains (systems-level pass)

*Assume one element is owned — what does it reach?*

- **Chain 1:** mass-assigned `role=admin` (or duplicate-`admin` registration) → `/admin` returns every MD5 hash → offline crack (`hunter2`-class passwords) → valid credentials persist even if the register bug is later fixed. *Fixing only the registration flaw does not remove the risk — the weak hashing is a second, independent bug that turns a transient bug into permanent credential theft.*
- **Chain 2:** stored XSS (`notes_html|safe`, Medium alone) + missing `HttpOnly` → steals a real admin session cookie → combined with no `exp` the token works indefinitely → `/admin` dump → chain 1 again. *Two medium bugs chain into full account takeover.*
- **Chain 3:** `/export` command injection → reads `/proc/self/environ` → recovers `APP_SECRET`, `TEAM_SALT` → can mint valid JWTs offline even after the hardcoded `SECRET` is rotated — *unless* the env-secret design itself is fixed (TB4).

## Coverage check vs the course attack-surface list

| Attack surface (Week 1 list) | Covered by |
|---|---|
| HTTP params (form, query) | rows 1–3, 7, 9 |
| Headers / cookies | row 4 (JWT cookie) |
| File uploads | n/a — app has no upload feature |
| APIs (`/api/notes`, `/admin` JSON) | rows 6, 8 |
| Env vars / config | row 12, D4 |
| Dependencies (`requirements.txt`) | secondary risks → Phase 2 SCA |
