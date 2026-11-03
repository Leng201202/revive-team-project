# NoteVault demo video script

Target length: **8–10 minutes**. Show the terminal and relevant source/report
side by side. Never show a real token, private key, or account credential beyond
the course-provided local test credentials.

## Before recording

```bash
cd /Users/leng/Desktop/SoftwareSecurity/revive-notevault-secure-build
git status
docker compose down
```

Prepare these browser tabs/files:

- `REPORT.md`
- `threat-model/02-dataflow.md`
- vulnerable `app.py` on `main`
- fixed `app.py` on `security-remediation`
- the passing GitHub Security CI run
- the signed-release run and `cosign-verify.txt` artifact

## 0:00–0:40 — Introduction

**Show:** report cover and repository branches.

**Say:**

> We are team REVIVE. NoteVault is a Flask and SQLite note application. We
> approached the project in two parts: first attack and analyze the supplied
> baseline, then remediate the application and secure its build and release.
> We identified 19 findings: 3 Critical, 10 High, 5 Medium, and 1 Low.

## 0:40–1:30 — Threat model

**Show:** the Mermaid DFD and STRIDE/top-five table.

**Say:**

> The browser is untrusted. The key boundaries are client to Flask, Flask to
> SQLite, Flask to the OS shell, and container to host/image. Our highest risks
> were command execution, two SQL-injection paths, JWT forgery, privilege
> escalation, and IDOR. The attack chains matter: for example, SQL injection
> exposes MD5 hashes, making offline credential cracking possible.

## 1:30–3:15 — Attack the vulnerable baseline

```bash
git switch main
export TEAM_ID=REVIVE
docker compose up -d --build
```

Log in and prove command execution:

```bash
curl -s -c alice.jar -X POST http://localhost:8080/login \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alicepw"

curl -s -b alice.jar -G http://localhost:8080/export \
  --data-urlencode "fmt=txt;id"
```

**Point out:** `uid=0(root)`.

Then demonstrate SQL-injection login bypass and IDOR:

```bash
curl -i -c bypass.jar -X POST http://localhost:8080/login \
  --data-urlencode "username=alice'--" \
  --data-urlencode "password=wrong"

curl -s -b bypass.jar http://localhost:8080/api/notes/2
```

**Say:**

> The export input is concatenated into a `shell=True` command, and the
> container runs as root. Login input is concatenated into SQL, so the comment
> sequence removes the password check. Once authenticated as Alice, changing
> the note number returns the admin's note because the API never checks owner.

## 3:15–4:20 — Root cause in code

**Show:** baseline `app.py` around login, API note, search, and export.

**Say:**

> These are not scanner-only findings. The vulnerable interpreter boundaries
> are visible directly: formatted SQL, an unrestricted object query, raw HTML
> marked safe, and attacker input passed to a shell. The hardcoded JWT secret,
> MD5 hashes, missing cookie flags, and debug mode amplify those primary bugs.

Stop the baseline:

```bash
docker compose down
```

## 4:20–6:15 — Show the fixes and failed attacks

```bash
git switch security-remediation
export TEAM_ID=REVIVE
export APP_SECRET=REVIVE-demo-only-random-secret-please-change-123456789
docker compose up -d --build
```

Get the CSRF token and log in normally:

```bash
curl -s -c secure.jar http://localhost:8080/ -o login.html
CSRF=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' login.html | head -1)
curl -i -b secure.jar -c secure.jar -X POST http://localhost:8080/login \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alicepw" \
  --data-urlencode "csrf_token=$CSRF"
```

Repeat the command injection and IDOR attacks:

```bash
curl -i -b secure.jar -G http://localhost:8080/export \
  --data-urlencode "fmt=txt;id"

curl -i -b secure.jar http://localhost:8080/api/notes/2
```

**Point out:** the responses are `400 unsupported export format` and `404 not
found`; there is no command output or admin note.

**Show fixed code and say:**

> Export uses an exact txt/json allow-list and never starts a shell. Queries use
> placeholders. The note query includes both id and owner. Templates autoescape
> note data. Registration always chooses the user role. Sessions use a runtime
> key, HS256 only, required audience, issuer, expiry, and JTI claims, revocation,
> and HttpOnly, Secure, SameSite Strict cookies.

## 6:15–7:10 — Regression and security validation

```bash
.venv/bin/python -m pytest -q
.venv/bin/bandit -r app.py -lll
.venv/bin/pip-audit -r requirements.lock --disable-pip
```

**Say:**

> Twenty-one tests prove both attack rejection and legitimate behavior. Bandit
> reports no findings, and pip-audit reports no known vulnerabilities in the
> hash-locked production graph.

## 7:10–8:00 — Container and SBOM

```bash
docker compose exec notevault id
docker inspect "$(docker compose ps -q notevault)" --format '{{.Config.User}}'
jq '.specVersion, (.components | length)' supply-chain/sbom.cdx.json
```

**Say:**

> The image uses a digest-pinned slim Python base, UID 10001, a read-only root
> filesystem, no added Linux capabilities, no embedded application secret, and
> hash-verified dependencies. The validated CycloneDX 1.6 SBOM contains nine
> production components.

## 8:00–8:50 — CI, signing, and provenance

**Show:** `.github/workflows/security.yml`, one intentional failing run, the
final passing run, then the signed-release verification artifact.

**Say:**

> Every push runs tests, Bandit SAST, pip-audit SCA, Gitleaks secret scanning,
> and a Trivy container gate. HIGH or CRITICAL findings fail the workflow. A
> version tag builds an immutable GHCR image, records provenance, signs the
> image digest keylessly with Cosign, attaches the SBOM, and verifies the OIDC
> identity. This verification output proves the artifact we built is the one we
> signed.

## 8:50–9:20 — Conclusion

**Say:**

> The project reduced the baseline from immediate root command execution,
> database compromise, and account takeover to a layered design with tested
> authorization, safe interpreter boundaries, confined runtime, and verifiable
> release evidence. Remaining production work is external TLS termination, a
> shared rate limiter for multi-instance deployment, centralized alerts, and
> periodic independent retesting.

Stop the demo:

```bash
docker compose down
```

## Evidence to capture after recording

- Final video link viewable without requesting access
- Passing Security CI screenshot
- Intentional HIGH/CRITICAL failing-gate screenshot
- Cosign verification output screenshot/text
- Release provenance/attestation link

