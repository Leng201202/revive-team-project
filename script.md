# NoteVault three-person demo video script

Target length: **8–10 minutes**. Show the terminal and relevant source/report
side by side. Never show a real token, private key, or account credential beyond
the course-provided local test credentials.

## Three-person split

| Person | Time | Responsibility |
|---|---:|---|
| **Person 1 — Panaikron** | 0:00–3:15 | Introduction, threat model, and successful attacks against the baseline |
| **Person 2 — Sai** | 3:15–6:15 | Root causes, remediated code, and proof that the attacks now fail |
| **Person 3 — Zaw** | 6:15–9:20 | Tests, SAST/SCA, container, SBOM, CI, signing, provenance, and conclusion |

Record the sections separately if needed, but use one shared terminal session
for the command sequence. Person 3 combines the recordings into the final
video. Each person should rehearse their own narration and the handoff to the
next person.

## Before recording

Rehearse the complete sequence before recording. Commands below use Bash or zsh
on macOS/Linux and require Docker Desktop with Compose v2, Python 3, curl, and
jq. Start Docker Desktop first. Save and commit your work before switching
branches; `git status --short` should be empty.

The `main` branch contains the vulnerable baseline. The fixed application and
all secure-build deliverables are on `security-remediation`. The commands below
switch between those two branches for the before-and-after demonstration.

```bash
cd /Users/leng/Desktop/SoftwareSecurity/revive-notevault-secure-build
git switch security-remediation
git status --short
docker compose version
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
export TEAM_ID=REVIVE
export APP_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DEMO_TMP="$(mktemp -d /tmp/notevault-demo.XXXXXX)"
docker compose down
```

Keep this terminal open throughout the demo so the generated secret remains
available. The command sets the secret without printing it; do not echo it while
recording. Compose requires `APP_SECRET` even for `docker compose down`.

Prepare these browser tabs/files:

- `REPORT.md`
- `threat-model/02-dataflow.md`
- vulnerable `app.py` on `main`
- fixed `app.py` on `security-remediation`
- the passing GitHub Security CI run
- the signed-release run and `cosign-verify.txt` artifact

Increase terminal font size and use a fresh browser session for each version.
Keep the same `TEAM_ID=REVIVE` throughout. The login commands below show only
HTTP status codes; cookie jars hold session tokens and should stay off camera.

# Person 1 — Attack and threat analysis (0:00–3:15)

Person 1 performs the introduction, threat model, and all successful baseline
attacks. Hand over to Person 2 while the vulnerable application is still
running.

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
docker compose ps
curl -sS -o /dev/null -w 'Baseline readiness: HTTP %{http_code}\n' http://localhost:8080/
```

Continue only after the readiness request returns `200`. The baseline has no
health check, so retry the readiness request if the first request is too early.

Log in and prove command execution:

```bash
curl -sS -o /dev/null -w 'Normal login: HTTP %{http_code}\n' \
  -c "$DEMO_TMP/alice.jar" -X POST http://localhost:8080/login \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alicepw"

curl -s -b "$DEMO_TMP/alice.jar" -G http://localhost:8080/export \
  --data-urlencode "fmt=txt;id"
```

**Point out:** `uid=0(root)`.

Then demonstrate SQL-injection login bypass and IDOR:

```bash
curl -sS -o /dev/null -w 'SQL injection login: HTTP %{http_code}\n' \
  -c "$DEMO_TMP/bypass.jar" -X POST http://localhost:8080/login \
  --data-urlencode "username=alice'--" \
  --data-urlencode "password=wrong"

curl -s -b "$DEMO_TMP/bypass.jar" http://localhost:8080/api/notes/2
```

**Expected:** both logins return `302`. The second login succeeds despite the
wrong password, and note `2` contains the admin's private note. Keep the attack
limited to this local course container.

**Say:**

> The export input is concatenated into a `shell=True` command, and the
> container runs as root. Login input is concatenated into SQL, so the comment
> sequence removes the password check. Once authenticated as Alice, changing
> the note number returns the admin's note because the API never checks owner.

**Handoff:**

> I have demonstrated command injection, SQL-injection authentication bypass,
> and IDOR against the original baseline. Sai will now show their root causes
> and demonstrate the remediated application.

# Person 2 — Root cause and remediation (3:15–6:15)

Person 2 starts with the vulnerable app still running, explains the root cause,
stops it, switches to `security-remediation`, and proves the attacks are blocked.

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
git switch security-remediation
```

## 4:20–6:15 — Show the fixes and failed attacks

```bash
export TEAM_ID=REVIVE
docker compose up -d --build --wait --wait-timeout 120
```

After the health check passes, get the CSRF token and log in normally:

```bash
curl -s -c "$DEMO_TMP/secure.jar" http://localhost:8080/ \
  -o "$DEMO_TMP/login.html"
CSRF=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' \
  "$DEMO_TMP/login.html" | head -1)
curl -sS -o /dev/null -w 'Secure login: HTTP %{http_code}\n' \
  -b "$DEMO_TMP/secure.jar" -c "$DEMO_TMP/secure.jar" \
  -X POST http://localhost:8080/login \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alicepw" \
  --data-urlencode "csrf_token=$CSRF"
```

**Expected:** `302`. The CSRF token is needed because the fixed app rejects
state-changing requests without it. Keep the token and its matching cookie jar
together. A `403` here is a CSRF failure, not proof that a SQL injection was
blocked.

Repeat the SQL-injection login with a valid CSRF token:

```bash
curl -sS -o /dev/null -w 'Secure SQL injection login: HTTP %{http_code}\n' \
  -b "$DEMO_TMP/secure.jar" -X POST http://localhost:8080/login \
  --data-urlencode "username=alice'--" \
  --data-urlencode "password=wrong" \
  --data-urlencode "csrf_token=$CSRF"
```

**Expected:** `401 login failed`. This request does not save a new cookie, so
the existing legitimate Alice session remains available for the next checks.

Repeat the command injection and IDOR attacks:

```bash
curl -i -b "$DEMO_TMP/secure.jar" -G http://localhost:8080/export \
  --data-urlencode "fmt=txt;id"

curl -i -b "$DEMO_TMP/secure.jar" http://localhost:8080/api/notes/2
```

**Point out:** the responses are `400 unsupported export format` and `404 not
found`; there is no command output or admin note.

Prove legitimate behavior still works:

```bash
curl -i -b "$DEMO_TMP/secure.jar" http://localhost:8080/api/notes/1
curl -i -b "$DEMO_TMP/secure.jar" -G http://localhost:8080/export \
  --data-urlencode "fmt=txt"
```

**Expected:** both return `200` and contain only Alice's notes.

| Check | Baseline result | Fixed result |
|---|---|---|
| Correct Alice password | `302`, session issued | `302`, session issued |
| SQL injection with wrong password | `302`, bypass succeeds | `401`, login rejected |
| Export `fmt=txt;id` as Alice | Command output with `uid=0` | `400`, unsupported format |
| Alice reads admin note `2` | `200`, admin note disclosed | `404`, note unavailable |
| Alice reads own note `1` | `200` | `200` |

**Show fixed code and say:**

> Export uses an exact txt/json allow-list and never starts a shell. Queries use
> placeholders. The note query includes both id and owner. Templates autoescape
> note data. Registration always chooses the user role. Sessions use a runtime
> key, HS256 only, required audience, issuer, expiry, and JTI claims, revocation,
> and HttpOnly, Secure, SameSite Strict cookies.

**Handoff:**

> The same attacks now return 401, 400, and 404, while legitimate requests
> still return 200. Zaw will now verify the tests, hardened container, SBOM,
> security pipeline, signing, and provenance.

# Person 3 — Secure build and delivery evidence (6:15–9:20)

Person 3 runs the automated checks, shows the supply-chain controls, presents
the GitHub evidence, gives the conclusion, and assembles the final recording.

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

Use that narration only if the displayed commands pass. If the test count or
scanner result differs, investigate and update the narration before recording.

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

> Pushes to main, security-remediation, and dev run tests, Bandit SAST,
> pip-audit SCA, Gitleaks secret scanning,
> and a Trivy container gate. HIGH or CRITICAL findings fail the workflow. A
> version tag builds an immutable GHCR image, records provenance, signs the
> image digest keylessly with Cosign, attaches the SBOM, and verifies the OIDC
> identity. This verification output proves the artifact we built is the one we
> signed.

Before using this narration, open the repository's **Actions** tab and verify:

1. **Security CI:** all jobs pass for the demonstrated fixed commit. Record the
   run URL and commit SHA.
2. **Failing-gate evidence:** the log names a HIGH/CRITICAL finding and the gate
   fails because of it. A scanner installation/download error is not evidence
   that a vulnerability was detected.
3. **Signed release:** a successful `v*` tag run identifies the released image
   digest. Download **release-security-evidence** from that run's Artifacts
   section and open `cosign-verify.txt`.
4. **Provenance:** open the build-provenance attestation from the same release
   and match its subject digest to the signed image.

If signing has not run, describe it as configured automation and finish the
release before recording the final video. Do not present a workflow file alone
as proof that an artifact has been signed.

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

Add the video URL to the report cover and the run URLs, commit SHA, image digest,
and verification evidence to sections 6–7. Export the report as PDF and check
that diagrams, screenshots, and links render correctly. Test the video link in
a private browser window to confirm it opens without an access request.

## Troubleshooting during rehearsal

| Symptom | What to check |
|---|---|
| Docker daemon unavailable | Start Docker Desktop and retry `docker compose ps`. |
| Port 8080 already in use | Stop the other course lab from its own directory with `docker compose down`. |
| `APP_SECRET` is missing | Run the secret-generation command in this terminal again, then recreate the secure container; log in again because the key changed. |
| Secure login returns `403` | Fetch a fresh login page and CSRF cookie together, then extract the token again. |
| Login returns `429` | Wait at least 60 seconds before another attempt. |
| Secure attack checks return `401` | The session is missing or expired; repeat normal login before testing export and IDOR. |
| Secure build fails its health check | Inspect `docker compose logs --tail=50 notevault` off camera, resolve the error, and retry. |
| `.venv/bin/python` is missing | Switch to `security-remediation` and run the virtual-environment setup from the preparation section. |
| Branch switch reports local changes | Save and commit your intended changes before continuing; do not discard them to run the demo. |

The cookie jars and `login.html` stay inside the temporary `$DEMO_TMP`
directory. Avoid `docker compose down -v` during the demo: it deletes the
secure app's persistent database volume.
