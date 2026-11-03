# REVIVE — NoteVault Secure Build

Term project for the Software Security course. The REVIVE team will assess the
intentionally vulnerable NoteVault application, reproduce and document its
security weaknesses, remediate them, and harden its build and release process.

> Warning: the baseline application is intentionally insecure. Run it only in
> the local course sandbox. Do not expose it to an untrusted network.

## Team

| Member | Student ID | Responsibility |
|---|---|---|
| Panaikron Marohabut | 6631503126 | Threat model, finding narration, report review (confirm with team) |
| Sai Shang Hlang | 6631503129 | Application remediation and regression tests (confirm with team) |
| Zaw Phyo Aung | 6631503130 | Container, SBOM, CI/signing and video (confirm with team) |

## Work in two parts

- [Part 1 — attack and analyze; Part 2 — defend and secure the build](PARTS.md)
- [Step-by-step demo video script](script.md)

The `main` branch preserves the vulnerable baseline for before/after evidence.
The `security-remediation` branch contains the fixed application and secure
build.

## Run the secure branch

Set the team identifier before the first build and keep it unchanged throughout
the project:

```bash
export TEAM_ID=REVIVE
export APP_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
docker compose up --build
```

Open <http://localhost:8080>. The provided baseline accounts are:

- `alice` / `alicepw`
- `admin` / `admin123`

Stop the application with:

```bash
docker compose down
```

Run the local verification suite with:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/bandit -r app.py -lll
.venv/bin/pip-audit -r requirements.lock --disable-pip
```

## Project deliverables

- Data-flow diagram, trust boundaries, STRIDE analysis, and ranked risks
- Vulnerability findings mapped to CWE and OWASP Top 10:2025/API categories
- Remediated code with one traceable commit per finding
- Regression tests proving the attacks no longer work
- Hardened dependencies and container image
- CycloneDX SBOM
- Cosign signature and verification evidence for the release artifact
- GitHub Actions gates for SAST, SCA, and secret scanning
- Final PDF report and recorded attack-to-fix walkthrough

## Repository workflow

The `main` branch begins with the original vulnerable teaching target. Security
work should be performed on a `security-remediation` branch using finding IDs in
commit messages, for example:

```text
fix(F-01): parameterize the login query
test(F-01): add SQL injection regression coverage
```

Do not put real credentials, signing keys, tokens, or private evidence in this
repository.

## Source and attribution

This project is based on the NoteVault starter application from the
[KOSEN69 Software Security course repository](https://github.com/nutthakorn7/software-security/tree/main/project/starter-app),
created by Nutthakorn Chalaemwongwan. The original application is deliberately
vulnerable course material. See `LICENSE`, `LICENSE-CONTENT`, and `NOTICE`.
