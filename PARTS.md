# NoteVault project in two parts

This file is the working order for the team. Do not mix the two parts: preserve
the vulnerable baseline and its evidence before demonstrating the secure branch.

## Part 1 — Attack and analyze

**Question answered:** What can an attacker do, why does it work, and how bad is
it?

1. Run the original vulnerable app from `main` with `TEAM_ID=REVIVE`.
2. Draw the DFD: client, Flask processes, JWT cookie, SQLite, environment, and
   OS shell.
3. Mark TB1 client/server, TB2 app/database, TB3 app/shell, and TB4
   container/host-image boundaries.
4. Apply STRIDE to every element and rank the top five risks.
5. Test every endpoint and record the request, observed result, impact, CWE,
   OWASP category, severity, and evidence.
6. Preserve screenshots/text evidence before editing the vulnerable code.
7. Review the report for contradictions and make its finding count match the
   executive summary.

**Part 1 artifacts:**

- `threat-model/01-problems.md` — plain-language attack surface
- `threat-model/02-dataflow.md` — DFD, flows, stores, boundaries
- `threat-model/03-stride.md` — STRIDE, abuse cases, attack chains, ranking
- `REPORT.md` sections 1–4 — scope and 19 formal findings
- `evidence/` — one evidence artifact for each finding

**Definition of done:** another student can reproduce every attack using the
written steps, understand the root cause, and locate the exact baseline code.

## Part 2 — Defend and secure the build

**Question answered:** Does each attack now fail, does legitimate behavior still
work, and can the released artifact be trusted?

1. Work only on `security-remediation`.
2. Fix the Critical/High application findings first: shell/SQL injection,
   authorization, registration roles, JWTs, XSS, password storage, debug mode.
3. Add layered controls: CSRF, rate limiting, cookie flags, security headers,
   audit events, input limits, persistent initialization.
4. Add one regression assertion per finding and run:

   ```bash
   .venv/bin/python -m pytest -q
   ```

5. Update and hash-lock dependencies, then run:

   ```bash
   .venv/bin/bandit -r app.py -lll
   .venv/bin/pip-audit -r requirements.lock --disable-pip
   ```

6. Harden Docker: digest pin, non-root UID, narrow copies, no embedded secret,
   read-only filesystem, dropped capabilities, persistent `/data` volume.
7. Generate and validate `supply-chain/sbom.cdx.json`.
8. Push the branch and confirm every Security CI job passes.
9. Push a `v*` tag. The release workflow builds the image, produces provenance,
   signs `image@digest` keylessly with Cosign, and saves verification evidence.
10. Complete the final video using `script.md`; add its public-view link and the
    CI/Cosign screenshots to `REPORT.md`.

**Part 2 artifacts:** secure code, 21 tests, lockfile, hardened Docker/Compose,
CycloneDX SBOM, two GitHub workflows, release signing/provenance automation,
completed report, and demo script.

**Definition of done:** tests/SAST/SCA/secret/container gates pass; the tagged
image signature and provenance verify; the video shows attack → root cause →
fix; and the report contains links/screenshots from the real GitHub runs.

## Final external steps the repository cannot perform by itself

- Team members confirm the proposed task split in `REPORT.md`.
- Push `security-remediation` and capture the passing Security CI run.
- Create a temporary failing CI demonstration, capture it, then revert it.
- Push a release tag and download `release-security-evidence`.
- Record/upload the demo and paste the viewable link into the report.

