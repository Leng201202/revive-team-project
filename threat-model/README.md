# Threat model — NoteVault (REVIVE)

Threat-model artifacts for the term project, covering the baseline NoteVault
application (`../app.py`, `../Dockerfile`, `../docker-compose.yml`).

**Read in this order** — each layer adds formality on top of the same findings:

| Step | File | Contents |
|---|---|---|
| 1 | [`01-problems.md`](01-problems.md) | Every problem explained in plain language first, then mapped to DFD/STRIDE/week/CWE/OWASP — start here |
| 2 | [`02-dataflow.md`](02-dataflow.md) | Data-flow diagram (Mermaid): external entities, processes, data stores, data flows, trust boundaries |
| 3 | [`03-stride.md`](03-stride.md) | STRIDE-per-element analysis, abuse cases, attack chains, top 5 ranked risks |

Sections 2–3 of [`../REPORT.md`](../REPORT.md) summarise the same material in
the required report format. For the PDF report, render the Mermaid diagram to
an image (e.g. <https://mermaid.live>) and insert it.
