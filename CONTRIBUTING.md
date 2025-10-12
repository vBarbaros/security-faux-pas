# Contributing to security-faux-pas

Thank you! Contributions are welcome — under strict safety rules.

## Required for every example
1. File names:
    - `*.vuln.example` for the vulnerable snippet (inert).
    - `*.fix.example` for the remediation snippet (inert).
2. Do **not** add any directly executable file:
    - No `#!` shebangs.
    - No intact `main()`/entrypoints that compile/run.
    - No scripts that call `eval`, `system`, `exec`, or shells in working form.
    - No binaries; no files with the executable bit set.
3. Each example begins with a header in the **first 8 lines**:
    - Title, language, **CWE**, **OWASP** (if applicable).
    - The line: `STATUS: INERT — DO NOT RUN`
    - One-sentence rationale for why it’s insecure (for `*.vuln.example`) or how it’s mitigated (for `*.fix.example`).
4. Update the per-language `README.md`:
    - Note that examples are inert, how to **read** them, and mitigations/references.
5. Tests: **non-executable checks only** (e.g., lint that verifies headers present).  
   No PoC automation or exploitation.

## PR checklist
- [ ] Files use `.vuln.example` / `.fix.example` extensions.
- [ ] Header includes `INERT — DO NOT RUN` within first 8 lines.
- [ ] No shebangs / no executable bits / no runnable `main`.
- [ ] Per-language README updated.
- [ ] CWE/OWASP mapping included (and `docs/mapping.md` updated if needed).

If unsure, open a draft PR and request review.
