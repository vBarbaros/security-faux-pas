# Contributing to security-faux-pas

Thank you! Contributions are welcome — under strict safety rules.

## File structure for CVE examples

Each CVE must include **both** vulnerable and fixed examples:

```
vulnerabilities/<language>/
├── CVE-YYYY-NNNNN-<description>.vuln.example
├── CVE-YYYY-NNNNN-<description>.fix.example
└── README.md (updated with new CVE entry)
```

**Naming convention:**
- `CVE-YYYY-NNNNN-<short-description>.vuln.example`
- `CVE-YYYY-NNNNN-<short-description>.fix.example`

## Required for every example

1. **Header format** (first 8 lines):
   ```
   /*
    * INERT — DO NOT RUN
    * 
    * CVE-YYYY-NNNNN: <Vulnerability Title>
    * CWE-XXX: <CWE Description>
    * OWASP: <OWASP Category>
    * 
    * Vulnerability: <Brief description>
    * Source: <Affected software/versions>
    */
   ```

2. **Exit statement** (immediately after header):
   - **Python**: `import sys; sys.exit(-1)`
   - **TypeScript/JavaScript**: `process.exit(-1);`
   - **Java**: `static { System.exit(-1); }` (first line in class)

3. **Safety requirements**:
   - No `#!` shebangs
   - No executable bits set
   - No runnable `main()` functions
   - No working `eval`, `system`, `exec` calls

4. **Documentation**:
   - Update language-specific `README.md`
   - Add CWE/OWASP mapping to `docs/mapping.md`

## PR checklist
- [ ] Both `.vuln.example` and `.fix.example` files created
- [ ] CVE naming convention followed
- [ ] Header includes `INERT — DO NOT RUN` in first 8 lines
- [ ] Exit statement added after header
- [ ] No executable code/shebangs/bits
- [ ] Language README.md updated
- [ ] CWE/OWASP mapping documented

If unsure, open a draft PR and request review.
