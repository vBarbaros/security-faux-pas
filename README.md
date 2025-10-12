<img src="assets/linkedin-profile-october-2025.png" alt="LinkedIn Profile Header" style="width: 100%; height: 300px; object-fit: cover; object-position: center;">

# security-faux-pas — intentionally *inert* vulnerable examples (educational)

**READ THIS FIRST — DO NOT RUN ANY CODE IN THIS REPOSITORY.**

`security-faux-pas` is a *teaching collection* of intentionally vulnerable code snippets  
stored in **non-runnable** formats (for example, `.example` files or fenced code blocks).

Its goal is to help developers **recognize insecure coding patterns** and learn proper mitigations —  
**not** to provide runnable exploits or proof-of-concept scripts.

---

## 🎯 Purpose

- Highlight **common security mistakes** (“faux pas”) across multiple programming languages.
- Provide **secure fixes** alongside each vulnerable example.
- Map examples to **CWE** and **OWASP Top 10** categories.
- Keep all examples **safe, inert, and educational**.

---

## 📂 Repository structure

```text
security-faux-pas/
├─ README.md
├─ DISCLAIMER.md
├─ CONTRIBUTING.md
├─ vulnerabilities/
│  ├─ typescript/
│  │  ├─ 01-auth-bypass.vuln.example
│  │  ├─ 01-auth-bypass.fix.example
│  │  └─ README.md
│  ├─ c/
│  ├─ java/
│  ├─ python/
│  ├─ node/
│  ├─ php/
│  ├─ ruby/
│  ├─ go/
│  └─ rust/
├─ docs/
│  ├─ howto_read.md
│  └─ mapping.md
└─ .github/
   └─ workflows/
      └─ enforce-nonrunnable.yml
```


## ⚖️ Rules of use
1. **Do not execute any example.** 🚫  
   All `.vuln.example` and `.fix.example` files are deliberately incomplete or contain placeholders.
2. **For learning only.** 📚 Study patterns, discuss mitigations, compare insecure vs secure.
3. **Contributors must follow safety policies.** See `CONTRIBUTING.md`. CI enforces:
   - `INERT — DO NOT RUN` header present,
   - no executable bits / shebangs,
   - no runnable `main` entrypoints.
4. **No exploits/payloads.** ❌ PRs adding them will be rejected.

## 📖 How to use
- Open `vulnerabilities/<language>/*.{vuln,fix}.example` to read insecure pattern and remediation.
- See `docs/mapping.md` for CWE/OWASP references.
- Browse language-specific folders:
  - [🟦 TypeScript examples](vulnerabilities/typescript/README.md)
  - [🐍 Python examples](vulnerabilities/python/README.md)
  - [☕ Java examples](vulnerabilities/java/README.md)

## 🔬 Need runnable labs?
Create a **private, isolated training environment** under supervision.  
This public repo is intentionally inert.

— The `security-faux-pas` Team
