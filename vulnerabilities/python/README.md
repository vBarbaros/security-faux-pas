# 🐍 Python Security Examples

[← Back to main README](../../README.md)

This folder contains Python-specific security vulnerability examples and their fixes.

## 📋 Examples

### Pickle Deserialization (CVE-2022-42969) 🥒
- **Vulnerable**: [`CVE-2022-42969-pickle-deserialization.vuln.example`](CVE-2022-42969-pickle-deserialization.vuln.example) ⚠️
- **Fixed**: [`CVE-2022-42969-pickle-deserialization.fix.example`](CVE-2022-42969-pickle-deserialization.fix.example) ✅
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **OWASP**: A08:2021 – Software and Data Integrity Failures
- **Description**: Unsafe pickle deserialization allows arbitrary code execution

### Buffer Overflow (CVE-2021-3177) 💥
- **Vulnerable**: [`CVE-2021-3177-buffer-overflow.vuln.example`](CVE-2021-3177-buffer-overflow.vuln.example) ⚠️
- **Fixed**: [`CVE-2021-3177-buffer-overflow.fix.example`](CVE-2021-3177-buffer-overflow.fix.example) ✅
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)
- **OWASP**: A06:2021 – Vulnerable and Outdated Components
- **Description**: ctypes string_at function buffer overflow in Python core

### CRLF Injection (CVE-2020-26137) 📡
- **Vulnerable**: [`CVE-2020-26137-crlf-injection.vuln.example`](CVE-2020-26137-crlf-injection.vuln.example) ⚠️
- **Fixed**: [`CVE-2020-26137-crlf-injection.fix.example`](CVE-2020-26137-crlf-injection.fix.example) ✅
- **CWE**: CWE-93 (Improper Neutralization of CRLF Sequences)
- **OWASP**: A03:2021 – Injection
- **Description**: HTTP header injection via CRLF sequences in urllib

### XXE Injection (CVE-2019-16935) 🔍
- **Vulnerable**: [`CVE-2019-16935-xxe-injection.vuln.example`](CVE-2019-16935-xxe-injection.vuln.example) ⚠️
- **Fixed**: [`CVE-2019-16935-xxe-injection.fix.example`](CVE-2019-16935-xxe-injection.fix.example) ✅
- **CWE**: CWE-611 (Improper Restriction of XML External Entity Reference)
- **OWASP**: A04:2021 – Insecure Design
- **Description**: XML parser allows external entity processing leading to file disclosure

### Cookie Injection (CVE-2018-20852) 🍪
- **Vulnerable**: [`CVE-2018-20852-cookie-injection.vuln.example`](CVE-2018-20852-cookie-injection.vuln.example) ⚠️
- **Fixed**: [`CVE-2018-20852-cookie-injection.fix.example`](CVE-2018-20852-cookie-injection.fix.example) ✅
- **CWE**: CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
- **OWASP**: A03:2021 – Injection
- **Description**: Cookie values allow CRLF injection in http.cookies module

## 📖 Usage

Read the `.vuln.example` files to understand the security flaw, then compare with the corresponding `.fix.example` to see the secure implementation.

**Remember**: All examples are intentionally inert and should never be executed. 🚫
