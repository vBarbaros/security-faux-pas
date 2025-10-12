# 🐍 Python Security Examples

[← Back to main README](../../README.md)

This folder contains Python-specific security vulnerability examples and their fixes.

## 📋 Examples

### 01 - Pickle Deserialization (CVE-2022-42969) 🥒
- **Vulnerable**: [`01-pickle-deserialization.vuln.example`](01-pickle-deserialization.vuln.example) ⚠️
- **Fixed**: [`01-pickle-deserialization.fix.example`](01-pickle-deserialization.fix.example) ✅
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **OWASP**: A08:2021 – Software and Data Integrity Failures
- **Description**: Unsafe pickle deserialization allows arbitrary code execution

### 02 - Buffer Overflow (CVE-2021-3177) 💥
- **Vulnerable**: [`02-buffer-overflow.vuln.example`](02-buffer-overflow.vuln.example) ⚠️
- **Fixed**: [`02-buffer-overflow.fix.example`](02-buffer-overflow.fix.example) ✅
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)
- **OWASP**: A06:2021 – Vulnerable and Outdated Components
- **Description**: ctypes string_at function buffer overflow in Python core

### 03 - CRLF Injection (CVE-2020-26137) 📡
- **Vulnerable**: [`03-crlf-injection.vuln.example`](03-crlf-injection.vuln.example) ⚠️
- **Fixed**: [`03-crlf-injection.fix.example`](03-crlf-injection.fix.example) ✅
- **CWE**: CWE-93 (Improper Neutralization of CRLF Sequences)
- **OWASP**: A03:2021 – Injection
- **Description**: HTTP header injection via CRLF sequences in urllib

### 04 - XXE Injection (CVE-2019-16935) 🔍
- **Vulnerable**: [`04-xxe-injection.vuln.example`](04-xxe-injection.vuln.example) ⚠️
- **Fixed**: [`04-xxe-injection.fix.example`](04-xxe-injection.fix.example) ✅
- **CWE**: CWE-611 (Improper Restriction of XML External Entity Reference)
- **OWASP**: A04:2021 – Insecure Design
- **Description**: XML parser allows external entity processing leading to file disclosure

### 05 - Cookie Injection (CVE-2018-20852) 🍪
- **Vulnerable**: [`05-cookie-injection.vuln.example`](05-cookie-injection.vuln.example) ⚠️
- **Fixed**: [`05-cookie-injection.fix.example`](05-cookie-injection.fix.example) ✅
- **CWE**: CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
- **OWASP**: A03:2021 – Injection
- **Description**: Cookie values allow CRLF injection in http.cookies module

## 📖 Usage

Read the `.vuln.example` files to understand the security flaw, then compare with the corresponding `.fix.example` to see the secure implementation.

**Remember**: All examples are intentionally inert and should never be executed. 🚫
