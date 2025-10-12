# 🟦 TypeScript Security Examples

[← Back to main README](../../README.md)

This folder contains TypeScript-specific security vulnerability examples and their fixes.

## 📋 Examples

### 01 - Authentication Bypass (CVE-2024-31621) 🔓
- **Vulnerable**: [`01-auth-bypass.vuln.example`](01-auth-bypass.vuln.example) ⚠️
- **Fixed**: [`01-auth-bypass.fix.example`](01-auth-bypass.fix.example) ✅
- **CWE**: CWE-178 (Improper Handling of Case Sensitivity)
- **OWASP**: A01:2021 – Broken Access Control
- **Description**: Case-sensitive URL matching allows authentication bypass in Express middleware

### 02 - Prototype Pollution (CVE-2023-26136) 🦠
- **Vulnerable**: [`02-prototype-pollution.vuln.example`](02-prototype-pollution.vuln.example) ⚠️
- **Fixed**: [`02-prototype-pollution.fix.example`](02-prototype-pollution.fix.example) ✅
- **CWE**: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
- **OWASP**: A08:2021 – Software and Data Integrity Failures
- **Description**: Cookie parsing allows __proto__ pollution in tough-cookie library

### 03 - ReDoS Attack (CVE-2022-25883) 💥
- **Vulnerable**: [`03-redos.vuln.example`](03-redos.vuln.example) ⚠️
- **Fixed**: [`03-redos.fix.example`](03-redos.fix.example) ✅
- **CWE**: CWE-1333 (Inefficient Regular Expression Complexity)
- **OWASP**: A06:2021 – Vulnerable and Outdated Components
- **Description**: Catastrophic backtracking in semver package regex causes DoS

### 04 - Command Injection (CVE-2021-23337) 💻
- **Vulnerable**: [`04-command-injection.vuln.example`](04-command-injection.vuln.example) ⚠️
- **Fixed**: [`04-command-injection.fix.example`](04-command-injection.fix.example) ✅
- **CWE**: CWE-94 (Improper Control of Generation of Code)
- **OWASP**: A03:2021 – Injection
- **Description**: Lodash template compilation allows remote code execution

### 05 - Path Traversal (CVE-2020-28469) 📁
- **Vulnerable**: [`05-path-traversal.vuln.example`](05-path-traversal.vuln.example) ⚠️
- **Fixed**: [`05-path-traversal.fix.example`](05-path-traversal.fix.example) ✅
- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **OWASP**: A01:2021 – Broken Access Control
- **Description**: Insufficient path validation in Glob package allows directory traversal

## 📖 Usage

Read the `.vuln.example` files to understand the security flaw, then compare with the corresponding `.fix.example` to see the secure implementation.

**Remember**: All examples are intentionally inert and should never be executed. 🚫
