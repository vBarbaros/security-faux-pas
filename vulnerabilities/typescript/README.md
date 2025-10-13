# 🟦 TypeScript Security Examples

[← Back to main README](../../README.md)

This folder contains TypeScript-specific security vulnerability examples and their fixes.

## 📋 Examples

### Authentication Bypass (CVE-2024-31621) 🔓
- **Vulnerable**: [`CVE-2024-31621-auth-bypass.vuln.example`](CVE-2024-31621-auth-bypass.vuln.example) ⚠️
- **Fixed**: [`CVE-2024-31621-auth-bypass.fix.example`](CVE-2024-31621-auth-bypass.fix.example) ✅
- **CWE**: CWE-178 (Improper Handling of Case Sensitivity)
- **OWASP**: A01:2021 – Broken Access Control
- **Description**: Case-sensitive URL matching allows authentication bypass in Express middleware

### Prototype Pollution (CVE-2023-26136) 🦠
- **Vulnerable**: [`CVE-2023-26136-prototype-pollution.vuln.example`](CVE-2023-26136-prototype-pollution.vuln.example) ⚠️
- **Fixed**: [`CVE-2023-26136-prototype-pollution.fix.example`](CVE-2023-26136-prototype-pollution.fix.example) ✅
- **CWE**: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
- **OWASP**: A08:2021 – Software and Data Integrity Failures
- **Description**: Cookie parsing allows __proto__ pollution in tough-cookie library

### ReDoS Attack (CVE-2022-25883) 💥
- **Vulnerable**: [`CVE-2022-25883-redos.vuln.example`](CVE-2022-25883-redos.vuln.example) ⚠️
- **Fixed**: [`CVE-2022-25883-redos.fix.example`](CVE-2022-25883-redos.fix.example) ✅
- **CWE**: CWE-1333 (Inefficient Regular Expression Complexity)
- **OWASP**: A06:2021 – Vulnerable and Outdated Components
- **Description**: Catastrophic backtracking in semver package regex causes DoS

### Command Injection (CVE-2021-23337) 💻
- **Vulnerable**: [`CVE-2021-23337-command-injection.vuln.example`](CVE-2021-23337-command-injection.vuln.example) ⚠️
- **Fixed**: [`CVE-2021-23337-command-injection.fix.example`](CVE-2021-23337-command-injection.fix.example) ✅
- **CWE**: CWE-94 (Improper Control of Generation of Code)
- **OWASP**: A03:2021 – Injection
- **Description**: Lodash template compilation allows remote code execution

### Path Traversal (CVE-2020-28469) 📁
- **Vulnerable**: [`CVE-2020-28469-path-traversal.vuln.example`](CVE-2020-28469-path-traversal.vuln.example) ⚠️
- **Fixed**: [`CVE-2020-28469-path-traversal.fix.example`](CVE-2020-28469-path-traversal.fix.example) ✅
- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **OWASP**: A01:2021 – Broken Access Control
- **Description**: Insufficient path validation in Glob package allows directory traversal

## 📖 Usage

Read the `.vuln.example` files to understand the security flaw, then compare with the corresponding `.fix.example` to see the secure implementation.

**Remember**: All examples are intentionally inert and should never be executed. 🚫
