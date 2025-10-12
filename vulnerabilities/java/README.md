# ☕ Java Security Examples

[← Back to main README](../../README.md)

This folder contains Java-specific security vulnerability examples and their fixes.

## 📋 Examples

### 01 - Log4Shell JNDI Injection (CVE-2021-44228) 🪵
- **Vulnerable**: [`01-log4j-jndi.vuln.example`](01-log4j-jndi.vuln.example) ⚠️
- **Fixed**: [`01-log4j-jndi.fix.example`](01-log4j-jndi.fix.example) ✅
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **OWASP**: A06:2021 – Vulnerable and Outdated Components
- **Description**: Log4j JNDI lookup allows remote code execution via malicious LDAP servers

### 02 - Spring4Shell RCE (CVE-2022-22965) 🌱
- **Vulnerable**: [`02-spring4shell.vuln.example`](02-spring4shell.vuln.example) ⚠️
- **Fixed**: [`02-spring4shell.fix.example`](02-spring4shell.fix.example) ✅
- **CWE**: CWE-94 (Improper Control of Generation of Code)
- **OWASP**: A03:2021 – Injection
- **Description**: Class loader manipulation via Spring data binding leads to RCE

### 03 - Java Deserialization RCE (CVE-2021-42013) 🔄
- **Vulnerable**: [`03-deserialization.vuln.example`](03-deserialization.vuln.example) ⚠️
- **Fixed**: [`03-deserialization.fix.example`](03-deserialization.fix.example) ✅
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **OWASP**: A08:2021 – Software and Data Integrity Failures
- **Description**: Unsafe deserialization of user data allows arbitrary code execution

### 04 - Spring Security Bypass (CVE-2020-5421) 🔐
- **Vulnerable**: [`04-auth-bypass.vuln.example`](04-auth-bypass.vuln.example) ⚠️
- **Fixed**: [`04-auth-bypass.fix.example`](04-auth-bypass.fix.example) ✅
- **CWE**: CWE-863 (Incorrect Authorization)
- **OWASP**: A01:2021 – Broken Access Control
- **Description**: RFD attack via filename manipulation bypasses security controls

### 05 - Tomcat Command Injection (CVE-2019-0232) 🐱
- **Vulnerable**: [`05-command-injection.vuln.example`](05-command-injection.vuln.example) ⚠️
- **Fixed**: [`05-command-injection.fix.example`](05-command-injection.fix.example) ✅
- **CWE**: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **OWASP**: A03:2021 – Injection
- **Description**: CGI servlet allows command injection on Windows systems

## 📖 Usage

Read the `.vuln.example` files to understand the security flaw, then compare with the corresponding `.fix.example` to see the secure implementation.

**Remember**: All examples are intentionally inert and should never be executed. 🚫
