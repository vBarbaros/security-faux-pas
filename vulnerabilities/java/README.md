# ☕ Java Security Examples

[← Back to main README](../../README.md)

This folder contains Java-specific security vulnerability examples and their fixes.

## 📋 Examples

### Log4Shell JNDI Injection (CVE-2021-44228) 🪵
- **Vulnerable**: [`CVE-2021-44228-log4j-jndi.vuln.example`](CVE-2021-44228-log4j-jndi.vuln.example) ⚠️
- **Fixed**: [`CVE-2021-44228-log4j-jndi.fix.example`](CVE-2021-44228-log4j-jndi.fix.example) ✅
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **OWASP**: A06:2021 – Vulnerable and Outdated Components
- **Description**: Log4j JNDI lookup allows remote code execution via malicious LDAP servers

### Spring4Shell RCE (CVE-2022-22965) 🌱
- **Vulnerable**: [`CVE-2022-22965-spring4shell.vuln.example`](CVE-2022-22965-spring4shell.vuln.example) ⚠️
- **Fixed**: [`CVE-2022-22965-spring4shell.fix.example`](CVE-2022-22965-spring4shell.fix.example) ✅
- **CWE**: CWE-94 (Improper Control of Generation of Code)
- **OWASP**: A03:2021 – Injection
- **Description**: Class loader manipulation via Spring data binding leads to RCE

### Java Deserialization RCE (CVE-2021-42013) 🔄
- **Vulnerable**: [`CVE-2021-42013-deserialization.vuln.example`](CVE-2021-42013-deserialization.vuln.example) ⚠️
- **Fixed**: [`CVE-2021-42013-deserialization.fix.example`](CVE-2021-42013-deserialization.fix.example) ✅
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **OWASP**: A08:2021 – Software and Data Integrity Failures
- **Description**: Unsafe deserialization of user data allows arbitrary code execution

### Spring Security Bypass (CVE-2020-5421) 🔐
- **Vulnerable**: [`CVE-2020-5421-auth-bypass.vuln.example`](CVE-2020-5421-auth-bypass.vuln.example) ⚠️
- **Fixed**: [`CVE-2020-5421-auth-bypass.fix.example`](CVE-2020-5421-auth-bypass.fix.example) ✅
- **CWE**: CWE-863 (Incorrect Authorization)
- **OWASP**: A01:2021 – Broken Access Control
- **Description**: RFD attack via filename manipulation bypasses security controls

### Tomcat Command Injection (CVE-2019-0232) 🐱
- **Vulnerable**: [`CVE-2019-0232-command-injection.vuln.example`](CVE-2019-0232-command-injection.vuln.example) ⚠️
- **Fixed**: [`CVE-2019-0232-command-injection.fix.example`](CVE-2019-0232-command-injection.fix.example) ✅
- **CWE**: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **OWASP**: A03:2021 – Injection
- **Description**: CGI servlet allows command injection on Windows systems

## 📖 Usage

Read the `.vuln.example` files to understand the security flaw, then compare with the corresponding `.fix.example` to see the secure implementation.

**Remember**: All examples are intentionally inert and should never be executed. 🚫
