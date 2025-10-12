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

## 📖 Usage

Read the `.vuln.example` files to understand the security flaw, then compare with the corresponding `.fix.example` to see the secure implementation.

**Remember**: All examples are intentionally inert and should never be executed. 🚫
