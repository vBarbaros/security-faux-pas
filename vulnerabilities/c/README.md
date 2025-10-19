# C Security Examples

**⚠️ ALL FILES ARE INERT — DO NOT COMPILE OR RUN**

This directory contains educational examples of security vulnerabilities in C code and their secure fixes.

## Examples

### CVE-2024-6387: OpenSSH RegreSSHion Signal Handler Race Condition
- **Vulnerable**: `CVE-2024-6387-signal-race.vuln.example`
- **Secure Fix**: `CVE-2024-6387-signal-race.fix.example`
- **Issue**: Async-signal-unsafe functions in SIGALRM handler
- **Impact**: Remote code execution as root
- **Fix**: Proper signal handling with async-signal-safe operations

## Key Security Principles

1. **Signal Safety**: Only use async-signal-safe functions in signal handlers
2. **Race Conditions**: Avoid shared resource access without proper synchronization
3. **Thread Safety**: Use proper locking mechanisms for concurrent access
4. **Input Validation**: Always validate and sanitize user inputs

## References

- [CWE-362: Race Conditions](https://cwe.mitre.org/data/definitions/362.html)
- [Signal Safety (POSIX)](https://man7.org/linux/man-pages/man7/signal-safety.7.html)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
