# Security Policy

## Supported Versions

| Module Version | Drupal Core | Supported |
|---------------|-------------|-----------|
| 1.x | 11.x / 10.4+ | ✅ Active |
| dev | 11.x | ⚠️ Development only |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

This repository contains security-sensitive modules. Responsible disclosure protects the entire Drupal community.

### How to Report

1. **Email**: harshvardhan.soni@xecurify.com
   - Subject line: `[SECURITY] drupal-security-iam-suite: <brief description>`
   - PGP key available on request

2. **Include in your report**:
   - Affected module name and version
   - Type of vulnerability (XSS, CSRF, privilege escalation, etc.)
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Within 30 days (critical: 7 days) |
| Public disclosure | After fix released + 7-day grace period |

---

## Security Design Principles

All modules in this suite are built with:

- **Defence in depth**: Multiple security layers
- **Least privilege**: Minimal permissions required
- **Fail secure**: On error, deny access rather than allow
- **Input validation**: All user input validated at system boundaries
- **Output encoding**: All output encoded to prevent XSS
- **Parameterized queries**: Never string-concatenated SQL
- **No eval()**: PHP code execution vectors blocked
- **Audit logging**: Security events logged to Drupal watchdog

---

## Security Advisory Process

This project follows the [Drupal Security Advisory Policy](https://www.drupal.org/drupal-security-team/security-team-procedures) principles:

- CVEs will be requested for confirmed vulnerabilities
- Fixes will be available before public disclosure
- Security releases will be tagged separately from feature releases

---

## Hall of Fame

We acknowledge security researchers who responsibly disclose vulnerabilities. If you'd like to be listed here after a fix is released, please let us know in your report.

| Researcher | Vulnerability | Module | Fixed In |
|-----------|--------------|--------|---------|
| — | — | — | — |
