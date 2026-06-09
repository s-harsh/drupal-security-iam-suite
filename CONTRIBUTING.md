# Contributing to Drupal Security & IAM Module Suite

Thank you for your interest in contributing! This suite is an open-source collection of security and IAM modules for Drupal 11 / Drupal CMS 2.0.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Branching Strategy](#branching-strategy)
- [Commit Convention](#commit-convention)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Getting Started

### Prerequisites
- PHP 8.2+
- Composer
- Drupal 11.x or 10.4+ development environment
- Node.js 18+ (for Playwright tests)

### Setup

```bash
# Clone the repository
git clone https://github.com/s-harsh/drupal-security-iam-suite.git
cd drupal-security-iam-suite

# Install a module's dependencies
cd modules/custom/hibp_password_guard
composer install

# Install Playwright for UI tests
npm install
npx playwright install
```

---

## Branching Strategy

We follow **Gitflow**:

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready, tagged releases only |
| `develop` | Integration branch — all features merge here first |
| `feature/{module-name}` | New module or major feature |
| `fix/{issue-number}-description` | Bug fixes |
| `hotfix/{description}` | Critical production fixes |
| `release/{version}` | Release preparation |

### Branch Rules
- `main` requires PR + 1 review + all CI checks passing
- `develop` requires PR + all CI checks passing
- Direct commits to `main` or `develop` are blocked

---

## Commit Convention

We use **Conventional Commits** (https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | When to use |
|------|------------|
| `feat` | New feature or module |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `refactor` | Code change with no feature/fix |
| `perf` | Performance improvement |
| `chore` | Build process, tooling, dependencies |
| `security` | Security fix (non-breaking) |
| `ci` | CI/CD configuration changes |

### Examples

```
feat(hibp-password-guard): add breached password detection via HIBP k-anonymity API

Implements NIST SP 800-63B-4 requirement for checking passwords against
breach corpuses. Uses SHA-1 k-anonymity so no plaintext ever leaves the server.

Closes #12
```

```
fix(api-flood-guard): correct IPv6 address normalization in flood key

The flood key was including full IPv6 addresses instead of /64 prefixes,
causing the same subnet to spawn multiple flood entries.

Fixes #47
```

---

## Pull Request Process

1. **Branch** from `develop` (or `main` for hotfixes)
2. **Follow** the commit convention
3. **Write tests** — new code must have ≥80% coverage
4. **Update** relevant documentation
5. **Fill** the PR template completely
6. **Pass** all CI checks (CodeSniffer, PHPStan level 6, PHPUnit, Playwright)
7. **Request** review from a maintainer

---

## Coding Standards

All PHP code must comply with:

- **Drupal Coding Standards**: https://www.drupal.org/docs/develop/standards
- **PHP 8.2+**: Use typed properties, readonly, enums, named arguments
- **Drupal 11 OOP Hooks**: Use `#[Hook]` attribute, not procedural `hook_*` functions
- **Constructor DI**: Never call `\Drupal::service()` inside class methods
- **strict_types=1** on every PHP file

### Automated Checks

```bash
# PHP CodeSniffer (Drupal standard)
./vendor/bin/phpcs --standard=Drupal,DrupalPractice modules/custom/[module_name]/src/

# PHPStan (level 6)
./vendor/bin/phpstan analyse modules/custom/[module_name]/src/ --level=6

# PHPUnit
./vendor/bin/phpunit modules/custom/[module_name]/tests/
```

---

## Testing Requirements

Every module must have:

| Test Type | Location | Framework | Minimum |
|-----------|----------|-----------|---------|
| Unit tests | `tests/src/Unit/` | PHPUnit 10 | All services |
| Functional tests | `tests/src/Functional/` | BrowserTestBase | All admin forms |
| UI tests | `playwright/` | Playwright 1.60+ | Key user flows |

### Running Playwright Tests

```bash
# Requires a running Drupal 11 instance at http://localhost
npx playwright test playwright/[module_name].spec.js
```

---

## Security Vulnerabilities

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please follow our [Security Policy](SECURITY.md) and report privately via email: harshvardhan.soni@xecurify.com

We follow responsible disclosure — you'll receive a response within 48 hours.

---

## Module Development Guide

Each module in this suite must:

1. Work on **Drupal 11.x** and **Drupal CMS 2.0**
2. Include a `composer.json` with `"type": "drupal-module"`
3. Follow PSR-4 autoloading under `src/`
4. Include config schema in `config/schema/`
5. Have a `hook_requirements()` implementation for the status report
6. Be covered by a README with installation and configuration docs
7. Have no deprecated Drupal API usage

---

## Questions?

Open a [Discussion](https://github.com/s-harsh/drupal-security-iam-suite/discussions) — we're happy to help!
