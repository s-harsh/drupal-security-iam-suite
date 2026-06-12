# SBOM Sentinel

Supply chain security for Drupal — NIS2 Article 21 compliance.

## Overview

SBOM Sentinel generates [CycloneDX 1.6](https://cyclonedx.org/specification/overview/)
Software Bill of Materials (SBOM) documents from your Drupal installation's
`composer.lock`, queries each component against [OSV.dev](https://osv.dev/)
for known CVEs, and computes NIS2 Article 21 risk scores.

## Features

- **CycloneDX 1.6 SBOM generation** — reads `composer.lock` and maps every
  Composer package to a fully-formed CycloneDX component with PURL, licence,
  and source URL.
- **OSV.dev CVE scanning** — queries `https://api.osv.dev/v1/query` for each
  component using the Packagist ecosystem. Results are cached to avoid
  hammering the API on every page visit.
- **NIS2 risk scoring** — maps CVSS v3 base scores (and text severity labels)
  to four risk bands: Critical / High / Medium / Low, per NIS2 Article 21.
- **Admin risk report** — sortable table at
  `/admin/reports/sbom-sentinel` showing CVE counts, NIS2 severity badges, max
  CVSS scores, and direct OSV links.
- **Export** — download the SBOM as CycloneDX 1.6 JSON or XML from the report
  page or via direct URLs.
- **Drush commands** — `drush sbom:generate` and `drush sbom:audit` for CLI
  usage and CI/CD pipeline integration.
- **Weekly cron scan** — optional automated weekly scan with configurable
  email report to the site administrator.

## Requirements

- Drupal 11 (or 10.4+)
- PHP 8.2+
- `guzzlehttp/guzzle` ^7.0 (included with Drupal core)

## Installation

```bash
composer require drupal/sbom_sentinel
drush en sbom_sentinel
drush cr
```

## Configuration

Navigate to **Administration > Configuration > Security > SBOM Sentinel**
(`/admin/config/security/sbom-sentinel`) to configure:

| Setting | Default | Description |
|---------|---------|-------------|
| `enabled` | `true` | Global on/off switch |
| `composer_lock_path` | `../composer.lock` | Path to `composer.lock` relative to Drupal root |
| `osv_api_base_url` | `https://api.osv.dev/v1` | OSV.dev API base URL |
| `http_timeout` | `10` | HTTP request timeout in seconds (1–60) |
| `scan_cache_ttl` | `3600` | Scan result cache TTL in seconds (0 = disabled) |
| `cron_enabled` | `true` | Run a fresh scan weekly via cron |
| `email_report_enabled` | `false` | Send an email summary after each cron scan |
| `email_recipient` | `` | Email address for cron reports (blank = site email) |

## Drush Commands

### `drush sbom:generate`

Generates the CycloneDX SBOM and prints a summary.

```bash
# Print summary
drush sbom:generate

# Write JSON to a file
drush sbom:generate --output=/tmp/sbom.json

# Bypass cache
drush sbom:generate --no-cache
```

### `drush sbom:audit`

Runs the full OSV.dev vulnerability scan and reports CVE findings. Exits
non-zero when findings meet or exceed `--fail-on` severity (useful in CI/CD).

```bash
# Audit all components
drush sbom:audit

# Fresh scan, fail CI on any critical finding
drush sbom:audit --no-cache --fail-on=critical

# Report only high+ findings
drush sbom:audit --min-severity=high
```

## NIS2 Risk Levels

| CVSS v3 Score | NIS2 Band |
|---------------|-----------|
| >= 9.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.1 – 3.9 | Low |
| None found | None |

Text-based severity labels (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`) from OSV's
`database_specific.severity` field are also mapped when CVSS scores are absent.

## Export Format

Exports conform to the [CycloneDX 1.6 specification](https://cyclonedx.org/docs/1.6/json/).

Each component includes:
- `bom-ref`, `name`, `version`, `purl`
- `licenses` (SPDX IDs)
- `externalReferences` (VCS source URL)
- `properties` with NIS2 risk level, CVE count, and max CVSS score

Vulnerabilities reference their source component via the `affects[].ref` field.

## Security Notes

- The OSV API client logs only exception class names and HTTP status codes —
  never package version strings in association with user identifiers.
- Scan results are stored in Drupal's cache bin, not in a custom database table,
  to avoid sensitive vulnerability data proliferating across the database.
- Export endpoints require the `export sbom sentinel` permission (restricted
  access by default).

## Running Tests

```bash
# Unit tests
phpunit modules/custom/sbom_sentinel/tests/src/Unit/

# Functional tests (requires full Drupal test environment)
phpunit modules/custom/sbom_sentinel/tests/src/Functional/

# Playwright E2E tests (requires running Drupal)
npx playwright test playwright/sbom_sentinel.spec.js
```

## Maintainers

- s-harsh (Miniorange Software Security)
