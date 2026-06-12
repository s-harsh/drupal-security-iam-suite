# SBOM Sentinel — Design Document

## Purpose

SBOM Sentinel provides NIS2 Article 21 supply chain security compliance for
Drupal 11 installations. It answers the question: *which of my installed
Composer packages have known CVEs, and how severe are they?*

The module covers three core NIS2 Article 21(2)(e) requirements:

1. **Software inventory** — a machine-readable SBOM in the industry-standard
   CycloneDX 1.6 format.
2. **Vulnerability disclosure** — per-component CVE lookup via OSV.dev.
3. **Risk classification** — CVSS-based severity banding aligned with NIS2
   terminology (Critical / High / Medium / Low).

---

## Functional Requirements

### FR-1: SBOM Generation

- Parse `composer.lock` from a configurable path.
- Include both `packages` and `packages-dev` entries.
- Generate a CycloneDX 1.6 JSON document with:
  - `bomFormat`, `specVersion`, `serialNumber` (UUID v4), `version`,
    `metadata.timestamp`, `metadata.tools`.
  - One `component` element per package containing `type`, `bom-ref`,
    `name`, `version`, `description`, `purl` (pkg:composer/…), `licenses`,
    `externalReferences` (VCS URL), and `properties` for NIS2 metadata.
  - A `vulnerabilities` array referencing affected components.

### FR-2: OSV.dev Vulnerability Scanning

- POST to `https://api.osv.dev/v1/query` for each component.
- Use the `Packagist` ecosystem and the package name and version.
- Handle HTTP errors, network failures, and invalid JSON gracefully.
- Cache scan results for a configurable TTL (default: 3600 s).
- Expose `--no-cache` flag in Drush commands to force re-scan.

### FR-3: NIS2 Risk Scoring

- Map CVSS v3 base scores to risk bands:
  - Critical: >= 9.0
  - High: 7.0–8.9
  - Medium: 4.0–6.9
  - Low: 0.1–3.9
  - None: no vulnerabilities
- Fall back to OSV text severity labels (`CRITICAL`, `HIGH`, `MODERATE`,
  `MEDIUM`, `LOW`) when CVSS scores are absent.
- Use the highest severity across all vulnerabilities for a component.

### FR-4: Admin Risk Report

- Render at `/admin/reports/sbom-sentinel`.
- Sortable table by: package name, version, CVE count, NIS2 risk, CVSS score.
- NIS2 severity badges using Drupal message CSS classes (error/warning/status).
- Hyperlinks to OSV vulnerability records (https://osv.dev/vulnerability/{id}).
- Summary line: total components scanned, vulnerable count, scan timestamp.
- Links to JSON and XML export endpoints.
- Permission: `view sbom sentinel report`.

### FR-5: SBOM Export

- JSON: `application/vnd.cyclonedx+json`, filename `sbom-YYYY-MM-DD.cdx.json`.
- XML: `application/vnd.cyclonedx+xml`, filename `sbom-YYYY-MM-DD.cdx.xml`.
  - XML uses the CycloneDX 1.6 namespace
    `http://cyclonedx.org/schema/bom/1.6`.
  - Generated with PHP's `DOMDocument` for correctness.
- Both reuse the cached scan data; trigger a fresh scan only when no cache exists.
- Permission: `export sbom sentinel`.

### FR-6: Drush Commands

**`drush sbom:generate`**
- Options: `--output=<path>`, `--no-cache`.
- Prints format, spec version, serial number, component count, generation time.
- Writes JSON to `--output` path when provided.

**`drush sbom:audit`**
- Options: `--no-cache`, `--min-severity=<level>`, `--fail-on=<level>`.
- Prints a summary table of vulnerable components above `--min-severity`.
- Exits non-zero (throws `RuntimeException`) when findings reach `--fail-on`
  severity, suitable for CI/CD pipeline gates.

### FR-7: Weekly Cron Scan

- `hook_cron` fires at most once every 7 days (604 800 s).
- Stores last-run timestamp in Drupal State API.
- Optionally emails a scan summary to the configured recipient or the site
  email address.
- Email uses `plugin.manager.mail` with module key `cron_report`.

### FR-8: Status Report Integration

- `hook_requirements` reports the number of vulnerable components and the
  highest NIS2 risk level on the Drupal status report page.
- Severity mapping: Critical/High → `REQUIREMENT_ERROR`,
  Medium/Low → `REQUIREMENT_WARNING`, clean → `REQUIREMENT_OK`.

---

## Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| Drupal compatibility | Core 11 (10.4+ also supported) |
| PHP | 8.2+, strict types everywhere |
| HTTP | Guzzle 7 via Drupal's `http_client` service |
| Caching | Module-specific `cache.sbom_sentinel` bin |
| Permissions | Three distinct, restricted-access permissions |
| Coding standards | Drupal 11 OOP hooks, PSR-4, constructor DI |
| Logging | Module channel `logger.channel.sbom_sentinel` |
| No external JS | Pure server-side rendering; no custom assets |

---

## Out of Scope (v1.0)

- SBOM signing / attestation (CycloneDX attestation profile).
- VEX (Vulnerability Exploitability eXchange) statements.
- Integration with other SCA tools (Snyk, Dependabot).
- Historical scan tracking / diff between scans.
- Per-component remediation advice.
- SBOM ingestion from submodules (nested composer.json).
