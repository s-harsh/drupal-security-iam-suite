# Changelog — SBOM Sentinel

All notable changes to this module are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] — 2026-06-11

### Added

- Initial release of SBOM Sentinel.
- `SbomGenerator` service: reads `composer.lock`, maps packages to
  `SbomComponent` value objects, and builds CycloneDX 1.6 SBOM documents.
- `OsvApiClient` service: queries `https://api.osv.dev/v1/query` for each
  Composer component using the Packagist ecosystem. Handles
  `ConnectException`, `RequestException`, and `TransferException` gracefully.
- `NisRiskScorer` service: maps CVSS v3 base scores and OSV text severity
  labels to NIS2 Article 21 risk bands (Critical / High / Medium / Low / None).
- `SbomComponent` immutable readonly value object for component identity.
- `CveResult` immutable readonly value object for per-component scan results.
- `SbomReportController`: sortable admin table at
  `/admin/reports/sbom-sentinel` with CVE counts, NIS2 severity badges, max
  CVSS scores, and direct OSV links per component.
- `SbomExportController`: CycloneDX 1.6 JSON and XML download endpoints.
- `SbomSentinelSettingsForm`: admin configuration form with validation.
- `SbomSentinelHooks`: OOP hook implementations via `#[Hook]` attribute —
  `hook_requirements` (status report), `hook_help`, `hook_cron` (weekly scan
  with optional email report).
- `SbomSentinelCommands`: Drush 12 commands `sbom:generate` and `sbom:audit`
  with `--no-cache`, `--output`, `--min-severity`, and `--fail-on` options.
- Config schema and install defaults in `config/`.
- Permissions: `administer sbom sentinel`, `view sbom sentinel report`,
  `export sbom sentinel`.
- Admin menu links under Security (settings) and Reports (risk report).
- Unit tests for `NisRiskScorer`, `OsvApiClient`, `SbomGenerator`, and
  `SbomComponent`.
- Functional tests for the report, export, and settings controllers.
- Playwright E2E test suite covering all major user flows.
- `docs/sbom_sentinel_design.md` and `docs/sbom_sentinel_architecture.md`.
