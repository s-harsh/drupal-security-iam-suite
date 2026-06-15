# SBOM Sentinel — Architecture Document

## Module Layout

```
sbom_sentinel/
├── sbom_sentinel.info.yml          Module metadata
├── sbom_sentinel.module            Near-empty; declare(strict_types=1) only
├── sbom_sentinel.services.yml      DI service definitions
├── sbom_sentinel.routing.yml       Four admin routes
├── sbom_sentinel.permissions.yml   Three permissions
├── sbom_sentinel.links.menu.yml    Admin menu links
├── drush.services.yml              Drush command registration
├── sbom_sentinel.drush.yml         Drush path discovery
├── composer.json                   Package manifest
├── config/
│   ├── install/sbom_sentinel.settings.yml   Install-time defaults
│   └── schema/sbom_sentinel.schema.yml      Config schema
└── src/
    ├── Hook/
    │   └── SbomSentinelHooks.php   hook_requirements, hook_help, hook_cron
    ├── Service/
    │   ├── SbomGenerator.php       Orchestration layer
    │   ├── OsvApiClient.php        OSV.dev HTTP wrapper
    │   └── NisRiskScorer.php       CVSS → NIS2 risk band mapper
    ├── Controller/
    │   ├── SbomReportController.php    Admin risk report table
    │   └── SbomExportController.php    JSON / XML download endpoints
    ├── Form/
    │   └── SbomSentinelSettingsForm.php  ConfigFormBase settings form
    ├── Drush/Commands/
    │   └── SbomSentinelCommands.php     sbom:generate, sbom:audit
    └── Value/
        ├── SbomComponent.php   Immutable component value object
        └── CveResult.php       Immutable per-component scan result
```

---

## Service Graph

```
sbom_sentinel.hooks
    └── sbom_sentinel.sbom_generator
            ├── sbom_sentinel.osv_api_client
            │       ├── http_client (Drupal core Guzzle)
            │       ├── config.factory
            │       └── logger.channel.sbom_sentinel
            ├── sbom_sentinel.nis_risk_scorer  (no deps)
            ├── config.factory
            ├── cache.sbom_sentinel
            └── logger.channel.sbom_sentinel

SbomReportController     → sbom_sentinel.sbom_generator
SbomExportController     → sbom_sentinel.sbom_generator
SbomSentinelSettingsForm → config.factory  (via ConfigFormBase)
SbomSentinelCommands     → sbom_sentinel.sbom_generator, config.factory
```

---

## Data Flow

### 1. Report Page (`GET /admin/reports/sbom-sentinel`)

```
Browser
  → SbomReportController::reportPage()
      → SbomGenerator::getCachedResults()   [check cache.sbom_sentinel]
         ↓ cache miss
      → SbomGenerator::scan()
          → SbomGenerator::parseComposerLock()
              → file_get_contents(composer.lock)
              → JSON decode
              → [SbomComponent, ...]
          → foreach SbomComponent:
              → OsvApiClient::queryComponent()
                  → GuzzleHTTP POST api.osv.dev/v1/query
                  → return ['success', 'vulnerabilities', 'error_message']
              → NisRiskScorer::computeRiskLevel(vulnerabilities)
              → NisRiskScorer::maxCvssScore(vulnerabilities)
              → new CveResult(...)
          → SbomGenerator::buildCycloneDxDocument()
          → cache.sbom_sentinel::set()
      → render table of CveResults
  ← Drupal render array
```

### 2. Export (`GET /admin/reports/sbom-sentinel/export/json`)

```
Browser
  → SbomExportController::exportJson()
      → SbomGenerator::getCachedResults()
         ↓ cache hit (reuse existing scan)
      → json_encode($sbom, JSON_PRETTY_PRINT)
  ← Response (application/vnd.cyclonedx+json, Content-Disposition: attachment)
```

### 3. Cron (`hook_cron`)

```
Drupal cron
  → SbomSentinelHooks::cron()
      → check State API: last run < 7 days ago?
      → SbomGenerator::scan(bypassCache: TRUE)
      → State API: set last_cron_run = now
      → [optional] plugin.manager.mail::mail('sbom_sentinel', 'cron_report', ...)
```

### 4. Drush `sbom:audit`

```
CLI: drush sbom:audit --no-cache --fail-on=critical
  → SbomSentinelCommands::audit()
      → SbomGenerator::scan(bypassCache: TRUE)
      → filter CveResults by --min-severity
      → print table to STDOUT
      → if any result >= --fail-on: throw RuntimeException (exit 1)
```

---

## Value Objects

### `SbomComponent` (immutable readonly)

Represents a single Composer package entry:

| Property | Type | Source |
|----------|------|--------|
| `name` | `string` | `composer.lock` → `packages[].name` |
| `version` | `string` | normalised (v-prefix stripped) |
| `type` | `string` | `packages[].type` |
| `description` | `string` | `packages[].description` |
| `purl` | `string` | `pkg:composer/{name}@{version}` |
| `bomRef` | `string` | `md5(name@version)` |
| `licenses` | `string[]` | `packages[].license` |
| `sourceUrl` | `string` | `packages[].source.url` |

### `CveResult` (immutable readonly)

Represents the OSV.dev scan result for one component:

| Property | Type | Meaning |
|----------|------|---------|
| `packageName` | `string` | Matches `SbomComponent::name` |
| `packageVersion` | `string` | Matches `SbomComponent::version` |
| `apiError` | `bool` | TRUE on OSV API failure |
| `errorMessage` | `string` | Exception class or HTTP status |
| `vulnerabilities` | `array` | Raw OSV vulnerability objects |
| `nisRiskLevel` | `string` | 'critical'/'high'/'medium'/'low'/'none' |
| `maxCvssScore` | `float` | Highest CVSS v3 base score |

---

## NIS2 Risk Scoring Logic

`NisRiskScorer` applies the following priority order when extracting a score
from an OSV vulnerability object:

1. `database_specific.cvss_v3` (float) — used by GHSA-sourced records.
2. `database_specific.cvss` (float) — alternative key.
3. `severity[].score` where `type` is `CVSS_V3` or `CVSS_V4` — parsed for a
   leading `N.N ` score prefix.
4. `database_specific.severity` (text label) — converted to a midpoint score.
5. `affected[].ecosystem_specific.severity` (text label) — fallback.

The worst (highest) level across all vulnerabilities for a component is
returned. This ensures the risk badge reflects the real worst-case exposure.

---

## CycloneDX 1.6 Compliance Notes

The generated SBOM uses:

- `bomFormat: "CycloneDX"` and `specVersion: "1.6"`.
- A UUID v4 `serialNumber` (generated with `random_bytes(16)`).
- `metadata.tools[0]` identifying the module as the generating tool.
- `purl` in `pkg:composer/{vendor}/{name}@{version}` format per
  [PURL spec](https://github.com/package-url/purl-spec).
- `properties` for non-standard NIS2 metadata (prefixed `sbom_sentinel:`).
- `vulnerabilities[].affects[].ref` pointing to `component.bom-ref`.
- XML export uses PHP `DOMDocument` with the namespace
  `http://cyclonedx.org/schema/bom/1.6`.

---

## Caching Strategy

| Layer | Key | TTL | Purpose |
|-------|-----|-----|---------|
| `cache.sbom_sentinel` | `sbom_sentinel.scan_results` | Configurable (default 3600 s) | Full scan output including SBOM document and all CveResult objects |

A single cache entry stores the entire scan output. This keeps the cache
simple and avoids per-component cache stampedes during peak traffic. The TTL
is deliberately short (1 hour default) to ensure relatively current CVE data
on active sites. The cron job bypasses the cache to always store fresh results.

---

## Permissions

| Permission | Used by | Description |
|------------|---------|-------------|
| `administer sbom sentinel` | Settings form route | Configure module settings |
| `view sbom sentinel report` | Report controller | Read-only risk report access |
| `export sbom sentinel` | Export controllers | Download CycloneDX SBOM files |

All three permissions have `restrict access: true` to prevent accidental
assignment to non-administrative roles.

---

## Extension Points

The architecture supports the following future extensions without breaking
changes:

- **Additional ecosystems** — `OsvApiClient::queryComponent()` currently
  hard-codes `Packagist`. A `$ecosystem` parameter can be added to support
  npm, PyPI, etc., when Drupal's JavaScript/Python dependencies are tracked.
- **Signed SBOMs** — `SbomExportController` can be extended to pass the
  document through a signing service before streaming the download.
- **Historical scans** — `SbomGenerator::scan()` can write each result to a
  custom entity/database table in addition to the cache, enabling diff reports.
- **Email template** — the `cron_report` mail key enables a custom
  `hook_mail()` template with full HTML formatting.
