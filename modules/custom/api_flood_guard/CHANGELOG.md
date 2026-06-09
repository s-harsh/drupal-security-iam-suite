# Changelog

All notable changes to API Flood Guard are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 1.0.0 (2026-06-07)

### Added

- Initial release of the API Flood Guard module.
- Per-IP flood control with configurable request threshold and time window
  (defaults: 100 requests / 3600 seconds).
- Per-username flood control with configurable threshold and time window
  (defaults: 20 requests / 900 seconds). Usernames are SHA-256-hashed before
  storage; raw identifiers are never persisted.
- Automatic clearing of per-username flood counters on successful (HTTP 200)
  authentication responses, preventing lockout of legitimate users.
- CIDR-based IP allowlist supporting IPv4 addresses, IPv6 addresses, and
  subnet ranges. Allowlisted IPs bypass all flood and reputation checks.
- Configurable list of protected API paths with `prefix:` and `exact:` match
  modes. Defaults cover `/jsonapi`, `/user/login`, `/oauth/token`, and
  `/rest/user/login`.
- HTML form submission bypass: standard Drupal login form POSTs to
  `/user/login` are excluded from API flood control and handled by Drupal
  core's built-in login flood protection.
- IP reputation plugin system (`IpReputationProviderInterface`,
  `IpReputationProvider` attribute, `IpReputationManager` plugin manager).
- AbuseIPDB v2 IP reputation provider plugin with configurable confidence
  score threshold, maximum report age, and per-IP response caching.
- Key module integration for the AbuseIPDB API key field: API keys can be
  stored in a Key entity instead of plain configuration.
- Fail-open design for reputation providers: network errors, invalid
  credentials, and unexpected API responses are logged as warnings and the
  request proceeds to standard flood checks.
- JSON:API-compatible block response format (`application/vnd.api+json`) when
  the client sends a matching `Accept` header.
- `Retry-After`, `Cache-Control: no-store, no-cache`, and
  `X-Content-Type-Options: nosniff` headers on all block responses.
- Configurable HTTP response code for block responses: 429 (default) or 503.
- Configurable block response message body.
- Admin settings form at `/admin/config/security/api-flood-guard`.
- Flood-state dashboard at
  `/admin/config/security/api-flood-guard/flood-state` showing live IP and
  username flood counters with auto-refresh every 30 seconds and manual
  clear controls.
- Recent block events log page at
  `/admin/config/security/api-flood-guard/log`.
- JSON data endpoint for the flood-state dashboard at
  `/admin/config/security/api-flood-guard/flood-state/data`.
- `administer api flood guard` permission controlling access to all admin
  pages and Drush commands.
- Drush command `api-flood-guard:status` (`afg:status`): display active flood
  entry counts by namespace.
- Drush command `api-flood-guard:clear` (`afg:clear`): clear flood entries
  by IP address, username, or all entries at once.
- Drush command `api-flood-guard:allowlist-add` (`afg:allowlist-add`): add a
  CIDR range or single IP to the allowlist via the command line.
- Drush command `api-flood-guard:test-ip` (`afg:test-ip`): test an IP address
  against the configured reputation provider and display the result.
- `FloodDecision` immutable value object encapsulating the pipeline outcome
  (allowed/blocked, reason, identifier, retry-after seconds).
- `IpReputationResult` immutable value object encapsulating reputation check
  results (score, blocked flag, provider name, cache flag, error flag).
- Optional debug-level logging of every allowed request through a protected
  path (disabled by default).
- Unit and functional test coverage for all services, value objects, event
  subscribers, forms, controller, and plugin classes.
- Drupal 10.4 and Drupal 11 compatibility (`core_version_requirement: ^10.4 || ^11`).
- No third-party PHP library dependencies beyond Drupal core.
