# Changelog

All notable changes to HIBP Password Guard will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 1.0.0 (2026-06-07)

### Added

- Initial release of the HIBP Password Guard module.
- `HibpPasswordCheckerService` -- orchestrates the full check pipeline: SHA-1
  hashing, cache lookup, HIBP API call, CRLF response parsing, suffix matching,
  and fail-mode resolution.
- `HibpApiClient` -- low-level Guzzle wrapper for the HIBP Pwned Passwords
  Range API (`GET /range/{PREFIX}`). Sends the `Add-Padding: true` header.
  Returns a typed `HibpRangeResponse` value object.
- `HibpCheckResult` and `HibpRangeResponse` -- immutable `final readonly`
  value objects decoupling the HTTP transport layer from business logic.
- `HibpCompromised` Password Policy constraint plugin (plugin ID:
  `hibp_compromised`, label: "Not Pwned Password"). Integrates with
  `drupal/password_policy ^4.0`.
- Administration settings form at
  `/admin/config/security/hibp-password-guard` exposing five configuration
  keys: `enabled`, `cache_ttl`, `fail_mode`, `http_timeout`, `api_base_url`.
- Dedicated cache bin `cache.hibp_password_guard` for storing range response
  bodies keyed by SHA-1 prefix. Default TTL: 86400 seconds (24 hours).
- Configurable degradation mode: `fail_open` (accept password on API error)
  and `fail_closed` (block password on API error).
- `hook_requirements` implementation (via Drupal 11 `#[Hook]` attribute) that
  probes API connectivity on the Status Report page. Probe results cached for
  five minutes to limit outbound requests.
- `hook_help` implementation providing module description and links on the
  help page.
- Drush 12 command `hibp:check-user` (alias `hibp-cu`) with `--plaintext` and
  `--bypass-cache` options for manual breach checks from the CLI.
- Dedicated logger channel `hibp_password_guard`. Log entries contain only
  exception class names and HTTP status codes -- no passwords, hashes, or user
  identifiers.
- Configuration schema (`hibp_password_guard.schema.yml`) and default
  configuration (`hibp_password_guard.settings.yml`).
- Menu link under **Administration > Configuration > Security**.
- Permission `administer hibp password guard` (restricted access).
- Unit tests for `HibpApiClient`, `HibpPasswordCheckerService`,
  `HibpCompromised`, `HibpPasswordGuardHooks`, `HibpCheckResult`, and
  `HibpRangeResponse`.
- Functional tests for the settings form, Status Report integration, the
  constraint integration, and the Drush command.
- Compatibility with Drupal 10.4 and Drupal 11.x.
