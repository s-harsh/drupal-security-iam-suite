# Changelog

All notable changes to **Session Sentinel** will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-10

### Added
- Initial release of Session Sentinel for Drupal 11.
- **Idle session timeout**: per-role configurable idle timeout (default 30 min), global fallback, cron-based pruning.
- **Concurrent session limit**: max N simultaneous sessions per user (default 3); oldest session killed on overflow; optional admin exemption.
- **Device fingerprint binding**: SHA-256 of User-Agent + /24 IP subnet; anomalous mid-session changes are flagged in the sentinel table and logged; optional kill-on-change mode.
- **Admin dashboard**: live table at `/admin/config/security/session-sentinel/dashboard` with per-session Kill button (CSRF-protected) and auto-refresh JSON endpoint.
- **JS countdown warning**: `session-timeout-warning.js` Drupal behaviour that shows a countdown banner 5 minutes (configurable) before idle expiry and pings a keep-alive endpoint when the user clicks "Stay logged in".
- **Drush commands**: `session-sentinel:prune`, `session-sentinel:list`, `session-sentinel:kill`, `session-sentinel:status`.
- **Config schema** and install default YAML.
- **Unit tests**: `SessionSentinelManagerTest`, `DeviceFingerprintServiceTest`, `SessionRecordTest`.
- **Functional tests**: `SessionSentinelSettingsFormTest`, `SessionDashboardControllerTest`.
- **Playwright E2E spec**: `playwright/session_sentinel.spec.js`.
- Full Drupal 11 OOP hook architecture (`#[Hook]` attribute, `drupal.hook` service tag).
