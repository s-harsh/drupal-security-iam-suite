# Changelog — Paranoia Reborn

All notable changes to this module are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Initial release of Paranoia Reborn for Drupal 11.
- Three lockdown profiles: Strict, Balanced (recommended), Custom.
- `PathRestrictor` service: path-based access control with admin exceptions and wildcard support.
- `ModuleHardener` service: detects and disables the PHP filter module (RCE vector).
- `AccessControlSubscriber`: kernel REQUEST subscriber that enforces path restrictions at priority 33.
- `ParanoiaRebornHooks`: OOP hooks (`hook_requirements`, `hook_help`, `hook_modules_installed`, `hook_menu_links_discovered_alter`) via `#[Hook]` attributes.
- `LockdownProfile`: immutable readonly value object encapsulating profile settings.
- `ParanoiaRebornSettingsForm`: ConfigFormBase settings form with profile selector, role checkboxes, path-exception textarea, and custom toggles driven by Drupal `#states`.
- `AuditLogController`: paginated watchdog table at `/admin/reports/paranoia-reborn-audit`.
- `paranoia_reborn.settings` config schema and default install config (balanced profile).
- PHPUnit unit tests: `PathRestrictorTest`, `ModuleHardenerTest`.
- PHPUnit functional tests: `ParanoiaRebornSettingsFormTest`, `AccessControlTest`.
- Playwright E2E spec: `paranoia_reborn.spec.js`.
- Design and architecture documentation: `docs/paranoia_reborn_design.md`, `docs/paranoia_reborn_architecture.md`.

---

## Links
- [Issue queue](https://github.com/s-harsh/drupal-security-iam-suite/issues)
- [Roadmap](https://github.com/s-harsh/drupal-security-iam-suite/projects)
