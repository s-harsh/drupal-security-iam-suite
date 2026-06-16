# Passkey Forge Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-06-15

### Added

- Initial release of Passkey Forge for Drupal 11.
- FIDO2/WebAuthn Level 3 passkey registration ceremony (`/passkey-forge/register/challenge` + `/passkey-forge/register/complete`).
- FIDO2/WebAuthn Level 3 passkey authentication ceremony (`/passkey-forge/auth/challenge` + `/passkey-forge/auth/complete`).
- Support for platform authenticators (Touch ID, Face ID, Windows Hello) and roaming authenticators (USB, NFC, BLE, hybrid).
- Attestation policy configuration: `none`, `indirect`, `direct`.
- Per-role passkey enforcement via `enforce_for_roles` configuration key.
- Admin interface to view all passkeys per user (`PasskeyAdminController::userKeys`).
- Admin revocation endpoint (`PasskeyAdminController::revoke`).
- User-facing passkey management form (`PasskeyManageForm`) at `/user/{uid}/passkeys/register`.
- `PasskeyForgeSettingsForm` (ConfigFormBase) with full validation for all 11 configuration keys.
- `WebAuthnService`: challenge generation, options building, registration and authentication verification.
- `AttestationValidator`: policy enforcement for `none`, `indirect`, `direct` with role overrides.
- `PasskeyStorage`: database CRUD layer with IDOR-safe queries.
- `PasskeyCredential` immutable readonly value object with copy-and-modify factory methods.
- `AttestationPolicy` backed string enum with `fromStringWithDefault()` safe deserialization.
- `PasskeyForgeHooks`: OOP hook implementations for `hook_user_login`, `hook_user_delete`, `hook_requirements`, `hook_help` using Drupal 11 `#[Hook]` attribute system.
- `passkey-register.js`: browser WebAuthn registration ceremony (challenge fetch, `navigator.credentials.create`, assertion POST).
- `passkey-authenticate.js`: browser WebAuthn authentication ceremony with auto-injection into the Drupal login form.
- `passkey_forge_credentials` database schema with surrogate PK, soft-delete revocation, sign count, transports, AAGUID.
- PHPUnit unit tests: `WebAuthnServiceTest`, `AttestationValidatorTest`, `PasskeyCredentialTest`.
- BrowserTestBase functional tests: `PasskeyForgeSettingsFormTest`.
- Playwright E2E tests with Chromium CDP virtual authenticator support.
- Design document: `docs/passkey_forge_design.md`.
- Architecture document: `docs/passkey_forge_architecture.md`.
- Composer metadata with `web-auth/webauthn-lib ^4.9` dependency.
- CMI schema (`config/schema/passkey_forge.schema.yml`) with typed definitions for all 11 settings keys.
