# Passkey Forge — Architecture Document

## Module Structure

```
passkey_forge/
├── passkey_forge.info.yml          Module metadata, dependencies
├── passkey_forge.module             Near-empty; declares strict_types only
├── passkey_forge.services.yml       DI service definitions
├── passkey_forge.routing.yml        Route definitions
├── passkey_forge.permissions.yml    Permission declarations
├── passkey_forge.links.menu.yml     Admin menu entries
├── passkey_forge.libraries.yml      JS library definitions
├── passkey_forge.install            Schema + uninstall hook
├── composer.json                    Composer metadata + web-auth/webauthn-lib
├── config/
│   ├── install/passkey_forge.settings.yml   Default config
│   └── schema/passkey_forge.schema.yml      CMI schema
├── js/
│   ├── passkey-register.js          Registration ceremony JS
│   └── passkey-authenticate.js      Authentication ceremony JS
├── src/
│   ├── Hook/PasskeyForgeHooks.php   OOP hooks (#[Hook] attributes)
│   ├── Service/
│   │   ├── WebAuthnService.php      Core ceremony orchestrator
│   │   ├── AttestationValidator.php Attestation policy enforcement
│   │   └── PasskeyStorage.php       Database CRUD layer
│   ├── Controller/
│   │   ├── PasskeyRegistrationController.php  /register/challenge + complete
│   │   ├── PasskeyAuthController.php           /auth/challenge + complete
│   │   └── PasskeyAdminController.php          Admin credential management
│   ├── Form/
│   │   ├── PasskeyForgeSettingsForm.php  ConfigFormBase settings
│   │   └── PasskeyManageForm.php         User passkey management form
│   └── Value/
│       ├── AttestationPolicy.php    Backed enum: none / indirect / direct
│       └── PasskeyCredential.php    Immutable readonly credential VO
└── tests/
    ├── src/Unit/
    │   ├── Service/WebAuthnServiceTest.php
    │   ├── Service/AttestationValidatorTest.php
    │   └── Value/PasskeyCredentialTest.php
    └── src/Functional/
        └── Form/PasskeyForgeSettingsFormTest.php
```

## Component Diagram

```
Browser JS                  Drupal PHP
──────────────────────────────────────────────────────────────

passkey-register.js
  │  GET /register/challenge ──────► PasskeyRegistrationController::challenge()
  │                                    └─ WebAuthnService::buildRegistrationOptions()
  │                                         └─ generates challenge (CSPRNG)
  │                                         └─ loads existing creds via PasskeyStorage
  │◄── JSON (PublicKeyCredentialCreationOptions)
  │
  │  navigator.credentials.create()
  │
  │  POST /register/complete ──────► PasskeyRegistrationController::complete()
  │                                    └─ WebAuthnService::verifyRegistrationResponse()
  │                                         └─ validates clientDataJSON, challenge, origin
  │                                         └─ parses authenticatorData (rpIdHash, flags)
  │                                         └─ extracts credentialId + COSE public key
  │                                    └─ AttestationValidator::validate()
  │                                    └─ PasskeyStorage::save()
  │◄── 201 JSON (credential_db_id, aaguid, transports)

passkey-authenticate.js
  │  GET /auth/challenge ──────────► PasskeyAuthController::challenge()
  │                                    └─ WebAuthnService::buildAuthenticationOptions()
  │                                    └─ PasskeyStorage::loadActiveByUid() (if username)
  │◄── JSON (PublicKeyCredentialRequestOptions)
  │
  │  navigator.credentials.get()
  │
  │  POST /auth/complete ──────────► PasskeyAuthController::complete()
  │                                    └─ PasskeyStorage::loadByCredentialId()
  │                                    └─ WebAuthnService::verifyAuthenticationResponse()
  │                                         └─ validates clientDataJSON, challenge, origin
  │                                         └─ verifies rpIdHash, UP/UV flags
  │                                         └─ verifies ECDSA/RSA signature (openssl_verify)
  │                                         └─ checks sign_count monotonicity
  │                                    └─ PasskeyStorage::updateSignCount()
  │                                    └─ user_login_finalize()
  │◄── 200 JSON (uid, redirect)
```

## Service Layer

### WebAuthnService

Central ceremony orchestrator. Responsibilities:

- **Challenge generation**: `random_bytes(32)` encoded as base64url.
- **User handle generation**: Deterministic SHA-256 hash of `passkey_forge:{uid}`, opaque to the authenticator.
- **Registration options**: Builds `PublicKeyCredentialCreationOptions` JSON from site configuration. Includes `excludeCredentials` for all active credentials to prevent re-registration.
- **Authentication options**: Builds `PublicKeyCredentialRequestOptions`. Populates `allowCredentials` for username-based flows; leaves empty for resident/discoverable-key flows.
- **Registration verification**: Validates `clientDataJSON` type, challenge match, origin allowlist, `rpIdHash`, UP/UV flags, and extracts the credential ID and COSE public key.
- **Authentication verification**: Full §7.2 verification including signature verification via `openssl_verify()` and sign-count monotonicity enforcement.
- **COSE key parsing**: Supports EC2 P-256 (ES256), RSA (RS256), OKP Ed25519 (EdDSA). Uses web-auth/cbor-lib when available; falls back to a minimal CBOR parser for the common ES256 case.

### AttestationValidator

Single-responsibility service for attestation policy enforcement:

- Reads the site-wide policy from `passkey_forge.settings.attestation_policy`.
- Accepts optional per-call policy override strings (for per-role enforcement).
- `none` policy: accepts all formats.
- `indirect` policy: rejects bare `none` format; does not validate certificate chain.
- `direct` policy: requires a verifiable format (packed, tpm, android-key, android-safetynet, fido-u2f, apple) AND a non-empty certificate chain.
- Provides `getPolicyOptions()` for use in the settings form select element.

### PasskeyStorage

Database persistence layer. Abstracts all SQL queries on `passkey_forge_credentials`. Key operations:

- `save()` — INSERT new credential row; returns surrogate PK.
- `loadByCredentialId()` — SELECT by credential_id WHERE revoked=0; used during authentication.
- `loadActiveByUid()` — SELECT active credentials for a user; used for registration exclude list and authentication allow list.
- `loadAllByUid()` — SELECT all (including revoked); used by admin UI.
- `userHasPasskey()` — COUNT active credentials; used by hook_user_login for enforcement check.
- `updateSignCount()` — UPDATE counter + last_used after successful authentication.
- `revoke()` — UPDATE revoked=1 by surrogate PK; used by admin and user management form.
- `deleteByUid()` — DELETE all rows for a UID; called from hook_user_delete.
- `updateLabel()` — UPDATE label scoped to uid to prevent IDOR.

## Value Objects

### PasskeyCredential (readonly class)

Immutable snapshot of a credential database row. Key design decisions:

- `readonly class` keyword enforces PHP-level immutability.
- Mutation via copy-and-modify factory methods: `withSignCount()` and `revoke()`.
- `fromDatabaseRow(array $row)` static factory for hydration.
- `transportsJson()` serialises transport hints for DB storage.
- `isActive()` computed property (`!revoked`).

### AttestationPolicy (backed enum)

Backed string enum with three cases: `None`, `Indirect`, `Direct`. Key design decisions:

- String backing type allows direct serialisation to/from config and DB.
- `fromStringWithDefault()` static factory for safe deserialization from untrusted input (unknown strings fall back to `None`).
- `label()` method returns human-readable strings for the settings form.

## Hook Implementations

All hooks are implemented via the Drupal 11 `#[Hook]` attribute system in `PasskeyForgeHooks`:

- `hook_user_login`: Enforces passkey requirement for configured roles. Displays warning if the user is in an enforced role but has no passkey registered.
- `hook_user_delete`: Removes all credentials for a deleted user account.
- `hook_requirements`: Runtime checks for RP ID configuration and webauthn-lib availability. Shown on the Drupal status report.
- `hook_help`: Returns the module help page content.

## JavaScript Architecture

Two separate library files, each attached via `#attached['library']` by the PHP layer:

- **`passkey_register`**: Attached to the passkey management form. Single `passkeyRegister` behavior listening on `#passkey-register-btn`. Handles the full registration ceremony: challenge fetch → `navigator.credentials.create()` → assertion POST. Uses `once()` to prevent duplicate listeners on AJAX re-attach.

- **`passkey_authenticate`**: Attached globally by `PasskeyForgeHooks` (hook_page_attachments would go here in a future enhancement). Injects a "Sign in with passkey" button above the password field on `#user-login-form`. Handles the full authentication ceremony.

Both files use only standard browser APIs (`fetch`, `navigator.credentials`, `window.btoa/atob`) and Drupal's `once()` and `drupalSettings` globals — no external JS dependencies.

## Composer Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `web-auth/webauthn-lib` | ^4.9 | Full WebAuthn server-side library (attestation, CBOR, COSE) |
| `web-auth/cose-lib` | ^4.2 | COSE key parsing utilities |
| `web-auth/cbor-lib` | ^0.2 | CBOR decoder used by webauthn-lib |
| `lcobucci/jwt` | ^5.0 | JWT handling (required by webauthn-lib for FIDO2 tokens) |
| `spomky-labs/pki-framework` | ^1.1 | PKI / X.509 utilities for attestation certificate validation |

The module's PHP service layer is designed to degrade gracefully when `web-auth/cbor-lib` is not yet available (using a minimal built-in CBOR parser for ES256), but full attestation validation requires the complete dependency tree.

## Testing Strategy

### Unit Tests (PHPUnit, `tests/src/Unit/`)

- **WebAuthnServiceTest**: Tests challenge generation (entropy, base64url encoding, uniqueness, length), user handle determinism, registration/authentication option construction, and error handling for malformed client data. Avoids full cryptographic ceremony by testing structural validation only.
- **AttestationValidatorTest**: Exhaustive truth table across all three policies, all known formats, and all role-override combinations.
- **PasskeyCredentialTest**: Constructor immutability, copy-and-modify methods, `fromDatabaseRow` hydration, null field handling.

### Functional Tests (BrowserTestBase, `tests/src/Functional/`)

- **PasskeyForgeSettingsFormTest**: Full HTTP cycle — access control (anonymous, unprivileged, privileged, admin), form rendering, save/persist, validation failures, no-op on validation failure, admin menu link.

### End-to-End Tests (Playwright, `playwright/passkey_forge.spec.js`)

- Settings form CRUD via real browser.
- Challenge endpoint JSON structure verification.
- Virtual FIDO2 authenticator (Chromium CDP `WebAuthn.enable`) for full registration ceremony.
- Authentication challenge and assertion flow.
- Admin credential view and revoke.

## Deployment Checklist

1. Install the module: `composer require drupal/passkey_forge && drush en passkey_forge`.
2. Navigate to `/admin/config/security/passkey-forge`.
3. Set **Relying Party ID** to your site's domain (e.g. `example.com`).
4. Set **Relying Party Name** to a human-readable site name.
5. Add your site's full origin to **Allowed origins** (e.g. `https://example.com`).
6. Choose an **attestation policy** appropriate for your compliance requirements.
7. Configure **per-role enforcement** if passkeys are mandatory for admin roles.
8. Save. Verify the status report at `/admin/reports/status` shows no errors.
9. Log in as a non-admin user and register a passkey at `/user/{uid}/passkeys/register`.
10. Test the passkey login flow by logging out and using the "Sign in with passkey" button.
