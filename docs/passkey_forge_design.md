# Passkey Forge — Design Document

## Overview

Passkey Forge is an enterprise-grade FIDO2/WebAuthn Level 3 passkey authentication module for Drupal 11. It enables users to register and authenticate with passkeys (platform authenticators such as Touch ID, Face ID, Windows Hello, and roaming authenticators such as YubiKeys and NFC security keys) as a replacement for or supplement to password-based login.

## Goals

- Full FIDO2/WebAuthn Level 3 compliance for registration and authentication ceremonies.
- Support platform (internal) and roaming (USB, NFC, BLE, hybrid) authenticators.
- Configurable attestation policy: `none`, `indirect`, `direct` — per site and per role.
- Per-role enforcement: require passkeys for privileged roles (e.g. `administrator`).
- Full admin interface: view all registered passkeys per user and revoke individual credentials.
- Graceful degradation: fall back to password login when no passkey is registered.
- Zero procedural code in the `.module` file — Drupal 11 OOP hook attribute system.
- Immutable value objects, typed properties, `declare(strict_types=1)` throughout.

## Non-Goals

- FIDO MDS3 attestation trust-anchor validation (requires external MDS3 feed; recommended for operators to add on top).
- Multi-factor authentication combining passkeys with a second factor.
- Custom authenticator selection UI beyond the browser's native credential picker.

## Security Model

### WebAuthn Ceremony Security

Registration and authentication ceremonies follow WebAuthn Level 3 §7.1 and §7.2:

1. **Challenge freshness**: Challenges are 32-byte CSPRNG-generated values stored in the PHP session with a configurable TTL. Each challenge is single-use — the session key is cleared immediately before response verification to prevent replay attacks.

2. **Origin binding**: The `origin` field in `clientDataJSON` is checked against the `allowed_origins` configuration list. Only exact matches are accepted. This prevents cross-site credential theft.

3. **RP ID hash verification**: The `rpIdHash` in `authenticatorData` is compared with `SHA-256(rp_id)`. A mismatch indicates a phishing attempt.

4. **User Presence**: The UP flag in `authenticatorData` is always required, ensuring the user physically interacted with the authenticator.

5. **User Verification**: The UV flag enforcement is configurable: `required` (always enforce), `preferred` (request but do not require), `discouraged` (do not request). Defaults to `preferred`.

6. **Signature counter**: An authenticator's monotonically increasing counter is stored and verified on each authentication. A non-increasing counter (when both counters are non-zero) is treated as evidence of a cloned authenticator and authentication is rejected with a warning log.

7. **Signature verification**: ES256, RS256, PS256, and EdDSA public keys are verified using `openssl_verify()`. The PEM public key is extracted from the COSE key during registration and stored in the database.

### Attestation Policy

The module supports three WebAuthn attestation conveyance preferences:

| Policy | Description | Use case |
|--------|-------------|----------|
| `none` | No attestation requested or validated | Consumer sites, maximum device compatibility |
| `indirect` | Attestation requested; platform may anonymise | Regulated environments needing device-type assurance |
| `direct` | Full manufacturer cert chain required | Government, finance, high-assurance deployments |

Per-role attestation overrides allow stricter policies for administrative roles while keeping `none` for general users.

### Access Control

- `administer passkey forge` — access settings, view all keys, revoke credentials (restrict access: true).
- `manage own passkeys` — register and remove own keys.
- Registration and authentication endpoints enforce ownership via session state.
- Revocation endpoint scope-limits DB updates to prevent IDOR (UPDATE WHERE id=? AND uid=?).

## Database Schema

A single table `passkey_forge_credentials` stores all registered credentials:

```
id              SERIAL PRIMARY KEY
uid             INT UNSIGNED NOT NULL  — FK to users.uid
credential_id   VARCHAR(1400) UNIQUE   — base64url-encoded credential ID
public_key      MEDIUMTEXT             — PEM-encoded COSE public key
aaguid          VARCHAR(36)            — UUID string or NULL
sign_count      INT UNSIGNED           — signature counter
attestation_type VARCHAR(16)           — none / indirect / direct
transports      VARCHAR(255)           — JSON array of transport hints
label           VARCHAR(255)           — user-provided label
revoked         TINYINT(1)             — soft-delete flag
created         INT UNSIGNED           — Unix timestamp
last_used       INT UNSIGNED           — Unix timestamp or NULL
```

Indexes: `uid`, `uid + revoked` (composite for fast per-user active lookup), `credential_id` (unique, for authentication lookup).

## Configuration Schema

All configuration is stored in `passkey_forge.settings` (CMI):

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Global on/off switch |
| `rp_id` | string | example.com | WebAuthn RP ID (domain) |
| `rp_name` | string | My Drupal Site | RP display name |
| `allowed_origins` | sequence | [https://example.com] | Accepted client origins |
| `attestation_policy` | string | none | Default attestation conveyance |
| `timeout` | int | 60000 | Ceremony timeout (ms) |
| `require_resident_key` | bool | false | Require discoverable credentials |
| `user_verification` | string | preferred | UV requirement |
| `enforce_for_roles` | sequence | [administrator] | Roles that must use passkeys |
| `allow_password_fallback` | bool | true | Allow password when no passkey |
| `challenge_ttl` | int | 300 | Challenge session lifetime (s) |

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/passkey-forge/register/challenge` | Logged in | Issue registration options |
| POST | `/passkey-forge/register/complete` | Logged in | Verify and store credential |
| GET | `/passkey-forge/auth/challenge` | Public | Issue authentication options |
| POST | `/passkey-forge/auth/complete` | Public | Verify assertion and log in |
| GET | `/admin/config/security/passkey-forge/users/{uid}/keys` | Admin | List user credentials |
| POST | `/admin/config/security/passkey-forge/keys/{id}/revoke` | Admin | Revoke credential |

## Graceful Degradation

When `allow_password_fallback` is enabled (default), users without a registered passkey proceed through the standard Drupal login form. The passkey authentication button is injected via JavaScript only when the browser supports `PublicKeyCredential`, so non-WebAuthn browsers see no UI change.

When the module is disabled (`enabled: false`), all passkey endpoints return 503 and the JS injection is skipped.
