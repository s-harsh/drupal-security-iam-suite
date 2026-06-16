# Passkey Forge

Enterprise-grade FIDO2/WebAuthn Level 3 passkey authentication for Drupal 11.

## Features

- Register platform authenticators (Touch ID, Face ID, Windows Hello) and roaming FIDO2 security keys (YubiKey, NFC tokens).
- Passkey-only login flow that bypasses the password form when a passkey is registered.
- Configurable attestation policies: `none`, `indirect`, `direct` — enforced globally or per role.
- Per-role passkey enforcement: require passkeys for privileged roles such as `administrator`.
- Admin interface to view all registered passkeys per user and revoke individual credentials.
- Graceful degradation: falls back to password login when no passkey is registered or the browser does not support WebAuthn.
- Full WebAuthn Level 3 server-side verification: challenge replay prevention, origin binding, RP ID hash, UP/UV flags, signature counter monotonicity.

## Requirements

- Drupal 11.x
- PHP 8.2+
- OpenSSL extension (for signature verification)
- Composer package: `web-auth/webauthn-lib ^4.9`

## Installation

```bash
composer require drupal/passkey_forge
drush en passkey_forge
```

## Configuration

1. Navigate to **Admin > Configuration > Security > Passkey Forge** (`/admin/config/security/passkey-forge`).
2. Set the **Relying Party ID** to your site's domain (e.g. `example.com`). This must match the domain users access the site from.
3. Add your site's full origin (e.g. `https://example.com`) to **Allowed origins**. Include all hostnames (www, bare domain, staging, etc.).
4. Choose an **attestation policy**:
   - **None** (default): No attestation required. Maximum device compatibility.
   - **Indirect**: Attestation requested but may be anonymised. Suitable for regulated environments.
   - **Direct**: Full manufacturer attestation required. Use for high-assurance deployments.
5. Optionally enable **per-role enforcement** to require passkeys for the `administrator` role or others.
6. Save the configuration.

## User Registration

Users can register passkeys at `/user/{uid}/passkeys/register` (requires `manage own passkeys` permission, granted to `authenticated` role by default).

The passkey button is also injected automatically on the standard login form (`/user/login`) in browsers that support WebAuthn.

## Admin Management

Administrators with the `administer passkey forge` permission can:

- View all passkeys per user at `/admin/config/security/passkey-forge/users/{uid}/keys`.
- Revoke individual credentials (sets a soft-delete flag; credentials are retained for audit).

## Security Notes

- Challenges are single-use 32-byte CSPRNG values stored in the PHP session.
- Origin validation prevents cross-site credential theft.
- Signature counters detect cloned authenticators.
- Credential IDs never appear in logs; only the first 8 characters (prefix) are logged.
- Attestation certificate chain validation beyond format checking requires integration with the FIDO MDS3 metadata service (not included but supported by the underlying `web-auth/webauthn-lib` library).

## Permissions

| Permission | Description |
|-----------|-------------|
| `administer passkey forge` | Configure the module, view all passkeys, revoke credentials |
| `manage own passkeys` | Register and remove own passkeys |

## Development

Run PHPUnit tests:
```bash
vendor/bin/phpunit modules/custom/passkey_forge/tests/
```

Run Playwright E2E tests:
```bash
npx playwright test playwright/passkey_forge.spec.js
```

See `docs/passkey_forge_design.md` and `docs/passkey_forge_architecture.md` for detailed design and architecture documentation.

## License

GPL-2.0-or-later. See LICENSE.txt.
