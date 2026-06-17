# SCIM Bridge

RFC 7644 SCIM 2.0 server for Drupal 11. Enables Okta, Azure Active Directory,
Google Workspace, and any other SCIM-compliant Identity Provider to provision
and manage Drupal user accounts and roles automatically.

## Features

- Full SCIM 2.0 user lifecycle: create, read, update (PUT), partial update (PATCH), delete
- Group provisioning mapped to Drupal roles
- Bearer token authentication per IdP with SHA-256 token hashing
- SCIM filter support: eq, ne, co, sw, ew, pr, and, or, not
- Pagination: startIndex + count
- Discovery endpoints: ServiceProviderConfig, Schemas, ResourceTypes
- Configurable attribute mapping: SCIM attribute paths to Drupal field machine names
- Conflict handling: skip (default) or update strategy on duplicate userName/email
- Admin UI for token management and attribute mapping
- Sync log table for auditing all provisioning operations
- Status report integration

## Requirements

- Drupal 11 (^11)
- PHP 8.2+

## Installation

```bash
drush en scim_bridge
drush updb
```

## Quick Start

1. Go to `/admin/config/security/scim-bridge`
2. Click **Add another token**, enter an IdP label, paste the raw Bearer token, and save
3. Configure attribute mapping at `/admin/config/security/scim-bridge/mapping`
4. In your IdP, set the SCIM base URL to: `https://your-site.example.com/scim/v2`
5. Set the Authorization header to: `Bearer <your-raw-token>`

## Endpoints

| Endpoint | Methods |
|---|---|
| `/scim/v2/Users` | GET, POST |
| `/scim/v2/Users/{id}` | GET, PUT, PATCH, DELETE |
| `/scim/v2/Groups` | GET, POST |
| `/scim/v2/Groups/{id}` | GET, PUT, PATCH, DELETE |
| `/scim/v2/ServiceProviderConfig` | GET (unauthenticated) |
| `/scim/v2/Schemas` | GET (unauthenticated) |
| `/scim/v2/ResourceTypes` | GET (unauthenticated) |

## IdP Configuration Guides

### Okta
1. Applications > Provisioning > SCIM
2. SCIM connector base URL: `https://your-site.example.com/scim/v2`
3. Authentication: HTTP Header, Authorization: Bearer `<token>`
4. Supported SCIM Actions: Push New Users, Push Profile Updates, Push Groups

### Azure Active Directory
1. Enterprise Applications > Provisioning
2. Provisioning Mode: Automatic
3. Tenant URL: `https://your-site.example.com/scim/v2`
4. Secret Token: `<token>`

### Google Workspace
1. Admin Console > Directory > LDAP / User Provisioning
2. Select Custom SCIM; set endpoint and Bearer token

## Security Notes

- Bearer tokens are stored as SHA-256 hashes in configuration. The plain-text
  token is never stored in Drupal.
- Token comparison uses `hash_equals()` to prevent timing attacks.
- The `anonymous` (uid=0) and system roles cannot be exposed or deleted via SCIM.

## Running Tests

```bash
# Unit tests
vendor/bin/phpunit modules/custom/scim_bridge/tests/src/Unit/

# Functional tests (requires running Drupal)
vendor/bin/phpunit modules/custom/scim_bridge/tests/src/Functional/

# Playwright E2E (requires running Drupal at http://localhost)
npx playwright test playwright/scim_bridge.spec.js
```

## License

GPL-2.0-or-later
