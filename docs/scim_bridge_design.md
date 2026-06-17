# SCIM Bridge — Design Document

## Overview

SCIM Bridge is a Drupal 11 module that implements a server-side RFC 7644 SCIM
2.0 endpoint. It enables enterprise Identity Providers (IdPs) such as Okta,
Azure Active Directory, and Google Workspace to automatically provision,
update, and deprovision user accounts and roles in Drupal via HTTP REST calls
authenticated with Bearer tokens.

---

## Problem Statement

Enterprises operating Drupal sites alongside an IdP need a reliable,
standards-compliant mechanism for user lifecycle management. Manual user
creation is error-prone and does not scale. Drupal's built-in user management
lacks SCIM support, leaving integrators to write bespoke glue code.

SCIM Bridge solves this by exposing a production-quality SCIM 2.0 server
endpoint directly from Drupal, requiring no external proxies or middleware.

---

## RFC 7643 / 7644 Compliance

The following sections of the SCIM specification are implemented:

| Spec Reference | Feature | Status |
|---|---|---|
| RFC 7644 §3.3 | Resource creation (POST) | Implemented |
| RFC 7644 §3.4 | Resource retrieval (GET) | Implemented |
| RFC 7644 §3.4.2 | Filtering | Implemented (partial) |
| RFC 7644 §3.4.2.4 | Pagination (startIndex, count) | Implemented |
| RFC 7644 §3.5.1 | Full replacement (PUT) | Implemented |
| RFC 7644 §3.5.2 | Partial update (PATCH) | Implemented |
| RFC 7644 §3.6 | Resource deletion (DELETE) | Implemented |
| RFC 7644 §4 | Discovery (ServiceProviderConfig, Schemas, ResourceTypes) | Implemented |
| RFC 7643 §4.1 | User schema | Implemented |
| RFC 7643 §4.2 | Group schema | Implemented |

### Supported Filter Operators

eq, ne, co (contains), sw (starts with), ew (ends with), gt, lt, ge, le, pr
(present), and, or, not.

### Not Implemented

- Bulk operations (RFC 7644 §3.7) — not supported; documented in
  ServiceProviderConfig
- ETag / conditional updates (RFC 7644 §3.14)
- Sort (RFC 7644 §3.4.2.3)
- Enterprise User Schema extension

---

## Authentication Model

Each IdP is assigned a unique Bearer token during setup. Tokens are stored
as SHA-256 hashes in Drupal configuration — the plain-text token exists only
in the IdP configuration. Incoming requests are authenticated by comparing
`SHA-256(Authorization header token)` to the stored hashes using
`hash_equals()` (constant-time comparison to prevent timing attacks).

Multiple tokens may be active simultaneously, allowing rolling rotation and
multi-IdP deployments.

---

## Data Model

### Users

SCIM User resources map directly to Drupal user entities. The attribute
mapping is configurable via `scim_bridge.mapping`:

| SCIM Attribute | Default Drupal Field |
|---|---|
| userName | name (unique) |
| emails[0].value | mail |
| displayName | field_display_name |
| name.givenName | field_first_name |
| name.familyName | field_last_name |
| phoneNumbers[0].value | field_phone |
| title | field_job_title |
| addresses[0].locality | field_city |
| addresses[0].country | field_country |
| active | status |
| externalId | field_scim_external_id |

Fields prefixed with `field_` are optional — if they do not exist on the
Drupal user entity, write operations for those attributes are silently skipped.
Core fields (`name`, `mail`, `status`) always exist.

### Groups

SCIM Groups map to Drupal roles. The module does not create a separate entity
type for groups. A configurable `group_role_map` in `scim_bridge.mapping`
allows administrators to define explicit SCIM displayName → Drupal role
machine-name mappings. When no explicit mapping exists, the displayName is
machine-name-ified automatically.

---

## Conflict Resolution

When a SCIM POST creates a user with a `userName` or email that already exists
in Drupal, the module applies the configured conflict strategy:

- **skip** (default): the existing user is returned unchanged with HTTP 200.
- **update**: the incoming SCIM attributes are merged into the existing account
  and HTTP 200 is returned.

Conflict strategy is configurable per site in `scim_bridge.settings`.

---

## PATCH Operations

SCIM PATCH requests carry an `Operations` array. Each operation has:
- `op`: add, remove, or replace
- `path`: SCIM attribute path (dot notation or bracketed sub-attribute filter)
- `value`: new value (absent for remove)

Path-less operations (where `value` is a map of attributes) are supported by
iterating the value map as individual sub-operations.

Bracketed filter expressions (e.g. `emails[type eq "work"].value`) are
normalised to index-0 notation (`emails[0].value`) for mapping lookup.

---

## Sync Log

All SCIM operations are recorded in the `scim_bridge_sync_log` database table.
Each row captures:

- Unix timestamp
- Operation type (create, update, patch, delete, list, get)
- Resource type (User or Group)
- SCIM externalId (when available)
- Drupal entity ID
- HTTP status code returned
- IdP label (which token matched)
- Detail / error message (optional)

Log retention is configurable (default 90 days). Logging can be disabled for
high-traffic deployments.

---

## Security Considerations

1. **Bearer tokens**: stored as SHA-256 hashes only. Plain-text tokens cannot
   be recovered from Drupal configuration.
2. **Timing-safe comparison**: `hash_equals()` is used for all token
   comparisons.
3. **Access control**: SCIM endpoints use `_custom_access` routing with the
   Drupal access result system; they are independent of Drupal's session
   authentication.
4. **Anonymous UID exclusion**: the anonymous user (uid=0) is never returned
   in SCIM list or get responses.
5. **System role protection**: the `anonymous` and `authenticated` Drupal
   roles cannot be deleted via the SCIM Groups DELETE endpoint.
6. **Input validation**: all JSON bodies are decoded with
   `JSON_THROW_ON_ERROR`; malformed payloads receive HTTP 400 immediately.
7. **Page size cap**: the maximum items per list response is configurable and
   server-enforced regardless of what the IdP requests.

---

## Admin UI

The module exposes two admin forms under `/admin/config/security/scim-bridge`:

1. **Settings** (`ScimBridgeSettingsForm`): global toggle, IdP token
   management (add/remove/enable/disable), conflict strategy, page size limit,
   sync log settings.
2. **Attribute Mapping** (`ScimMappingForm`): SCIM attribute → Drupal field
   table, Group displayName → Drupal role machine-name table.

Both forms are protected by the `administer scim bridge` permission.

---

## Status Report Integration

`ScimBridgeHooks::requirements()` adds a row to the Drupal status report
(`/admin/reports/status`) indicating:

- **OK**: module enabled and at least one active token configured.
- **Warning**: module enabled but no active tokens (all SCIM requests will be
  rejected with HTTP 401).
- **Warning**: module installed but disabled in settings.
