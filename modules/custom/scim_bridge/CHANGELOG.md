# Changelog

All notable changes to the SCIM Bridge module are documented here.

## [1.0.0] - 2026-06-16

### Added
- Initial release of the SCIM Bridge Drupal 11 module.
- RFC 7644 SCIM 2.0 server implementation for `/scim/v2/Users` and `/scim/v2/Groups`.
- Bearer token authentication with SHA-256 hashing and `hash_equals()` timing-safe comparison.
- Full user CRUD: GET (list + single), POST (create), PUT (replace), PATCH (partial update), DELETE.
- PATCH support: add, remove, replace operations on individual attributes, path-less value-map operations, and bracketed filter path normalisation.
- Group/role CRUD with member management via `grantRoleToUsers()` / `revokeRoleFromUsers()` / `setRoleMembers()`.
- SCIM filter parser supporting: eq, ne, co, sw, ew, gt, lt, ge, le, pr, and, or, not; parentheses; dot notation; bracketed sub-attribute filters.
- Pagination: `startIndex` and `count` query parameters with configurable server-side maximum.
- Discovery endpoints: `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, `/scim/v2/ResourceTypes`.
- Configurable attribute mapping: SCIM attribute paths → Drupal user field machine names via `scim_bridge.mapping` config.
- Configurable group-to-role mapping; auto-mapping by machine-name conversion when no explicit map is defined.
- Conflict resolution strategy: `skip` (default, returns existing user unchanged) or `update` (merges attributes).
- Admin UI settings form (`ScimBridgeSettingsForm`) with IdP token management (add/remove/toggle), conflict strategy, page size, sync log settings.
- Admin UI attribute mapping form (`ScimMappingForm`) with user attribute and group-role mapping tables.
- `scim_bridge_sync_log` database table for audit logging of all SCIM operations.
- Sync log retention: configurable TTL in days (0 = retain forever).
- Status report integration (`hook_requirements`) showing active token count and module health.
- `hook_help` implementation with endpoint reference and admin links.
- `administer scim bridge` permission with restricted access.
- Admin menu links under Security configuration section.
- PHPUnit unit tests: ScimFilterParserTest, ScimUserMapperTest, ScimGroupMapperTest, ScimUserTest.
- BrowserTestBase functional tests: ScimUsersControllerTest.
- Playwright E2E test suite: admin UI, SCIM API CRUD, auth rejection, discovery, status report.
- Design document (`docs/scim_bridge_design.md`).
- Architecture document (`docs/scim_bridge_architecture.md`).
