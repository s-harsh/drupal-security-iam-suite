# SCIM Bridge — Architecture Document

## Module Layout

```
modules/custom/scim_bridge/
├── scim_bridge.info.yml            # Module metadata (Drupal 11, ^11)
├── scim_bridge.module              # Near-empty; delegates all hooks to OOP class
├── scim_bridge.services.yml        # Service definitions with DI wiring
├── scim_bridge.routing.yml         # Route definitions (SCIM endpoints + admin UI)
├── scim_bridge.permissions.yml     # administer scim bridge permission
├── scim_bridge.links.menu.yml      # Admin menu links under Security
├── scim_bridge.install             # hook_schema (sync_log table), hook_uninstall
├── composer.json                   # Drupal module composer metadata
├── README.md                       # Quick-start guide
├── CHANGELOG.md                    # Version history
├── config/
│   ├── install/
│   │   ├── scim_bridge.settings.yml   # Default settings config
│   │   └── scim_bridge.mapping.yml    # Default attribute mapping config
│   └── schema/
│       └── scim_bridge.schema.yml     # Config schema definitions
├── src/
│   ├── Hook/
│   │   └── ScimBridgeHooks.php        # #[Hook] methods: requirements, help
│   ├── Service/
│   │   ├── ScimAuthenticator.php      # Bearer token authentication
│   │   ├── ScimFilterParser.php       # SCIM filter expression parser
│   │   ├── ScimUserMapper.php         # User CRUD + list + patch
│   │   └── ScimGroupMapper.php        # Group/role CRUD + list + patch
│   ├── Controller/
│   │   ├── ScimUsersController.php        # /scim/v2/Users endpoint
│   │   ├── ScimGroupsController.php       # /scim/v2/Groups endpoint
│   │   └── ScimServiceProviderController.php  # Discovery endpoints
│   ├── Form/
│   │   ├── ScimBridgeSettingsForm.php  # Settings admin form
│   │   └── ScimMappingForm.php        # Attribute mapping admin form
│   └── Value/
│       ├── ScimUser.php               # Immutable readonly User value object
│       ├── ScimGroup.php              # Immutable readonly Group value object
│       └── ScimPatchOperation.php     # Immutable readonly PATCH op value object
└── tests/
    ├── src/Unit/
    │   ├── Service/
    │   │   ├── ScimUserMapperTest.php
    │   │   ├── ScimGroupMapperTest.php
    │   │   └── ScimFilterParserTest.php
    │   └── Value/
    │       └── ScimUserTest.php
    └── src/Functional/
        └── Controller/
            └── ScimUsersControllerTest.php
```

---

## Component Responsibilities

### ScimAuthenticator

Stateless service. Extracts the `Authorization: Bearer <token>` header,
computes `SHA-256(token)`, and compares it against each active entry in
`scim_bridge.settings.idp_tokens` using `hash_equals()`. Returns the IdP
label string on success or `null` on failure.

### ScimFilterParser

Stateless service. Implements a hand-written recursive descent parser for SCIM
filter expressions (RFC 7644 §3.4.2.2). The parser:

1. Strips outer parentheses.
2. Splits on top-level `and`/`or` logical operators (respecting nesting depth).
3. Handles `not (expr)` wrapping.
4. Falls back to simple comparison parsing for leaf expressions.

Returns a nested array tree structure. A companion method
`toEntityQueryConditions()` translates the tree into Drupal entity query
`condition()` calls for supported operators. Post-query filtering via
`matchesSimple()` handles operators that cannot be expressed in entity queries.

### ScimUserMapper

Orchestrates all User CRUD operations:

- **listUsers**: builds an entity query with filter/pagination, loads users,
  converts to ScimUser via `drupalUserToScimUser()`, applies post-query
  filtering, and returns a ListResponse array.
- **createUser**: checks for conflicts, creates or returns existing user.
- **replaceUser**: loads user, calls `applyScimUserToEntity()`, saves.
- **patchUser**: loads user, iterates operations calling `applyPatchOperation()`.
- **deleteUser**: loads user, calls `delete()`.
- **drupalUserToScimUser**: reads core fields + configured field_* fields and
  constructs a ScimUser value object.
- **applyScimUserToEntity**: writes ScimUser properties to a UserInterface,
  respecting the configured attribute map.
- **applyPatchOperation**: handles path-based single-attribute patches and
  path-less value-map patches for UserInterface.

### ScimGroupMapper

Mirrors ScimUserMapper but for Drupal roles. Key difference: Drupal has no
standalone Group entity, so groups are represented by `user_role` config
entities. Member queries use entity queries on the `user` entity with a `roles`
condition.

### ScimUsersController / ScimGroupsController

Thin HTTP layer controllers. Each follows the same pattern:

1. Re-authenticate in the controller method (defence-in-depth; access callback
   already gated by Drupal's access manager).
2. Dispatch to the appropriate service method based on HTTP method.
3. Catch all `\Throwable` from service calls to prevent 500 responses leaking
   internal details.
4. Write a sync log entry.
5. Return a `JsonResponse` with `Content-Type: application/scim+json`.

### ScimServiceProviderController

Serves the three unauthenticated SCIM discovery endpoints. Hard-codes the
capability document (ServiceProviderConfig), resource type list, and schema
definitions. No service dependencies required.

### Value Objects (ScimUser, ScimGroup, ScimPatchOperation)

All three are `final readonly` classes — PHP 8.2 immutable value objects.
Factory methods (`fromArray()`) parse IdP JSON payloads; `toScimArray()`
serialises for the response. `withId()` returns a copy with the id set after
entity creation (supports immutable chaining).

---

## Request Lifecycle

```
IdP HTTP Request
    │
    ▼
Drupal Router (routing.yml)
    │ route matched
    ▼
Drupal Access Manager (_custom_access: ScimUsersController::access)
    │ ScimAuthenticator::authenticate()
    │ ─ returns null → AccessResult::forbidden()
    │ ─ returns label → AccessResult::allowed()
    ▼
ScimUsersController::collection() or ::item()
    │ re-authenticate (defence-in-depth)
    │ parse JSON body
    │ build ScimUser/ScimGroup value object
    ▼
ScimUserMapper / ScimGroupMapper
    │ entity query / load / save / delete
    │ Drupal user/role entity storage
    ▼
ScimUsersController
    │ write sync log entry
    │ build JsonResponse (Content-Type: application/scim+json)
    ▼
IdP receives SCIM-compliant HTTP response
```

---

## Configuration Architecture

Two config objects are used:

| Config Object | Purpose |
|---|---|
| `scim_bridge.settings` | Runtime settings: enabled flag, IdP tokens, conflict strategy, page size, sync log config |
| `scim_bridge.mapping` | Attribute mapping: SCIM attr → Drupal field, group displayName → role id |

Both have default values shipped in `config/install/` and schema definitions
in `config/schema/scim_bridge.schema.yml`. The schema ensures config import
validation and type safety.

---

## Service Wiring (DI)

All services use constructor injection with typed properties:

```
scim_bridge.authenticator
    └── config.factory
    └── logger.channel.scim_bridge

scim_bridge.filter_parser
    (no dependencies — stateless)

scim_bridge.user_mapper
    └── entity_type.manager
    └── config.factory
    └── logger.channel.scim_bridge
    └── scim_bridge.filter_parser
    └── password_generator

scim_bridge.group_mapper
    └── entity_type.manager
    └── config.factory
    └── logger.channel.scim_bridge

scim_bridge.hooks
    └── config.factory
    (tagged: drupal.hook)
```

Controllers use `ContainerInterface::get()` via the static `create()` factory
method (standard Drupal DI pattern for controllers).

---

## Database Schema

```sql
CREATE TABLE scim_bridge_sync_log (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  timestamp      INT UNSIGNED NOT NULL DEFAULT 0,
  operation      VARCHAR(16)  NOT NULL DEFAULT '',
  resource_type  VARCHAR(16)  NOT NULL DEFAULT '',
  scim_id        VARCHAR(255)          DEFAULT NULL,
  drupal_id      VARCHAR(255)          DEFAULT NULL,
  http_status    SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  idp_label      VARCHAR(128)          DEFAULT NULL,
  detail         TEXT                  DEFAULT NULL,
  INDEX (timestamp),
  INDEX (operation),
  INDEX (resource_type),
  INDEX (drupal_id)
);
```

---

## Coding Standards

All PHP files follow the project coding standards:

- `declare(strict_types=1)` on every file.
- Namespace: `Drupal\scim_bridge\`.
- OOP hooks: `#[Hook('hook_name')]` in `ScimBridgeHooks`, registered as a
  tagged `drupal.hook` service.
- Services use constructor property promotion with typed `readonly` properties.
- Controllers extend `ControllerBase` and have a static `create()` factory.
- Forms extend `ConfigFormBase` with `getEditableConfigNames()`.
- Value objects are `final readonly` classes with `fromArray()` factory
  methods and `toScimArray()` serialisers.
- No procedural code in `.module` file beyond the docblock.

---

## Testing Strategy

### Unit Tests (tests/src/Unit/)

- **ScimFilterParserTest**: covers all filter operators (eq, ne, co, sw, ew,
  pr, gt, lt, ge, le), logical operators (and, or, not), parentheses, entity
  query condition translation, and matchesSimple().
- **ScimUserMapperTest**: covers value object construction, drupalUserToScimUser(),
  getUser() null cases, deleteUser() cases, ScimUser.fromArray(), ScimUser.toScimArray(),
  ScimPatchOperation parsing and helpers.
- **ScimGroupMapperTest**: covers getGroup(), deleteGroup() (including system
  role protection), ScimGroup value object.
- **ScimUserTest**: comprehensive coverage of the ScimUser value object
  (immutability, field parsing, email precedence logic, toScimArray() shape).

All unit tests use `PHPUnit\Framework\MockObject\MockObject` for dependencies
and extend `Drupal\Tests\UnitTestCase`.

### Functional Tests (tests/src/Functional/)

- **ScimUsersControllerTest**: exercises the full HTTP stack using BrowserTestBase.
  Tests authentication (401/403 paths), discovery endpoints (ServiceProviderConfig,
  Schemas, ResourceTypes), list/get/404 responses, admin UI access control,
  pagination parameters.

### Playwright E2E Tests (playwright/scim_bridge.spec.js)

Covers admin UI interaction (settings, mapping, validation), all SCIM API
endpoints via HTTP (create/get/put/patch/delete users, group operations,
discovery endpoints), authentication rejection scenarios, and the status
report page.

---

## Deployment Checklist

1. Enable the module: `drush en scim_bridge`
2. Run database updates: `drush updb` (creates `scim_bridge_sync_log` table)
3. Navigate to `/admin/config/security/scim-bridge`
4. Add an IdP token: enter a label and paste the raw token; copy the token
   immediately as it cannot be retrieved after saving
5. Configure attribute mapping at `/admin/config/security/scim-bridge/mapping`
6. Configure the IdP's SCIM base URL to `https://your-site.example.com/scim/v2`
7. Verify the status report shows "SCIM Bridge: Active"
8. Test with a SCIM probe from the IdP
