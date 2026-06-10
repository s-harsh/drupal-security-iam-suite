# Session Sentinel — Architecture Document

## 1. Module Structure

```
session_sentinel/
├── session_sentinel.info.yml            # Module metadata
├── session_sentinel.module              # Near-empty stub (declare strict_types only)
├── session_sentinel.services.yml        # Service definitions + drupal.hook tag
├── session_sentinel.routing.yml         # Admin routes
├── session_sentinel.permissions.yml     # administer session sentinel
├── session_sentinel.links.menu.yml      # Admin menu links
├── session_sentinel.libraries.yml       # session_timeout_warning JS library
├── session_sentinel.install             # hook_schema, hook_install, hook_uninstall
├── drush.services.yml                   # Drush command registration
├── composer.json                        # PSR-4 autoload, drush.services extra
├── config/
│   ├── install/session_sentinel.settings.yml   # Default config values
│   └── schema/session_sentinel.schema.yml      # Config schema
├── js/
│   └── session-timeout-warning.js       # Idle countdown + keep-alive behaviour
├── src/
│   ├── Value/
│   │   └── SessionRecord.php            # Immutable readonly value object
│   ├── Service/
│   │   ├── DeviceFingerprintService.php  # SHA-256 fingerprint generation/comparison
│   │   └── SessionSentinelManager.php    # Core session management (DB ops, business logic)
│   ├── EventSubscriber/
│   │   └── SessionTimeoutSubscriber.php  # KernelEvents::REQUEST/RESPONSE subscriber
│   ├── Hook/
│   │   └── SessionSentinelHooks.php      # hook_help, hook_user_login/logout, hook_cron, hook_page_attachments
│   ├── Form/
│   │   └── SessionSentinelSettingsForm.php # ConfigFormBase settings form
│   ├── Controller/
│   │   └── SessionDashboardController.php  # Dashboard, kill, and JSON data actions
│   └── Drush/
│       └── Commands/
│           └── SessionSentinelCommands.php # Drush command implementations
├── tests/
│   └── src/
│       ├── Unit/
│       │   ├── Value/SessionRecordTest.php
│       │   └── Service/
│       │       ├── DeviceFingerprintServiceTest.php
│       │       └── SessionSentinelManagerTest.php
│       └── Functional/
│           ├── Form/SessionSentinelSettingsFormTest.php
│           └── Controller/SessionDashboardControllerTest.php
└── [root docs/playwright files omitted from this tree]
```

## 2. Component Responsibilities

### 2.1 `SessionRecord` (Value Object)

An immutable `readonly` class carrying a snapshot of a single session metadata row. All mutation methods (`withLastActive`, `withDeviceFlagged`) return new instances rather than modifying the original.

**Key methods**:
- `createNew()` — Factory for new (unsaved) records.
- `fromRow()` — Hydration from a DB row (`stdClass` or array).
- `idleSeconds(int $now)` — Computed idle time.
- `isIdle(int $timeout, int $now)` — Boundary-inclusive idle check.

### 2.2 `DeviceFingerprintService`

Stateless service responsible for fingerprint generation and comparison.

- `generate(Request)` — Extracts UA and IP from the request, calls `extractSubnet()`, returns `SHA-256(ua|subnet)`.
- `generateFromStrings(string, string)` — Variant for contexts without a Request object.
- `extractSubnet(string)` — Converts IPv4 → /24 prefix, IPv6 → /48 prefix (via `bin2hex(inet_pton())`), handles IPv4-mapped IPv6.
- `matches(string, string)` — Timing-safe comparison via `hash_equals()`.

### 2.3 `SessionSentinelManager`

The central orchestrator. Owns all database interactions with `session_sentinel_sessions`.

**Key responsibilities**:
- `createRecord()` — MERGE-upserts a new sentinel row on login.
- `touchSession()` — Updates `last_active` on each authenticated request.
- `killSession()` — Deletes from both `session_sentinel_sessions` and Drupal core `sessions` table.
- `enforceConcurrentLimit()` — Queries sessions by UID ordered by `last_active ASC`, kills oldest until count ≤ max.
- `idleTimeoutForUser()` — Resolves the effective timeout from role overrides + global config.
- `pruneStaleRecords()` — Bulk DELETE for cron and Drush.

### 2.4 `SessionTimeoutSubscriber`

An `EventSubscriberInterface` that subscribes to `KernelEvents::REQUEST` (priority 30) and `KernelEvents::RESPONSE` (priority -20).

**onRequest() pipeline** (authenticated, non-CLI, non-anonymous, main request only):
1. Hash the current session ID.
2. Load the sentinel record.
3. Check idle timeout → redirect to login if expired.
4. Check device fingerprint if binding is enabled → flag or kill.
5. Touch `last_active`.

**onResponse()**:
- Attaches the JS library and `drupalSettings` to `HtmlResponse` objects for authenticated users when idle timeout is configured.

### 2.5 `SessionSentinelHooks`

OOP hook class with the `drupal.hook` service tag.

| Hook | Purpose |
|---|---|
| `hook_help` | Help page content |
| `hook_user_login` | Create sentinel record; enforce concurrent limit |
| `hook_user_logout` | Delete sentinel record |
| `hook_cron` | Prune stale records; log summary |
| `hook_page_attachments` | Attach JS library and drupalSettings to all authenticated pages |

### 2.6 `SessionSentinelSettingsForm`

Extends `ConfigFormBase`. Renders all configuration fields, performs server-side validation (warning lead time < idle timeout, non-negative values, prune age minimum), and saves to `session_sentinel.settings`.

Per-role timeout fields are generated dynamically from `Role::loadMultiple()`.

### 2.7 `SessionDashboardController`

Extends `ControllerBase`.

- `dashboardPage()` — Loads up to 300 active sentinel records, looks up usernames, builds an HTML table with CSRF-protected kill links.
- `killSession(string, Request)` — Validates CSRF token manually, calls `SessionSentinelManager::killSession()`.
- `dashboardData()` — Returns `JsonResponse` for auto-refresh.

### 2.8 `SessionSentinelCommands`

Extends `DrushCommands`. Uses `#[CLI\Command]`, `#[CLI\Argument]`, and `#[CLI\Option]` attributes.

| Command | Key logic |
|---|---|
| `:prune` | Accepts `--age` override; calls bulk DELETE |
| `:list {uid}` | Calls `getSessionsForUser()`; renders as table |
| `:kill {hash}` | Validates 64-char hex; calls `killSession()` |
| `:status` | Counts active/flagged/stale; displays config summary |

## 3. Request Lifecycle (per authenticated request)

```
HTTP Request
    │
    ├── SessionTimeoutSubscriber::onRequest() [priority 30]
    │     ├── Skip anonymous / CLI / non-main / no session
    │     ├── Load SessionRecord by session_id_hash
    │     ├── [Idle check] → expired? → killSession() → RedirectResponse to /user/login
    │     ├── [Device check] → mismatch? → flagDeviceChange() or killSession()
    │     └── touchSession() → update last_active
    │
    └── Normal Drupal routing / controller
          │
          └── SessionTimeoutSubscriber::onResponse() [priority -20]
                └── Attach JS library + drupalSettings to HtmlResponse
```

## 4. Login Lifecycle

```
User submits login form
    │
    └── hook_user_login fires → SessionSentinelHooks::userLogin()
          ├── Compute device fingerprint (UA + /24 IP subnet)
          ├── SessionSentinelManager::createRecord()
          │     └── DB MERGE on session_id_hash
          └── SessionSentinelManager::enforceConcurrentLimit()
                ├── Query all sessions for uid, ordered by last_active ASC
                └── Kill oldest until count ≤ max_concurrent_sessions
```

## 5. Service Dependency Graph

```
session_sentinel.hooks
    └── session_sentinel.manager

session_sentinel.timeout_subscriber
    ├── session_sentinel.manager
    └── session_sentinel.device_fingerprint

session_sentinel.manager
    ├── @database
    ├── @config.factory
    ├── @logger.channel.session_sentinel
    ├── @session_handler
    └── @current_user

session_sentinel.device_fingerprint
    ├── @config.factory
    └── @logger.channel.session_sentinel

session_sentinel.drush_commands (drush.services.yml)
    ├── session_sentinel.manager
    ├── @database
    └── @config.factory
```

## 6. Configuration Architecture

`session_sentinel.settings` is a simple config object (no config entity, no typed config overrides). This was chosen because:
- All settings are site-wide, not per-entity.
- Config synchronisation (drush cim/cex) is the expected deployment workflow.
- Per-role timeouts are stored as a keyed sequence (role_id → seconds) within the same config object rather than as separate config entities to keep schema simple.

## 7. Drupal 11 Coding Standards Compliance

| Standard | Implementation |
|---|---|
| `declare(strict_types=1)` | All PHP files |
| OOP hooks via `#[Hook]` attribute | `SessionSentinelHooks` with `drupal.hook` service tag |
| Constructor DI + typed properties | All services |
| No procedural code in `.module` | Module file is a minimal stub |
| `ConfigFormBase` for settings | `SessionSentinelSettingsForm` |
| Immutable value objects | `SessionRecord` (readonly class) |
| Drush extends `DrushCommands` | `SessionSentinelCommands` |
| PSR-4 autoload | `Drupal\session_sentinel\` → `src/` |
| Tests in `tests/src/Unit` and `Functional` | Unit (MockObject) + BrowserTestBase |

## 8. Performance Considerations

- `session_sentinel_sessions` has indexes on `uid`, `last_active`, and `(uid, last_active)` to support the most common query patterns (concurrent limit check by UID, prune by age, dashboard ordered by last_active).
- `touchSession()` is a targeted UPDATE on the unique `session_id_hash` key — no full-table scans.
- The dashboard caps at 300 rows; the JSON endpoint mirrors this cap.
- The keep-alive throttle in JS (30-second minimum interval) prevents flooding `touchSession()` calls.
- Cron-based pruning keeps the table bounded over time.
