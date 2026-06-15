# Paranoia Reborn — Architecture Document

## 1. Directory Layout

```
modules/custom/paranoia_reborn/
├── paranoia_reborn.info.yml            # Module metadata, Drupal 11 declaration
├── paranoia_reborn.module              # Near-empty; hook delegation marker only
├── paranoia_reborn.services.yml        # DI container: services, event subscribers, hooks
├── paranoia_reborn.routing.yml         # Admin settings route + audit log route
├── paranoia_reborn.permissions.yml     # Two permissions: administer + bypass
├── paranoia_reborn.links.menu.yml      # Admin menu links (security config + reports)
├── composer.json                       # Composer metadata
├── README.md                           # User-facing documentation
├── CHANGELOG.md                        # Version history
├── config/
│   ├── install/
│   │   └── paranoia_reborn.settings.yml   # Default config (balanced profile)
│   └── schema/
│       └── paranoia_reborn.schema.yml     # Config schema (typed, validated)
└── src/
    ├── Controller/
    │   └── AuditLogController.php          # Renders paginated watchdog table
    ├── EventSubscriber/
    │   └── AccessControlSubscriber.php     # KernelEvents::REQUEST handler
    ├── Form/
    │   └── ParanoiaRebornSettingsForm.php  # ConfigFormBase settings UI
    ├── Hook/
    │   └── ParanoiaRebornHooks.php         # OOP hooks via #[Hook] attribute
    ├── Service/
    │   ├── ModuleHardener.php              # PHP filter disable logic
    │   └── PathRestrictor.php              # Path/role access decision logic
    └── Value/
        └── LockdownProfile.php             # Immutable profile value object
```

---

## 2. Service Graph

```
paranoia_reborn.hooks
  ├─ config.factory
  ├─ paranoia_reborn.module_hardener
  ├─ current_user
  ├─ module_handler
  └─ database

paranoia_reborn.path_restrictor
  ├─ config.factory
  ├─ current_user
  └─ logger.channel.paranoia_reborn

paranoia_reborn.module_hardener
  ├─ config.factory
  ├─ module_handler
  ├─ module_installer
  └─ logger.channel.paranoia_reborn

paranoia_reborn.access_control_subscriber  [event_subscriber]
  ├─ paranoia_reborn.path_restrictor
  ├─ current_user
  ├─ logger.channel.paranoia_reborn
  ├─ config.factory
  └─ request_stack
```

---

## 3. Component Descriptions

### 3.1 `LockdownProfile` (Value Object)

An immutable `final readonly class` capturing all boolean protection flags for one of the three profiles. Named constructors (`::strict()`, `::balanced()`, `::custom(...)`) and a `::fromConfig(array)` factory method decouple the form storage format from the domain logic.

Key invariant: the `strict` and `balanced` profiles always force all protection flags to `true` regardless of stored config values — this is enforced in `ParanoiaRebornSettingsForm::submitForm` and in `LockdownProfile::fromConfig`.

### 3.2 `PathRestrictor` (Service)

Encapsulates the entire access-decision algorithm. Receives `$path` and `AccountInterface $account` as arguments rather than reading from services directly, making it pure and trivially unit-testable.

Public API:
- `isBlocked(string $path, AccountInterface $account): bool`
- `blockReason(string $path, AccountInterface $account): string`
- `isTrusted(AccountInterface $account): bool`
- `isAdminPath(string $path): bool`
- `isFieldUiPath(string $path): bool`
- `isViewsUiPath(string $path): bool`
- `activeProfile(): LockdownProfile`

Field UI detection uses five regex patterns covering node types, taxonomy, block content, and paragraphs. The pattern set is intentionally conservative: it only matches known Field UI URL shapes, not all `/admin/structure/*` paths.

### 3.3 `ModuleHardener` (Service)

Single responsibility: manage the PHP filter module lifecycle. The `disablePhpFilterIfRequired()` method is idempotent — calling it when the module is already disabled is a no-op.

Also provides `hardeningStatus(): array` which is used by the hook class to populate the status report without the hook needing to know about the module system directly.

### 3.4 `AccessControlSubscriber` (Event Subscriber)

Priority 33 on `KernelEvents::REQUEST`. This sits after Drupal's router (priority 40, which matches the route) but before the controller invocation. Returning a `Response` from this event short-circuits the normal request handling pipeline.

The subscriber delegates all access logic to `PathRestrictor` and audit logging to the logger channel. It does not contain any path-matching or role-checking logic directly.

**Why priority 33?** Drupal's `RouterListener` runs at priority 32 (sets the request attributes from the matched route). We want to intercept after routing is done (so `getPathInfo()` is accurate) but before any controller or form runs. Priority 33 is one step above the router listener — enough to intercept before any business logic runs.

### 3.5 `ParanoiaRebornHooks` (Hook Class)

Tagged as `drupal.hook`, picked up by Drupal 11's OOP hook discovery. All hooks use `#[Hook('hook_name')]` attribute syntax.

Implemented hooks:
- `hook_requirements` — populates six status report items.
- `hook_help` — provides contextual help for the module's help page.
- `hook_modules_installed` — re-applies PHP filter hardening if the `php` module is re-installed while Paranoia Reborn is active.
- `hook_menu_links_discovered_alter` — removes Field UI and Views UI menu links from the admin toolbar for non-trusted users. This is a UI hint only; the actual request blocking happens in the subscriber.

### 3.6 `ParanoiaRebornSettingsForm` (Config Form)

`ConfigFormBase` subclass. Key design decisions:

- **`#states` for custom toggles**: Custom protection toggles are hidden via Drupal's `#states` JS API when the profile is not Custom. This prevents confusion about which settings are active.
- **Profile forces overrides on submit**: When Strict or Balanced is saved, `submitForm` writes `TRUE` for all protection flags regardless of the individual checkbox values. This prevents the stored config from getting out of sync with the profile semantics.
- **PHP filter immediate action**: After saving config, `disablePhpFilterIfRequired()` is called so the hardening takes effect immediately rather than waiting for the next cron or cache rebuild.
- **Role loading**: `\Drupal\user\Entity\Role::loadMultiple()` is called directly in a private helper. This is acceptable in a form class since forms are not unit-tested at the same level as services.

### 3.7 `AuditLogController`

Minimal controller. Uses `PagerSelectExtender` and `TableSortExtender` for database-level pagination and sorting — no in-memory data processing. Watchdog `variables` are unserialized with `allowed_classes => FALSE` to prevent object injection.

---

## 4. Configuration Management

Default config is stored in `config/install/paranoia_reborn.settings.yml` (balanced profile). The config schema in `config/schema/paranoia_reborn.schema.yml` provides type validation for all keys. This means the config can be exported/imported across environments and validated by Drupal's config:import.

---

## 5. Testing Strategy

### Unit Tests (`tests/src/Unit/`)

Both service classes (`PathRestrictor`, `ModuleHardener`) are unit-tested without any Drupal bootstrap. Dependencies are mocked with PHPUnit `MockObject`. Tests verify:

- Path detection correctness (admin, Field UI, Views UI).
- Access decision matrix (UID 1, trusted role, bypass permission, editor, anonymous).
- Exception list evaluation (exact match and wildcard).
- Module hardener state transitions (skip when disabled, uninstall when required, handle exception).

### Functional Tests (`tests/src/Functional/`)

`BrowserTestBase`-based tests that boot a real Drupal kernel and make HTTP requests:

- `ParanoiaRebornSettingsFormTest`: form access control, field rendering, save/validate behaviour for each profile.
- `AccessControlTest`: HTTP-level access checks for editor, admin, and developer users across admin, Field UI, and Views UI paths; audit log write-on-block and skip-when-disabled.

### Playwright E2E (`playwright/paranoia_reborn.spec.js`)

Browser-driven tests against a running Drupal site. Covers the full UI flow from login through form submission, access control (by checking HTTP status codes and response body), audit log page, status report, and toolbar link visibility.

---

## 6. Coding Standards Compliance

| Standard | Implementation |
|---|---|
| `declare(strict_types=1)` at top of every PHP file | Yes |
| Namespace `Drupal\paranoia_reborn\` | Yes |
| OOP hooks in `src/Hook/ParanoiaRebornHooks.php` with `#[Hook]` | Yes |
| Services with constructor DI, typed readonly properties | Yes |
| `ConfigFormBase` settings form | Yes |
| Near-empty `.module` file | Yes |
| Immutable `readonly` value objects | Yes |
| PHPUnit unit tests with MockObject | Yes |
| PHPUnit functional tests with BrowserTestBase | Yes |

---

## 7. Dependency Notes

- **`drupal/core ^11`**: Uses `#[Hook]` attribute (introduced in Drupal 10.2, stable in 11.0), `Drupal\Core\Extension\ModuleInstallerInterface`, `KernelEvents::REQUEST`, `PagerSelectExtender`, `TableSortExtender`.
- **`drupal/dblog`**: Required because the audit log reads from the `watchdog` table. Listed as a hard dependency in `paranoia_reborn.info.yml`.
- **No contrib dependencies**: The module intentionally has zero contrib module dependencies to maximise install compatibility.
