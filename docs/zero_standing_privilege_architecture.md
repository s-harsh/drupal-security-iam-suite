# Zero Standing Privilege — Architecture Document

## Module Overview

```
modules/custom/zero_standing_privilege/
├── zero_standing_privilege.info.yml          # Module declaration
├── zero_standing_privilege.module            # Near-empty procedural stub
├── zero_standing_privilege.services.yml      # Service container definitions
├── zero_standing_privilege.routing.yml       # Route definitions
├── zero_standing_privilege.permissions.yml   # Permission definitions
├── zero_standing_privilege.links.menu.yml    # Admin/user menu links
├── zero_standing_privilege.install           # Schema + install/uninstall hooks
├── drush.services.yml                        # Drush command service registration
├── composer.json                             # Composer metadata
├── config/
│   ├── install/zero_standing_privilege.settings.yml   # Default config
│   └── schema/zero_standing_privilege.schema.yml      # Config schema
└── src/
    ├── Hook/ZeroStandingPrivilegeHooks.php   # OOP hook implementations
    ├── Entity/
    │   ├── ElevationRequest.php              # ContentEntityBase
    │   └── ElevationRequestInterface.php     # Entity interface
    ├── Service/
    │   ├── PrivilegeManager.php              # Core lifecycle service
    │   ├── ApprovalService.php               # Approval/denial façade
    │   └── ElevationNotifier.php             # Email notification service
    ├── Form/
    │   ├── ZspSettingsForm.php               # Admin settings form
    │   └── ElevationRequestForm.php          # User request form
    ├── Controller/
    │   ├── ElevationRequestController.php    # User-facing pages + revoke
    │   └── ApprovalQueueController.php       # Admin queue, active, audit
    ├── Drush/Commands/ZspCommands.php        # Drush 12 commands
    └── Value/ElevationStatus.php             # PHP 8.1 backed enum
```

---

## Dependency Graph

```
ZeroStandingPrivilegeHooks
  └── PrivilegeManager
  └── ElevationNotifier (lazy via container in hook_mail)

PrivilegeManager
  ├── EntityTypeManagerInterface
  ├── ConfigFactoryInterface
  ├── LoggerInterface
  ├── AccountInterface (current_user)
  ├── Connection (database)
  └── ElevationNotifier

ApprovalService
  ├── EntityTypeManagerInterface
  ├── ConfigFactoryInterface
  ├── LoggerInterface
  ├── PrivilegeManager
  └── ElevationNotifier

ElevationNotifier
  ├── MailManagerInterface
  ├── ConfigFactoryInterface
  ├── EntityTypeManagerInterface
  ├── LoggerInterface
  └── LanguageManagerInterface

ElevationRequestController
  ├── PrivilegeManager
  └── AccountInterface

ApprovalQueueController
  ├── PrivilegeManager
  └── ApprovalService

ZspCommands (Drush)
  ├── PrivilegeManager
  ├── ApprovalService
  ├── EntityTypeManagerInterface
  ├── ConfigFactoryInterface
  └── LoggerInterface
```

---

## Entity: ElevationRequest

**Type:** ContentEntityBase (`elevation_request`)

**Storage table:** `zero_standing_privilege_request`

**Entity keys:** `id` (serial), `uuid`

### Field Schema

| Field | Type | Description |
|---|---|---|
| `id` | serial (unsigned) | Auto-increment primary key |
| `uuid` | varchar(128) | UUID for external references |
| `requester_uid` | integer (unsigned) | UID of the requesting user |
| `target_role` | varchar(64) | Role machine name being requested |
| `reason` | longtext | Business justification (required) |
| `duration_minutes` | integer (unsigned) | Requested elevation duration |
| `status` | varchar(16) | ElevationStatus enum value |
| `approver_uid` | integer (unsigned) | UID of approver (0 if pending) |
| `approver_comment` | longtext | Approver note / denial reason |
| `created` | integer | Unix timestamp of request creation |
| `granted_at` | integer (unsigned) | Unix timestamp when role was granted |
| `expires_at` | integer (unsigned) | Unix timestamp when grant expires |
| `revocation_token` | varchar(64) | One-time self-revocation token |

### ElevationStatus Enum

```php
enum ElevationStatus: string {
  case Pending  = 'pending';   // Awaiting approver decision
  case Approved = 'approved';  // Role active
  case Denied   = 'denied';    // Declined by approver
  case Expired  = 'expired';   // Passed expires_at
  case Revoked  = 'revoked';   // Manually terminated
}
```

Valid transitions:
- `pending → approved` (via `PrivilegeManager::grantElevation`)
- `pending → denied` (via `PrivilegeManager::denyRequest`)
- `approved → expired` (via `PrivilegeManager::revokeElevation(reason:'expired')`)
- `approved → revoked` (via `PrivilegeManager::revokeElevation(reason:'manual'|'token'|'account_cancel')`)

Terminal states (`denied`, `expired`, `revoked`) have no further transitions.

---

## Service Architecture

### PrivilegeManager

The central domain service. Owns the full elevation lifecycle:

| Method | Description |
|---|---|
| `createRequest(uid, role, reason, minutes)` | Creates and saves a pending ElevationRequest; applies auto-approve if configured; notifies approvers |
| `grantElevation(request, approverId, comment)` | Transitions pending→approved; adds role; generates token; notifies requester |
| `denyRequest(request, approverId, comment)` | Transitions pending→denied; notifies requester |
| `revokeElevation(request, reason)` | Transitions approved→expired or approved→revoked; removes role; notifies on expiry |
| `revokeExpiredElevations()` | Batch-queries and revokes all approved requests with `expires_at <= NOW()` |
| `revokeByToken(token)` | Finds a matching approved request by revocation token and revokes it |
| `getPendingRequests()` | Query: all pending, oldest first |
| `getActiveElevations()` | Query: all approved with future expires_at |
| `getRequestsForUser(uid, limit)` | Query: all requests for a specific user, newest first |
| `getAuditLog(limit, offset)` | Query: all requests, newest first, paginated |
| `loadRequest(id)` | Load single entity or null |

### ApprovalService

A focused façade used by controllers. Adds:
- `isApprover(uid)`: checks config for the approver authorization
- `approve(requestId, approverId, comment)`: validates state then delegates to PrivilegeManager
- `deny(requestId, approverId, comment)`: validates state then delegates
- `countPendingRequests()`: for queue badges
- `countActiveElevations()`: for queue badges

### ElevationNotifier

Pure notification service. Builds mail body/subject strings and dispatches via `MailManager`.
Body construction is invoked from `ZeroStandingPrivilegeHooks::mail()` (hook_mail implementation).
This avoids the circular dependency `hooks → notifier → hooks`.

---

## Routing Design

All routes follow Drupal conventions:

| Route | Path | Handler | Auth |
|---|---|---|---|
| `zero_standing_privilege.settings` | `/admin/config/security/zero-standing-privilege` | ZspSettingsForm | `administer zsp` |
| `zero_standing_privilege.request` | `/zsp/request` | ElevationRequestForm | `request privilege elevation` |
| `zero_standing_privilege.my_requests` | `/zsp/my-requests` | ElevationRequestController::myRequests | `request privilege elevation` |
| `zero_standing_privilege.view` | `/zsp/request/{id}` | ElevationRequestController::view | `request privilege elevation` |
| `zero_standing_privilege.revoke` | `/zsp/request/{id}/revoke` [POST] | ElevationRequestController::revoke | `request privilege elevation` |
| `zero_standing_privilege.approval_queue` | `/admin/.../queue` | ApprovalQueueController::queue | `approve privilege elevation` |
| `zero_standing_privilege.approve` | `/admin/.../queue/{id}/approve` [POST] | ApprovalQueueController::approve | `approve privilege elevation` |
| `zero_standing_privilege.deny` | `/admin/.../queue/{id}/deny` [POST] | ApprovalQueueController::deny | `approve privilege elevation` |
| `zero_standing_privilege.active_elevations` | `/admin/.../active` | ApprovalQueueController::activeElevations | `administer zsp` |
| `zero_standing_privilege.audit_log` | `/admin/.../audit` | ApprovalQueueController::auditLog | `administer zsp` |

---

## Cron Integration

`ZeroStandingPrivilegeHooks::cron()` is tagged with `#[Hook('cron')]` and calls
`PrivilegeManager::revokeExpiredElevations()`. This queries:

```sql
SELECT id FROM zero_standing_privilege_request
WHERE status = 'approved'
  AND expires_at > 0
  AND expires_at <= UNIX_TIMESTAMP()
```

For each result: removes the role from the user, transitions status to `expired`, sends expiry email.

**Recommended cron frequency:** every 5 minutes to minimize the window where an expired elevation
is still technically active. Use `elytra`, `ultimate_cron`, or a system cron job.

---

## Drush Integration

Commands use Drush 12 PHP attribute syntax (`#[CLI\Command]`, `#[CLI\Argument]`, `#[CLI\Option]`),
registered in `drush.services.yml` under the `drush.command` tag.

```bash
drush zsp:revoke-expired   # Batch-revoke expired elevations
drush zsp:grant 5 editor 120 --reason="Emergency patch"
drush zsp:status           # Show pending/active counts in table
drush zsp:deny 42 --reason="Not in change window"
drush zsp:list --status=approved --limit=10
```

---

## Coding Standards

- All PHP files: `<?php\ndeclare(strict_types=1);`
- Namespace: `Drupal\zero_standing_privilege\`
- Constructor promotion + `readonly` typed properties throughout
- No procedural code in `.module` except the file docblock
- Hooks use `#[Hook('hook_name')]` attribute on methods in `ZeroStandingPrivilegeHooks`
- ConfigFormBase for settings; FormBase for user forms
- ContentEntityBase for the ElevationRequest entity (DB-backed)
- Drush commands extend `DrushCommands` with attribute-based metadata

---

## Test Coverage

### Unit Tests (`tests/src/Unit/`)

| Test Class | Coverage |
|---|---|
| `PrivilegeManagerTest` | createRequest (clamp/disallowed), grantElevation, denyRequest, revokeElevation, revokeByToken, revokeExpiredElevations |
| `ApprovalServiceTest` | isApprover (uid/role/missing), approve/deny (state guards, delegation, not-found) |

All unit tests use PHPUnit MockObject; no Drupal bootstrap required.

### Functional Tests (`tests/src/Functional/`)

| Test Class | Coverage |
|---|---|
| `ElevationRequestFormTest` | Anonymous access, permission check, form validation (empty reason, short reason, max duration), successful submission, duplicate guard |
| `ApprovalQueueControllerTest` | Anonymous/unpermissioned access, empty queue, pending request visibility, active elevations table, audit log access |

Functional tests use `BrowserTestBase` with `stark` theme.

---

## Future Work (v2.0 Roadmap)

- **External PAM integration** plugin API (HashiCorp Vault, CyberArk, BeyondTrust) for approval delegation.
- **Time-window restrictions**: only allow elevation during business hours or defined change windows.
- **Notification channels**: Slack / Teams / PagerDuty webhooks alongside email.
- **Risk scoring**: auto-deny requests that match high-risk patterns (weekend, unusual role, unusual IP).
- **4-eyes approval**: require N-of-M approver signatures for high-privilege roles.
- **Elevation history diff**: show what configuration changes were made during an elevation window.
- **REST/JSON:API exposure**: for integration with external SIEM / ITSM tools.
