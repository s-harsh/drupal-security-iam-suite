# Zero Standing Privilege (ZSP)

The first open-source **Just-In-Time Privileged Access Management (PAM)** module for Drupal.

ZSP eliminates persistent administrator accounts by replacing them with time-bounded role elevations:
users request a higher role, an approver reviews the request, the role is granted for a capped duration,
and it is **automatically revoked** when time runs out.

---

## Features

| Feature | Details |
|---|---|
| **JIT Role Elevation** | Users request a target role + duration + justification |
| **Approval Workflow** | Auto-approve (by requester role) or require named approvers |
| **Time-Bounded Grants** | Configurable max per site (default 4 h); hard-capped |
| **Automatic Revocation** | Cron-driven + immediate via one-click email token |
| **Audit Trail** | ElevationRequest entity: who, what, when, why, outcome |
| **Email Notifications** | On request (to approvers), on grant/deny/expiry (to requester) |
| **Admin UI** | Approval queue, active elevations dashboard, audit log table |
| **Drush Commands** | `zsp:revoke-expired`, `zsp:grant`, `zsp:status`, `zsp:deny`, `zsp:list` |

---

## Requirements

- Drupal 10.4 or 11.x
- PHP 8.2+
- Drush 12+ (for CLI commands)

---

## Installation

```bash
composer require drupal/zero_standing_privilege
drush en zero_standing_privilege
drush cr
```

---

## Quick Start

### 1. Configure

Navigate to **Admin › Configuration › Security › Zero Standing Privilege** or:

```
/admin/config/security/zero-standing-privilege
```

Key settings:
- **Require approval** — toggle manual vs automatic approval
- **Approver roles** — which roles can approve requests
- **Max elevation minutes** — hard cap on grant duration (default: 240)
- **Allowed target roles** — restrict which roles may be requested

### 2. Grant permissions

| Permission | Who should have it |
|---|---|
| `request privilege elevation` | Any user allowed to request elevation |
| `approve privilege elevation` | Designated approvers (security team) |
| `administer zero standing privilege` | Site security administrators |

### 3. Request elevation

Users visit `/zsp/request`, fill in target role, duration, and justification.

### 4. Review requests

Approvers visit `/admin/config/security/zero-standing-privilege/queue` or receive email notification.

### 5. Automatic expiry

Set up cron (recommended: every 5 minutes) or run manually:

```bash
drush cron
# or specifically:
drush zsp:revoke-expired
```

---

## Drush Commands

```bash
# Revoke all expired elevations immediately
drush zsp:revoke-expired

# Directly grant an elevation (bypasses approval workflow)
drush zsp:grant 5 editor 120 --reason="Emergency deployment"

# Show pending/active counts
drush zsp:status

# List requests by status
drush zsp:list --status=pending
drush zsp:list --status=approved --limit=10

# Deny a specific pending request
drush zsp:deny 42 --reason="Outside change window"
```

---

## Architecture

See [`docs/zero_standing_privilege_architecture.md`](../../../../docs/zero_standing_privilege_architecture.md)
and [`docs/zero_standing_privilege_design.md`](../../../../docs/zero_standing_privilege_design.md).

---

## Testing

```bash
# Unit tests
vendor/bin/phpunit modules/custom/zero_standing_privilege/tests/src/Unit/

# Functional tests (requires Drupal test setup)
vendor/bin/phpunit modules/custom/zero_standing_privilege/tests/src/Functional/

# Playwright E2E tests
npx playwright test playwright/zero_standing_privilege.spec.js
```

---

## Security Considerations

- Revocation tokens are single-use and invalidated on use or status change.
- All state transitions are logged at `notice` level to the Drupal watchdog.
- The `administer zero standing privilege` permission is marked `restrict access: true`.
- Elevation requests record the full justification text for compliance audits.
- CSRF tokens protect all POST actions in the admin UI.

---

## License

GPL-2.0-or-later
