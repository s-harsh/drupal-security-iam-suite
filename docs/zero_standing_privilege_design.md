# Zero Standing Privilege — Design Document

## Problem Statement

Drupal sites routinely maintain **standing privileged accounts**: users with the `administrator` role
(or equivalent) whose elevated access persists indefinitely, even when not actively performing
administrative tasks. This pattern violates the principle of least privilege and dramatically expands
the blast radius of compromised credentials, session hijacking, or insider threats.

The **Zero Standing Privilege (ZSP)** module eliminates standing privilege by replacing it with
**Just-In-Time (JIT) access**: users are granted elevated roles only when they need them, only for
as long as they need them, and every grant is recorded in an immutable audit trail.

---

## Goals

1. **Eliminate standing admin accounts** on production Drupal sites.
2. **Minimal friction** for legitimate users: the request-to-grant round-trip should take under 2 minutes.
3. **Zero implicit trust**: every elevation requires a justification and (optionally) explicit approval.
4. **Automatic revocation**: elevations expire without any manual action.
5. **Full auditability**: every state transition is persisted and queryable.
6. **Drupal-native UX**: standard Drupal forms, admin menu, permissions, email, and Drush.
7. **Open-source**: GPL-2.0-or-later, installable via Composer, no proprietary dependencies.

---

## Non-Goals

- This module does not replace Drupal's core role system.
- It does not provide 2FA / MFA (complement with other modules such as `tfa`).
- It does not audit *what* an elevated user did — only the elevation itself. Pair with an activity log module for content audit trails.
- It does not support hardware security keys or external PAM systems in v1.0 (planned for v2.0 via plugin API).

---

## User Roles & Actors

| Actor | Permission | Typical Drupal Role |
|---|---|---|
| **Requester** | `request privilege elevation` | Authenticated / editor |
| **Approver** | `approve privilege elevation` | Security team, manager |
| **Administrator** | `administer zero standing privilege` | Super-admin (itself a ZSP-managed role in production) |

---

## Elevation Request Lifecycle

```
[User] → Submit form → [pending]
                           │
               ┌───────────┴───────────┐
               │ require_approval=true │ require_approval=false (or auto_approve_roles match)
               ▼                       ▼
         [Approver reviews]       [approved immediately]
               │                       │
         ┌─────┴─────┐                 │
         │           │                 │
       [deny]    [approve] ────────────┘
         │           │
         ▼           ▼
      [denied]   [Role added to user account]
                     │
                  [Timer runs]
                     │
              ┌──────┴──────┐
              │             │
     [expires_at reached]  [User / Admin clicks Revoke]
              │             │
              ▼             ▼
          [expired]     [revoked]
      [Role removed]  [Role removed]
```

All transitions are logged at `notice` level to Drupal's watchdog.

---

## Approval Workflow

### Auto-Approval

When `require_approval = false` (global setting), or when the requester has a role listed in
`auto_approve_roles`, the elevation is granted immediately upon form submission without any
approver action.

This is appropriate for low-risk elevations (e.g., promoting an editor to `content_reviewer`) or
during planned maintenance windows.

### Manual Approval

When `require_approval = true` and the requester's roles are not in `auto_approve_roles`:

1. Request is saved with status `pending`.
2. Email sent to all users in `approver_roles` and `approver_uids`.
3. Approvers review the queue at `/admin/config/security/zero-standing-privilege/queue`.
4. Approver clicks **Approve** or **Deny** (form POST with CSRF token).
5. On approval: role added to user, email sent to requester, timer starts.
6. On denial: reason recorded, email sent to requester.

### Approver Configuration

Approvers are identified two ways (union, not intersection):
- **Approver roles**: all active users with at least one listed role.
- **Approver UIDs**: explicitly named user IDs (useful for service accounts).

---

## Time-Bounding

- **Default duration**: configurable (default: 60 minutes).
- **Maximum duration**: configurable hard cap (default: 240 minutes / 4 hours). Requests for longer durations are silently clamped.
- **Expiry stored as Unix timestamp** (`expires_at = granted_at + duration_minutes * 60`).
- **Automatic revocation**: `hook_cron` calls `PrivilegeManager::revokeExpiredElevations()`, which queries for `status=approved AND expires_at <= NOW()` and revokes each.
- **Immediate revocation**: available via:
  - Admin UI (Revoke button in active elevations table).
  - Requester self-service (Revoke button on request detail page).
  - Email token link (one-time token in the approval notification).
  - Drush: `drush zsp:revoke-expired`, `drush zsp:grant` (bypass).

---

## Email Notifications

| Event | Recipient | Toggle setting |
|---|---|---|
| New request submitted | Approvers | `notify_approvers_on_request` |
| Elevation approved | Requester | `notify_requester_on_grant` |
| Elevation denied | Requester | `notify_requester_on_deny` |
| Elevation expired | Requester | `notify_requester_on_expiry` |

All emails are sent via Drupal's `plugin.manager.mail` (respects configured mailer module).
Subject lines optionally prepend the site name.

### Revocation Token

When `revocation_token_enabled = true`, the approval notification email includes a signed URL:

```
/zsp/request/{id}/revoke?token={hex_token}
```

The token is a 48-character hex string (`bin2hex(random_bytes(24))`) stored in the
`revocation_token` field. It is cleared on use, on manual revocation, and on expiry.

---

## Audit Trail

Every elevation request is stored as an `ElevationRequest` entity with:
- Full lifecycle history (status transitions update the entity in-place).
- Approver identity and comment.
- Exact timestamps (created, granted_at, expires_at).
- Reason text provided by the requester.

The audit log page (`/admin/config/security/zero-standing-privilege/audit`) displays all records
newest-first with pagination (50 per page). Retention is configurable; 0 = retain forever.

For compliance use cases, the raw DB table (`zero_standing_privilege_request`) can be exported
directly or queried via Entity API.

---

## Security Threat Model

| Threat | Mitigation |
|---|---|
| CSRF on approve/deny/revoke | CSRF tokens on all POST routes |
| Token replay (revocation link) | One-time token, cleared on first use |
| Privilege escalation via race condition | Status guard in `grantElevation()` checks `isPending()` before modifying |
| Overly long elevation | Hard cap enforced in `PrivilegeManager::createRequest()` |
| Approver impersonation | Approval requires `approve privilege elevation` permission + CSRF |
| Stale elevations after account cancel | `hook_user_cancel` revokes all active grants for the cancelled account |
| Standing "approver" accounts | Recommend pairing with ZSP itself: approver role should also be JIT-managed |

---

## Configuration Reference

| Key | Type | Default | Description |
|---|---|---|---|
| `require_approval` | bool | true | Require manual approver action |
| `auto_approve_roles` | string[] | [] | Roles auto-approved on request |
| `approver_roles` | string[] | [administrator] | Roles whose members can approve |
| `approver_uids` | int[] | [] | Named approver UIDs |
| `max_elevation_minutes` | int | 240 | Hard cap on elevation duration |
| `default_elevation_minutes` | int | 60 | Pre-filled form value |
| `allowed_target_roles` | string[] | [] | Roles that may be requested (empty = all) |
| `notify_approvers_on_request` | bool | true | Email approvers on new request |
| `notify_requester_on_grant` | bool | true | Email requester on approval |
| `notify_requester_on_deny` | bool | true | Email requester on denial |
| `notify_requester_on_expiry` | bool | true | Email requester on expiry |
| `revocation_token_enabled` | bool | true | Include revoke link in emails |
| `revocation_token_ttl` | int | 86400 | Token validity in seconds |
| `audit_retention_days` | int | 365 | Days to keep completed records (0 = forever) |
