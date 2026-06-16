# Changelog — Zero Standing Privilege

All notable changes to this module are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-06-16

### Added

- Initial release of the Zero Standing Privilege JIT PAM module.
- `ElevationRequest` content entity with full CRUD lifecycle:
  - States: `pending`, `approved`, `denied`, `expired`, `revoked`
  - Fields: requester UID, target role, reason, duration, approver UID, approver comment, granted_at, expires_at, revocation token
- `PrivilegeManager` service: create request, grant, deny, revoke, batch revoke expired.
- `ApprovalService` service: isApprover check, approve, deny, count helpers.
- `ElevationNotifier` service: email notifications for all lifecycle events.
- `ElevationStatus` PHP 8.1 backed enum with `isActive()`, `isPending()`, `isTerminal()` helpers.
- `ZeroStandingPrivilegeHooks`: OOP hooks for `hook_help`, `hook_cron`, `hook_mail`, `hook_user_cancel`.
- `ZspSettingsForm`: full configuration form (approval workflow, duration caps, allowed roles, notifications, tokens, audit retention).
- `ElevationRequestForm`: user-facing request form with duplicate-pending guard and duration validation.
- `ElevationRequestController`: my-requests list, request detail view, revoke POST handler (CSRF + token).
- `ApprovalQueueController`: approval queue, approve/deny POST handlers, active elevations dashboard, audit log with pagination.
- `ZspCommands` (Drush): `zsp:revoke-expired`, `zsp:grant`, `zsp:status`, `zsp:deny`, `zsp:list`.
- Routing, permissions, menu links, config install, config schema.
- PHPUnit unit tests: `PrivilegeManagerTest`, `ApprovalServiceTest`.
- BrowserTestBase functional tests: `ElevationRequestFormTest`, `ApprovalQueueControllerTest`.
- Playwright E2E spec: `zero_standing_privilege.spec.js`.
- Design document: `docs/zero_standing_privilege_design.md`.
- Architecture document: `docs/zero_standing_privilege_architecture.md`.
